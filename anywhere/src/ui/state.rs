use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::AtomicU64;

use tokio::sync::RwLock;
use tokio::sync::broadcast;

// ---------------------------------------------------------------------------
// Traffic
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct TrafficMsg {
    pub up: u64,
    pub down: u64,
}

// ---------------------------------------------------------------------------
// Memory
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct MemoryMsg {
    pub inuse: u64,
}

// ---------------------------------------------------------------------------
// Connections
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, serde::Serialize)]
pub struct Connection {
    pub id: String,
    pub metadata: ConnMetadata,
    pub upload: u64,
    pub download: u64,
    pub start: String,
    pub chains: Vec<String>,
    pub rule: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ConnMetadata {
    #[serde(rename = "destinationIP")]
    pub destination_ip: String,
    #[serde(rename = "destinationPort")]
    pub destination_port: String,
    pub host: String,
    pub network: String,
    #[serde(rename = "type")]
    pub type_: String,
    #[serde(rename = "sourceIP")]
    pub source_ip: String,
    #[serde(rename = "sourcePort")]
    pub source_port: String,
    #[serde(rename = "processPath")]
    pub process_path: String,
    #[serde(rename = "dnsMode")]
    pub dns_mode: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ConnectionsMsg {
    #[serde(rename = "downloadTotal")]
    pub download_total: u64,
    #[serde(rename = "uploadTotal")]
    pub upload_total: u64,
    pub memory: u64,
    pub connections: Vec<Connection>,
}

// ---------------------------------------------------------------------------
// Per-connection atomic counters (shared between relay and state)
// ---------------------------------------------------------------------------

pub struct ConnCounters {
    pub upload: AtomicU64,
    pub download: AtomicU64,
}

impl ConnCounters {
    pub fn new_arc() -> Arc<Self> {
        Arc::new(Self {
            upload: AtomicU64::new(0),
            download: AtomicU64::new(0),
        })
    }
}

// ---------------------------------------------------------------------------
// Per-tag atomic counters
// ---------------------------------------------------------------------------

pub struct TagStats {
    pub upload: AtomicU64,
    pub download: AtomicU64,
}

impl TagStats {
    pub fn new() -> Self {
        Self {
            upload: AtomicU64::new(0),
            download: AtomicU64::new(0),
        }
    }
}

// ---------------------------------------------------------------------------
// AppStats — the global state object
// ---------------------------------------------------------------------------

pub struct AppStats {
    /// Total upload bytes (atomic, updated from relay hot path).
    pub upload_total: AtomicU64,
    /// Total download bytes (atomic, updated from relay hot path).
    pub download_total: AtomicU64,

    /// Per-outbound-tag statistics.
    pub per_tag: RwLock<HashMap<String, Arc<TagStats>>>,

    /// Active connections. Locked only on connect/disconnect.
    pub connections: RwLock<HashMap<String, ConnectionState>>,

    /// Broadcast channels for 3s tick pushes.
    pub traffic_tx: broadcast::Sender<TrafficMsg>,
    pub memory_tx: broadcast::Sender<MemoryMsg>,
    pub connections_tx: broadcast::Sender<ConnectionsMsg>,

    /// Platform-specific memory reader, injected by main.rs at startup.
    /// No #[cfg] in this file — all platform logic lives in main.rs.
    pub current_memory: fn() -> u64,
}

/// Internal per-connection state held in AppStats.connections.
pub struct ConnectionState {
    pub counters: Arc<ConnCounters>,
    pub info: Connection,
}

impl AppStats {
    pub fn new(current_memory: fn() -> u64) -> Arc<Self> {
        let (traffic_tx, _) = broadcast::channel(8);
        let (memory_tx, _) = broadcast::channel(8);
        let (connections_tx, _) = broadcast::channel(8);

        Arc::new(Self {
            upload_total: AtomicU64::new(0),
            download_total: AtomicU64::new(0),
            per_tag: RwLock::new(HashMap::new()),
            connections: RwLock::new(HashMap::new()),
            traffic_tx,
            memory_tx,
            connections_tx,
            current_memory,
        })
    }

    /// Register a new connection.
    pub async fn add_connection(
        &self, conn_id: String, counters: Arc<ConnCounters>, info: Connection,
    ) {
        self.connections
            .write()
            .await
            .insert(conn_id, ConnectionState { counters, info });
    }

    /// Remove a connection by ID.
    pub async fn remove_connection(&self, conn_id: &str) {
        self.connections.write().await.remove(conn_id);
    }

    /// Get or create tag stats for an outbound tag.
    pub async fn get_or_create_tag(&self, tag: &str) -> Arc<TagStats> {
        self.per_tag
            .write()
            .await
            .entry(tag.to_string())
            .or_insert_with(|| Arc::new(TagStats::new()))
            .clone()
    }
}

// ---------------------------------------------------------------------------
// Platform-specific memory reading (no #[cfg] on declarations — all cfg
// is inside function bodies. main.rs picks the right fn at startup.)
// ---------------------------------------------------------------------------

/// Reads RSS memory on Linux/Android via /proc/self/status. Returns 0 on other
pub fn read_linux_memory() -> u64 {
    if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
        for line in status.lines() {
            if line.starts_with("VmRSS:") {
                if let Some(kb_str) = line.split_whitespace().nth(1) {
                    if let Ok(kb) = kb_str.parse::<u64>() {
                        return kb * 1024;
                    }
                }
            }
        }
    }
    0
}

/// Reads RSS memory on macOS via mach2 + libc::task_info. Returns 0 on other
/// platforms.
#[allow(unused_unsafe)]
pub fn read_macos_memory() -> u64 {
    #[cfg(target_os = "macos")]
    {
        use mach2::task_info::mach_task_basic_info;
        use mach2::vm_types::natural_t;

        let mut info = std::mem::MaybeUninit::<mach_task_basic_info>::uninit();
        let mut count = (std::mem::size_of::<mach_task_basic_info>() /
            std::mem::size_of::<natural_t>()) as u32;
        let result = unsafe {
            libc::task_info(
                mach2::traps::mach_task_self() as libc::mach_port_t,
                mach2::task_info::MACH_TASK_BASIC_INFO as libc::task_flavor_t,
                info.as_mut_ptr() as *mut libc::integer_t,
                &mut count,
            )
        };
        if result == libc::KERN_SUCCESS {
            let info = unsafe { info.assume_init() };
            return info.resident_size as u64;
        }
    }
    0
}

/// Reads RSS memory on Windows via GetProcessMemoryInfo (WorkingSetSize).
/// Returns 0 on other platforms.
pub fn read_windows_memory() -> u64 {
    #[cfg(target_os = "windows")]
    {
        use windows_sys::Win32::System::ProcessStatus::{
            GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS,
        };
        use windows_sys::Win32::System::Threading::GetCurrentProcess;

        let mut counters: PROCESS_MEMORY_COUNTERS = unsafe { std::mem::zeroed() };
        let ok = unsafe {
            GetProcessMemoryInfo(
                GetCurrentProcess(),
                &mut counters,
                std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32,
            )
        };
        if ok != 0 {
            return counters.WorkingSetSize as u64;
        }
    }
    0
}
