// SPDX-License-Identifier: BSD-2-Clause
// Copyright © The anywhere project contributors.

//! SSH-tunnel outbound via SOCKS5.
//!
//! Spawns a command (e.g. `ssh -D 1080 -N user@host`) that provides a SOCKS5
//! endpoint on a local port. Each [`OutboundClient::dial`] connects to that
//! endpoint and issues a SOCKS5 CONNECT; [`OutboundClient::dial_udp`] uses
//! UDP ASSOCIATE.
//!
//! # Config
//!
//! ```toml
//! [[outbounds]]
//! type = "ssh"
//! tag = "mac"
//! cmd = "ssh -D 1080 -N user@host"
//! server = "127.0.0.1:1080"
//! ```

use std::io;
use std::net::SocketAddr;
#[cfg(unix)]
use std::os::unix::process::CommandExt;
use std::process::Stdio;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicI32;
use std::sync::atomic::AtomicI64;
use std::sync::atomic::AtomicU16;
use std::sync::atomic::AtomicU32;
use std::sync::atomic::Ordering;
use std::time::Duration;
use std::time::SystemTime;

use async_trait::async_trait;
use tokio::io::AsyncBufReadExt;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::net::UdpSocket;
use tokio::process::Child;
use tokio::sync::Mutex;
use tokio::sync::RwLock;
use tokio::time::Instant;
use tokio::time::sleep;

use crate::inbound::Address;
use crate::inbound::Destination;
use crate::outbound::OutboundClient;
use crate::relay::PacketRelay;
use crate::relay::StreamRelay;
use crate::relay::TcpRelay;

const SSH_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const SSH_UDP_IDLE_TIMEOUT: Duration = Duration::from_secs(60);
const MAX_FAILURES_BEFORE_RESPAWN: u32 = 1;
const PROXY_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// Skip the TCP health probe if the tunnel was verified healthy within this
/// window. Avoids redundant connect(2) on every dial in high-traffic scenarios.
const HEALTH_CHECK_CACHE_TTL_MS: i64 = 2_000;
/// Maximum single-interval delay when polling for tunnel readiness.
const SSH_POLL_MAX_DELAY_MS: u64 = 1_600;

// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// Proxy protocol
// ---------------------------------------------------------------------------

/// Supported proxy protocols for talking to the tunnel endpoint.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ProxyType {
    Socks5,
    Http,
}

impl ProxyType {
    fn from_config(s: Option<&str>) -> Self {
        match s {
            Some("socks5") => ProxyType::Socks5,
            _ => ProxyType::Http,
        }
    }
}
// ---------------------------------------------------------------------------
pub struct SshOutboundClient {
    /// Pre-parsed command binary name (parts[0]).
    cmd_binary: String,
    /// Pre-parsed command arguments (parts[1..]).
    cmd_args: Vec<String>,
    /// Whether the original cmd contains `{PORT}`.
    has_port_placeholder: bool,
    /// Outbound tag from config — used for concise log identification.
    log_tag: String,
    local_ip: std::net::IpAddr,
    allocated_port: AtomicU16,
    process: Arc<RwLock<Option<Child>>>,
    child_pid: AtomicI32,
    proxy_type: ProxyType,
    /// Consecutive CONNECT failures. Reset on success; when reaching the
    /// threshold the tunnel is respawned even if the port is still open.
    failure_count: AtomicU32,
    /// Unix-epoch milliseconds of the last successful health probe. Zero means
    /// "never probed". Checked by [`ensure_running`] to skip redundant probes.
    last_healthy_ms: AtomicI64,
    /// Optimistic flag; set when the health cache has ever been populated.
    /// Prevents a spurious probe on the very first call while the tunnel is
    /// still starting up.
    health_cache_seeded: AtomicBool,
}

impl SshOutboundClient {
    fn current_addr(&self) -> SocketAddr {
        SocketAddr::new(
            self.local_ip,
            self.allocated_port.load(Ordering::Relaxed),
        )
    }

    pub async fn from_config(
        cfg: &crate::config::OutboundConfig,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let cmd = cfg.cmd.as_deref().ok_or("ssh outbound: missing 'cmd'")?;
        let server = cfg
            .server
            .as_deref()
            .ok_or("ssh outbound: missing 'server'")?;

        let pt = ProxyType::from_config(cfg.proxy_type.as_deref());

        // server may contain {PORT}; resolve the IP part (throwaway port).
        // We'll replace {PORT} with a free port at spawn time.
        let bootstrap_addr =
            crate::outbound::common::resolve_addr(&server.replace("{PORT}", "1"))
                .map_err(|e| {
                    format!("ssh outbound: bad server '{server}': {e}")
                })?;

        // Pre-parse the command once so spawn_tunnel() avoids repeated
        // split_whitespace + allocation on every call.
        let cmd_parts: Vec<String> =
            cmd.split_whitespace().map(|s| s.to_string()).collect();
        let has_port_placeholder = cmd.contains("{PORT}");
        let (cmd_binary, cmd_args) = if cmd_parts.is_empty() {
            return Err("ssh outbound: empty cmd field".into());
        } else {
            (cmd_parts[0].clone(), cmd_parts[1..].to_vec())
        };

        let log_tag = cfg.tag.as_deref().unwrap_or("ssh").to_string();

        let client = Self {
            cmd_binary,
            cmd_args,
            has_port_placeholder,
            log_tag,
            local_ip: bootstrap_addr.ip(),
            allocated_port: AtomicU16::new(bootstrap_addr.port()),
            process: Arc::new(RwLock::new(None)),
            child_pid: AtomicI32::new(0),
            proxy_type: pt,
            failure_count: AtomicU32::new(0),
            last_healthy_ms: AtomicI64::new(0),
            health_cache_seeded: AtomicBool::new(false),
        };

        // Spawn the tunnel. Fail registration if the binary cannot be
        // spawned (command not found, fork error, etc.).
        client
            .spawn_tunnel()
            .await
            .map_err(|e| format!("ssh outbound '{}': {e}", client.log_tag))?;

        // Wait a bit for the port to become ready. If it times out, log a
        // warning at error level because the outbound won't work until the
        // port becomes reachable.
        if let Err(e) = client.poll_port(Duration::from_secs(5)).await {
            log::error!(
                "ssh outbound '{}' tunnel not yet ready: {e}",
                client.log_tag,
            );
        }

        Ok(client)
    }

    /// Spawn the tunnel command and store the child handle.
    ///
    /// If the config cmd contains `{PORT}`, it is replaced with a free
    /// ephemeral port so the tunnel never collides with TIME_WAIT from a
    /// previous instance.
    /// Spawn the tunnel command and store the child handle.
    ///
    /// If the config cmd contains `{PORT}`, it is replaced with a free
    /// ephemeral port so the tunnel never collides with TIME_WAIT from a
    /// previous instance.  Retries up to 3 times with a fresh port when the
    /// child exits immediately — this mitigates the race between dropping the
    /// temp listener and the SSH process binding the port (another process
    /// could steal it in the window).
    async fn spawn_tunnel(&self) -> io::Result<()> {
        let mut guard = self.process.write().await;

        // If we already have a running process, nothing to do.
        if let Some(child) = &mut *guard {
            match child.try_wait() {
                Ok(None) => return Ok(()),
                _ => {
                    let _ = child.kill().await;
                    let _ = child.wait().await;
                    *guard = None;
                },
            }
        }

        let max_attempts = if self.has_port_placeholder { 3 } else { 1 };

        for attempt in 0..max_attempts {
            // Allocate a free port for {PORT} substitution.
            let port = if self.has_port_placeholder {
                let listener = std::net::TcpListener::bind("127.0.0.1:0")
                    .map_err(|e| {
                        io::Error::new(
                            io::ErrorKind::Other,
                            format!("bind temp port: {e}"),
                        )
                    })?;
                let p = listener
                    .local_addr()
                    .map_err(|e| {
                        io::Error::new(
                            io::ErrorKind::Other,
                            format!("get temp port: {e}"),
                        )
                    })?
                    .port();
                drop(listener);
                self.allocated_port.store(p, Ordering::Relaxed);
                p
            } else {
                self.allocated_port.load(Ordering::Relaxed)
            };

            // Build command from pre-parsed parts.
            let mut std_cmd = std::process::Command::new(&self.cmd_binary);
            if self.has_port_placeholder {
                let port_str = port.to_string();
                let args: Vec<String> = self
                    .cmd_args
                    .iter()
                    .map(|a| a.replace("{PORT}", &port_str))
                    .collect();
                std_cmd.args(&args);
            } else {
                std_cmd.args(&self.cmd_args);
            }
            std_cmd
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::piped());
            #[cfg(unix)]
            {
                std_cmd.process_group(0);
            }
            let mut child = tokio::process::Command::from(std_cmd)
                .kill_on_drop(true)
                .spawn()
                .map_err(|e| {
                    let cmd_tag = self.display_command(port);
                    io::Error::new(
                        io::ErrorKind::Other,
                        format!("failed to spawn '{}': {e}", cmd_tag),
                    )
                })?;

            // If the child exited immediately (port conflict), retry.
            if attempt + 1 < max_attempts {
                if let Ok(Some(status)) = child.try_wait() {
                    log::warn!(
                        "ssh outbound '{}': tunnel exited early (status={}), \
                         retrying with fresh port",
                        self.log_tag,
                        status,
                    );
                    continue;
                }
            }

            // Log stderr so the user can see SSH connection errors.
            // Use the outbound tag as a concise identifier instead of the full
            // command string (avoids cloning a potentially large/sensitive cmd).
            if let Some(stderr) = child.stderr.take() {
                let tag = self.log_tag.clone();
                tokio::spawn(async move {
                    let reader = tokio::io::BufReader::new(stderr);
                    let mut lines = reader.lines();
                    while let Ok(Some(line)) = lines.next_line().await {
                        log::error!("ssh/{tag} [stderr]: {line}");
                    }
                });
            }

            let pid = child.id().unwrap_or(0) as i32;
            *guard = Some(child);
            self.child_pid.store(pid, Ordering::Relaxed);
            return Ok(());
        }

        unreachable!()
    }

    /// Poll tunnel endpoint until reachable, using exponential backoff.
    /// Returns `Ok(())` once the port accepts a TCP connection; returns
    /// `Err(TimedOut)` if `max_total` elapses without success.
    async fn poll_port(&self, max_total: Duration) -> io::Result<()> {
        let start = Instant::now();
        let mut delay_ms = 100u64;
        loop {
            if crate::outbound::common::connect_tcp_bypass(self.current_addr())
                .await
                .is_ok()
            {
                return Ok(());
            }
            let elapsed = start.elapsed();
            if elapsed >= max_total {
                break;
            }
            // Don't overshoot max_total.
            let actual = delay_ms
                .min((max_total.saturating_sub(elapsed)).as_millis() as u64);
            sleep(Duration::from_millis(actual)).await;
            delay_ms = (delay_ms * 2).min(SSH_POLL_MAX_DELAY_MS);
        }
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            format!(
                "tunnel at {} not reachable after {} ms",
                self.current_addr(),
                start.elapsed().as_millis(),
            ),
        ))
    }

    /// Ensure the tunnel process is running and the local endpoint is
    /// reachable. Spawns / respawns as needed.
    async fn ensure_running(&self) -> io::Result<()> {
        // Cache hit: tunnel was healthy within TTL, skip the TCP probe.
        if self.health_cache_seeded.load(Ordering::Relaxed) {
            let now = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as i64;
            let last = self.last_healthy_ms.load(Ordering::Relaxed);
            if now - last < HEALTH_CHECK_CACHE_TTL_MS {
                return Ok(());
            }
        }

        // Quick check (~500 ms) — most of the time the tunnel is already up.
        if tokio::time::timeout(
            Duration::from_millis(500),
            TcpStream::connect(self.current_addr()),
        )
        .await
        .ok()
        .and_then(|r| r.ok())
        .is_some()
        {
            self.seed_health_cache();
            return Ok(());
        }

        // Process might have died — respawn.
        self.spawn_tunnel().await?;

        // After a respawn, do the full poll cycle (up to 5 s) so the tunnel
        // has time to reconnect across a potentially slow link.
        let r = self.poll_port(Duration::from_secs(5)).await;
        if r.is_ok() {
            self.seed_health_cache();
        }
        r
    }

    // -----------------------------------------------------------------------
    // Proxy protocol dispatch
    // -----------------------------------------------------------------------

    /// Connect to `dest` through the tunnel endpoint using the configured
    /// proxy protocol. On success the caller can read/write the proxied TCP
    /// stream directly.
    async fn proxy_connect(
        proxy_type: ProxyType, stream: &mut TcpStream, dest: &Destination,
    ) -> io::Result<()> {
        match proxy_type {
            ProxyType::Socks5 => {
                Self::socks5_handshake(stream).await?;
                Self::socks5_connect(stream, dest).await
            },
            ProxyType::Http => Self::http_connect(stream, dest).await,
        }
    }

    /// SOCKS5 handshake (no-auth).
    async fn socks5_handshake(stream: &mut TcpStream) -> io::Result<()> {
        stream.write_all(&[0x05, 0x01, 0x00]).await?;
        let mut buf = [0u8; 2];
        stream.read_exact(&mut buf).await?;
        if buf != [0x05, 0x00] {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("SOCKS5 handshake rejected: {buf:02x?}"),
            ));
        }
        Ok(())
    }

    /// SOCKS5 CONNECT. Caller must have handshaken.
    async fn socks5_connect(
        stream: &mut TcpStream, dest: &Destination,
    ) -> io::Result<()> {
        let mut req = Vec::with_capacity(10);
        req.extend_from_slice(&[0x05, 0x01, 0x00]);
        match &dest.address {
            Address::Ipv4(o) => {
                req.push(0x01);
                req.extend_from_slice(o);
            },
            Address::Ipv6(o) => {
                req.push(0x04);
                req.extend_from_slice(o);
            },
            Address::Domain(d) => {
                req.push(0x03);
                req.push(d.len() as u8);
                req.extend_from_slice(d.as_bytes());
            },
        }
        req.extend_from_slice(&dest.port.to_be_bytes());
        stream.write_all(&req).await?;

        let mut header = [0u8; 4]; // VER + REP + RSV + ATYP
        stream.read_exact(&mut header).await?;
        if header[1] != 0x00 {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("SOCKS5 CONNECT failed: rep={}", header[1]),
            ));
        }
        // Read (and discard) the server-bound address.
        socks5_read_addr(stream).await?;
        Ok(())
    }

    /// HTTP CONNECT proxy handshake.
    async fn http_connect(
        stream: &mut TcpStream, dest: &Destination,
    ) -> io::Result<()> {
        let host_port = match &dest.address {
            Address::Ipv4(o) => {
                let ip = std::net::Ipv4Addr::from(*o);
                format!("{ip}:{}", dest.port)
            },
            Address::Ipv6(o) => {
                let ip = std::net::Ipv6Addr::from(*o);
                format!("[{ip}]:{}", dest.port)
            },
            Address::Domain(d) => format!("{d}:{}", dest.port),
        };
        let req =
            format!("CONNECT {host_port} HTTP/1.1\r\nHost: {host_port}\r\n\r\n");
        stream.write_all(req.as_bytes()).await?;

        // Read response headers until \r\n\r\n (O(n) scan tracking
        // checked_up_to so we don't re-scan bytes already examined).
        let mut buf = [0u8; 4096];
        let mut pos = 0;
        let mut checked_up_to: usize = 0;
        loop {
            if pos >= buf.len() {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    "HTTP CONNECT response too large",
                ));
            }
            let n = stream.read(&mut buf[pos..]).await?;
            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionReset,
                    "HTTP CONNECT: connection closed",
                ));
            }
            pos += n;
            // Only scan the newly-received region (with 3-byte overlap for the
            // \r\n\r\n boundary).
            let scan_start = checked_up_to.saturating_sub(3);
            let mut found = false;
            for i in scan_start..pos.saturating_sub(3) {
                if buf[i..i + 4] == [b'\r', b'\n', b'\r', b'\n'] {
                    found = true;
                    break;
                }
            }
            if found {
                break;
            }
            checked_up_to = pos;
        }

        let status_line = std::str::from_utf8(&buf[..pos])
            .ok()
            .and_then(|s| s.lines().next())
            .unwrap_or("");
        if !status_line.contains("200") {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("HTTP CONNECT failed: {status_line}"),
            ));
        }
        Ok(())
    }

    /// Reconstruct the command string for log / error display, substituting
    /// `{PORT}` if needed.
    fn display_command(&self, port: u16) -> String {
        if self.has_port_placeholder {
            self.log_tag.replace("{PORT}", &port.to_string())
        } else {
            self.log_tag.clone()
        }
    }

    /// Mark the tunnel as healthy in the cache so subsequent
    /// [`ensure_running`] calls skip the TCP probe.
    fn seed_health_cache(&self) {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;
        self.last_healthy_ms.store(now, Ordering::Relaxed);
        self.health_cache_seeded.store(true, Ordering::Relaxed);
    }
}

// ---------------------------------------------------------------------------
// SOCKS5 address helpers (shared by CONNECT, UDP ASSOCIATE, and UDP relay)
// ---------------------------------------------------------------------------

/// Append a SOCKS5 ATYP + address to `buf` (without port).
fn socks5_encode_addr(buf: &mut Vec<u8>, dest: &Destination) {
    match &dest.address {
        Address::Ipv4(o) => {
            buf.push(0x01);
            buf.extend_from_slice(o);
        },
        Address::Ipv6(o) => {
            buf.push(0x04);
            buf.extend_from_slice(o);
        },
        Address::Domain(d) => {
            buf.push(0x03);
            buf.push(d.len() as u8);
            buf.extend_from_slice(d.as_bytes());
        },
    }
}

/// Read a SOCKS5 ATYP + address + port from `stream` and return a `SocketAddr`.
async fn socks5_read_addr(stream: &mut TcpStream) -> io::Result<SocketAddr> {
    let mut atyp = [0u8; 1];
    stream.read_exact(&mut atyp).await?;
    match atyp[0] {
        0x01 => {
            let mut octets = [0u8; 4];
            stream.read_exact(&mut octets).await?;
            let mut port = [0u8; 2];
            stream.read_exact(&mut port).await?;
            Ok(SocketAddr::new(
                std::net::IpAddr::V4(std::net::Ipv4Addr::from(octets)),
                u16::from_be_bytes(port),
            ))
        },
        0x04 => {
            let mut octets = [0u8; 16];
            stream.read_exact(&mut octets).await?;
            let mut port = [0u8; 2];
            stream.read_exact(&mut port).await?;
            Ok(SocketAddr::new(
                std::net::IpAddr::V6(std::net::Ipv6Addr::from(octets)),
                u16::from_be_bytes(port),
            ))
        },
        0x03 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            let mut name = vec![0u8; len[0] as usize];
            stream.read_exact(&mut name).await?;
            let mut port_bytes = [0u8; 2];
            stream.read_exact(&mut port_bytes).await?;
            let domain = String::from_utf8_lossy(&name);
            let port = u16::from_be_bytes(port_bytes);
            let relay_addr_str = format!("{domain}:{port}");
            crate::outbound::common::resolve_addr(&relay_addr_str).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::Other,
                    format!(
                        "SOCKS5: cannot resolve relay '{relay_addr_str}': {e}"
                    ),
                )
            })
        },
        _ => Err(io::Error::new(
            io::ErrorKind::Other,
            format!("SOCKS5 unknown ATYP: {}", atyp[0]),
        )),
    }
}

// ---------------------------------------------------------------------------
// OutboundClient impl
// ---------------------------------------------------------------------------

#[async_trait]
impl OutboundClient for SshOutboundClient {
    async fn dial(
        &self, dest: &Destination,
    ) -> Result<Box<dyn StreamRelay>, Box<dyn std::error::Error>> {
        self.ensure_running().await.map_err(|e| {
            format!("ssh outbound '{}' not ready: {e}", self.log_tag)
        })?;

        let failure_count = match self.try_dial(dest).await {
            Ok(relay) => {
                self.failure_count.store(0, Ordering::Relaxed);
                return Ok(relay);
            },
            Err(_) => self.failure_count.fetch_add(1, Ordering::Relaxed) + 1,
        };

        log::warn!(
            "ssh outbound: CONNECT failed \
             (count={failure_count}/{MAX_FAILURES_BEFORE_RESPAWN})",
        );

        if failure_count >= MAX_FAILURES_BEFORE_RESPAWN {
            self.failure_count.store(0, Ordering::Relaxed);
            self.kill_process().await;
            self.spawn_tunnel().await?;
            self.poll_port(Duration::from_secs(5)).await.map_err(|e| {
                format!("ssh outbound '{}' respawn failed: {e}", self.log_tag)
            })?;
            return self.try_dial(dest).await;
        }

        sleep(Duration::from_millis(500)).await;
        self.try_dial(dest).await
    }

    async fn dial_udp(
        &self, _initial_dest: &Destination,
    ) -> Result<Box<dyn PacketRelay>, Box<dyn std::error::Error>> {
        self.ensure_running().await.map_err(|e| {
            format!("ssh outbound '{}' not ready: {e}", self.log_tag)
        })?;

        let failure_count = match self.try_dial_udp().await {
            Ok(relay) => {
                self.failure_count.store(0, Ordering::Relaxed);
                return Ok(relay);
            },
            Err(_) => self.failure_count.fetch_add(1, Ordering::Relaxed) + 1,
        };

        log::warn!(
            "ssh outbound: UDP ASSOCIATE failed \
             (count={failure_count}/{MAX_FAILURES_BEFORE_RESPAWN})",
        );

        if failure_count >= MAX_FAILURES_BEFORE_RESPAWN {
            self.failure_count.store(0, Ordering::Relaxed);
            self.kill_process().await;
            self.spawn_tunnel().await?;
            self.poll_port(Duration::from_secs(5)).await.map_err(|e| {
                format!("ssh outbound '{}' respawn failed: {e}", self.log_tag)
            })?;
            return self.try_dial_udp().await;
        }

        sleep(Duration::from_millis(500)).await;
        self.try_dial_udp().await
    }

    async fn test_latency(&self, _url: &str) -> Option<u64> {
        None
    }
}

impl SshOutboundClient {
    /// Kill the process group (`sh` + children like `ssh`) by PID stored in
    /// [`Self::child_pid`]. Used from both the async retry path and the
    /// sync Drop impl without needing the Mutex.
    fn kill_process_group(pid: i32) {
        if pid <= 0 {
            return;
        }
        #[cfg(unix)]
        unsafe {
            libc::kill(-pid, libc::SIGTERM);
        }
    }

    /// Force-kill the current tunnel process group (`sh` + `ssh`) and wait
    /// for reaping. Used inside the SOCKS5-failure retry path.
    ///
    /// Sends SIGTERM first, then waits up to 500ms for the process to exit
    /// gracefully (allowing SSH to close connections and clean up temp
    /// files), then sends SIGKILL as the final blow.
    async fn kill_process(&self) {
        let pid = self.child_pid.load(Ordering::Relaxed);
        if pid <= 0 {
            return;
        }

        // Step 1: SIGTERM — ask nicely.
        Self::kill_process_group(pid);

        // Step 2: Wait up to 500ms for graceful exit.
        let mut guard = self.process.write().await;
        if let Some(child) = &mut *guard {
            let deadline =
                tokio::time::Instant::now() + Duration::from_millis(500);
            loop {
                match child.try_wait() {
                    Ok(Some(_)) => break, // Exited.
                    Ok(None) => {
                        if tokio::time::Instant::now() >= deadline {
                            break; // Timeout — proceed to SIGKILL.
                        }
                        tokio::time::sleep(Duration::from_millis(50)).await;
                    },
                    Err(_) => break,
                }
            }
        }
        drop(guard);

        // Step 3: SIGKILL if still alive.
        let mut guard = self.process.write().await;
        if let Some(mut child) = guard.take() {
            let _ = child.kill().await;
            let _ = child.wait().await;
        }
        self.child_pid.store(0, Ordering::Relaxed);
    }

    /// Connect to the tunnel endpoint and establish proxied TCP connection.
    async fn try_dial(
        &self, dest: &Destination,
    ) -> Result<Box<dyn StreamRelay>, Box<dyn std::error::Error>> {
        let mut stream = tokio::time::timeout(
            SSH_CONNECT_TIMEOUT,
            crate::outbound::common::connect_tcp_bypass(self.current_addr()),
        )
        .await
        .map_err(|_| "ssh outbound: connect timeout to tunnel endpoint")?
        .map_err(|e| format!("ssh outbound: connect to tunnel endpoint: {e}"))?;

        tokio::time::timeout(
            PROXY_CONNECT_TIMEOUT,
            Self::proxy_connect(self.proxy_type, &mut stream, dest),
        )
        .await
        .map_err(|_| "ssh outbound: proxy connect timeout")?
        .map_err(|e| format!("ssh outbound: proxy connect failed: {e}"))?;

        Ok(Box::new(TcpRelay::new(stream)))
    }

    /// Connect to the tunnel endpoint and establish UDP relay (SOCKS5 only).
    async fn try_dial_udp(
        &self,
    ) -> Result<Box<dyn PacketRelay>, Box<dyn std::error::Error>> {
        if self.proxy_type == ProxyType::Http {
            return Err(crate::outbound::common::ERR_UDP_NOT_SUPPORTED.into());
        }

        let mut assoc_tcp = tokio::time::timeout(
            SSH_CONNECT_TIMEOUT,
            crate::outbound::common::connect_tcp_bypass(self.current_addr()),
        )
        .await
        .map_err(|_| "ssh outbound: connect timeout for UDP ASSOCIATE")?
        .map_err(|e| format!("ssh outbound: connect for UDP ASSOCIATE: {e}"))?;

        Self::socks5_handshake(&mut assoc_tcp).await?;
        let relay_addr = Self::socks5_udp_associate(&mut assoc_tcp).await?;

        let local = UdpSocket::bind("0.0.0.0:0").await?;
        log::info!(
            "ssh outbound UDP ASSOCIATE relay={relay_addr}, local={}",
            local.local_addr()?,
        );

        Ok(Box::new(SshUdpRelay {
            assoc_tcp: Arc::new(Mutex::new(assoc_tcp)),
            relay_addr,
            local,
            last_activity: Instant::now(),
            idle_timeout: SSH_UDP_IDLE_TIMEOUT,
        }))
    }
}

// Add socks5_udp_associate back — it was removed during the proxy_type
// refactor.
impl SshOutboundClient {
    /// SOCKS5 UDP ASSOCIATE. Returns the UDP relay address the server assigned.
    async fn socks5_udp_associate(
        stream: &mut TcpStream,
    ) -> io::Result<SocketAddr> {
        stream
            .write_all(&[
                0x05, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            ])
            .await?;

        let mut header = [0u8; 4]; // VER + REP + RSV + ATYP
        stream.read_exact(&mut header).await?;
        if header[1] != 0x00 {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("SOCKS5 UDP ASSOCIATE failed: rep={}", header[1]),
            ));
        }
        socks5_read_addr(stream).await
    }
}
impl Drop for SshOutboundClient {
    fn drop(&mut self) {
        let pid = self.child_pid.load(Ordering::Relaxed);
        Self::kill_process_group(pid);
        // sends SIGKILL as the final blow. No blocking sleep here —
        // std::thread::sleep in Drop would stall the tokio worker thread.
    }
}

// ---------------------------------------------------------------------------
// SshUdpRelay
// ---------------------------------------------------------------------------

/// UDP relay backed by a SOCKS5 UDP ASSOCIATE association.
struct SshUdpRelay {
    assoc_tcp: Arc<Mutex<TcpStream>>,
    /// Server-assigned UDP relay endpoint.
    relay_addr: SocketAddr,
    local: UdpSocket,
    last_activity: Instant,
    idle_timeout: Duration,
}

impl SshUdpRelay {
    fn next_deadline(&self) -> Instant {
        self.last_activity + self.idle_timeout
    }

    /// Check whether the UDP ASSOCIATE TCP connection is still alive.
    /// A closed association means the server can no longer route UDP
    /// datagrams to us.
    async fn assoc_alive(&self) -> bool {
        let stream = self.assoc_tcp.lock().await;
        // try_read with an empty buffer — just check if the socket is
        // readable or errored. An error means the connection is gone.
        match stream.try_read(&mut [0u8; 0]) {
            Ok(_) => true,
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => true,
            Err(_) => false,
        }
    }
}

/// Parse a SOCKS5 UDP datagram header from `buf[..n]`.
///
/// Returns `(payload_offset, payload_len, Destination)` where
/// `payload_offset` is the index in `buf` where the actual UDP payload
/// begins, and `payload_len` is its length.
fn parse_socks5_udp_header(
    buf: &[u8], n: usize,
) -> Result<(usize, usize, Destination), io::Error> {
    if n < 4 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "UDP packet too short for SOCKS5 header",
        ));
    }

    let frag = buf[2];
    if frag != 0x00 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "UDP fragmentation not supported",
        ));
    }

    let atyp = buf[3];
    let (offset, dest_addr): (usize, Address) = match atyp {
        0x01 if n >= 10 => {
            let octets: [u8; 4] = buf[4..8].try_into().unwrap();
            let addr = std::net::Ipv4Addr::from(octets);
            (8, Address::Ipv4(addr.octets()))
        },
        0x04 if n >= 22 => {
            let octets: [u8; 16] = buf[4..20].try_into().unwrap();
            let addr = std::net::Ipv6Addr::from(octets);
            (20, Address::Ipv6(addr.octets()))
        },
        0x03 if n >= 5 + buf[4] as usize + 2 => {
            let dlen = buf[4] as usize;
            let domain = String::from_utf8_lossy(&buf[5..5 + dlen]).to_string();
            (5 + dlen, Address::Domain(domain))
        },
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unknown SOCKS5 address type",
            ));
        },
    };

    let port = u16::from_be_bytes([buf[offset], buf[offset + 1]]);
    let payload_start = offset + 2;
    let payload_len = n - payload_start;

    Ok((
        payload_start,
        payload_len,
        Destination {
            address: dest_addr,
            port,
            resolved_ip: None,
        },
    ))
}

#[async_trait]
impl PacketRelay for SshUdpRelay {
    async fn read_packet(
        &mut self, buf: &mut [u8],
    ) -> io::Result<(usize, Destination)> {
        loop {
            let deadline = self.next_deadline();
            let remain = deadline
                .checked_duration_since(Instant::now())
                .unwrap_or(Duration::ZERO);

            // Periodically check whether the ASSOCIATE TCP is still alive.
            // If the remote peer or an intermediate NAT closed the
            // association, the UDP relay will never receive packets and
            // would otherwise hang until the idle timeout.
            let check_interval = Duration::from_secs(15);
            let poll_timeout = remain.min(check_interval);

            let result =
                tokio::time::timeout(poll_timeout, self.local.recv_from(buf))
                    .await;

            match result {
                Ok(Ok((n, _src))) => {
                    self.last_activity = Instant::now();
                    match parse_socks5_udp_header(buf, n) {
                        Ok((payload_start, payload_len, dest)) => {
                            // Shift payload to start of buf.
                            buf.copy_within(payload_start..n, 0);
                            return Ok((payload_len, dest));
                        },
                        Err(_) => continue, // Bad packet — skip.
                    }
                },
                Ok(Err(e)) => return Err(e),
                Err(_) => {
                    // Timeout — check assoc_tcp health before looping.
                    if remain <= check_interval {
                        // Real idle timeout.
                        return Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "UDP ASSOCIATE idle timeout",
                        ));
                    }
                    if !self.assoc_alive().await {
                        return Err(io::Error::new(
                            io::ErrorKind::ConnectionReset,
                            "UDP ASSOCIATE TCP connection lost",
                        ));
                    }
                    continue;
                },
            }
        }
    }

    async fn write_packet(
        &mut self, buf: &[u8], dest: &Destination,
    ) -> io::Result<()> {
        self.last_activity = Instant::now();

        // Build SOCKS5 UDP request header.
        let mut pkt = Vec::with_capacity(64);
        pkt.extend_from_slice(&[0x00, 0x00, 0x00]); // RSV + FRAG
        socks5_encode_addr(&mut pkt, dest);
        pkt.extend_from_slice(&dest.port.to_be_bytes());
        pkt.extend_from_slice(buf);

        self.local.send_to(&pkt, self.relay_addr).await?;
        Ok(())
    }

    async fn close(&mut self) -> io::Result<()> {
        // Drop the UDP socket; the association TCP will be dropped when
        // SshUdpRelay itself is dropped.
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::OutboundConfig;

    #[tokio::test]
    async fn test_from_config_missing_cmd() {
        let cfg = OutboundConfig {
            type_: "ssh".into(),
            tag: Some("test".into()),
            server: Some("127.0.0.1:1080".into()),
            cmd: None,
            proxy_type: None,
            password: None,
            method: None,
            plugin: None,
            plugin_opts: None,
            sni: None,
            fp: false,
            ech_config: None,
            outbounds: None,
            interval: None,
            url: None,
            insecure: false,
            idle_session_check_interval: None,
            idle_session_timeout: None,
            min_idle_session: None,
            xmux: None,
            transport: None,
            flow: None,
            reality: None,
            ech: false,
            tls_fragment: false,
            tls_fragment_config: None,
            uot: false,
            mode: None,
        };
        assert!(SshOutboundClient::from_config(&cfg).await.is_err());
    }

    #[tokio::test]
    async fn test_from_config_missing_server() {
        let cfg = OutboundConfig {
            type_: "ssh".into(),
            tag: Some("test".into()),
            server: None,
            cmd: Some("ssh -D 1080 -N host".into()),
            proxy_type: None,
            password: None,
            method: None,
            plugin: None,
            plugin_opts: None,
            sni: None,
            fp: false,
            ech_config: None,
            outbounds: None,
            interval: None,
            url: None,
            insecure: false,
            idle_session_check_interval: None,
            idle_session_timeout: None,
            min_idle_session: None,
            xmux: None,
            transport: None,
            flow: None,
            reality: None,
            ech: false,
            tls_fragment: false,
            tls_fragment_config: None,
            uot: false,
            mode: None,
        };
        assert!(SshOutboundClient::from_config(&cfg).await.is_err());
    }

    #[tokio::test]
    async fn test_from_config_ok() {
        let cfg = OutboundConfig {
            type_: "ssh".into(),
            tag: Some("test".into()),
            server: Some("127.0.0.1:1080".into()),
            cmd: Some("true".into()), // exits immediately, port won't come up
            proxy_type: None,
            password: None,
            method: None,
            plugin: None,
            plugin_opts: None,
            sni: None,
            fp: false,
            ech_config: None,
            outbounds: None,
            interval: None,
            url: None,
            insecure: false,
            idle_session_check_interval: None,
            idle_session_timeout: None,
            min_idle_session: None,
            xmux: None,
            transport: None,
            flow: None,
            reality: None,
            ech: false,
            tls_fragment: false,
            tls_fragment_config: None,
            uot: false,
            mode: None,
        };
        // from_config does NOT fail on spawn failure or port timeout — it
        // logs a warning and returns the client.
        let client = SshOutboundClient::from_config(&cfg).await.unwrap();
        assert_eq!(client.local_ip.to_string(), "127.0.0.1");
        assert_eq!(
            client
                .allocated_port
                .load(std::sync::atomic::Ordering::Relaxed),
            1080,
        );
    }
}
