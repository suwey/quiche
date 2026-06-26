// AnyTLS outbound client.
// TLS-based multiplexed proxy protocol with traffic padding.

use std::collections::HashMap;
use std::io::Read;
use std::io::Write;
use std::net::Shutdown;
use std::net::TcpStream;
use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicU32;
use std::sync::atomic::Ordering::SeqCst;
use std::time::Duration;

use async_trait::async_trait;
use boring::ssl::SslStream;
use tokio::sync::mpsc;

use crate::config::OutboundConfig;
use crate::inbound::Destination;
use crate::outbound::OutboundClient;
use crate::outbound::common::connect_tcp_bypass_sync;
use crate::outbound::common::create_tls_stream;
use crate::outbound::common::resolve_sni;
use crate::protocol::anytls as proto;
use crate::relay::PacketRelay;
use crate::relay::StreamRelay;

pub mod uot;

use uot::UotPacketRelay;
use uot::encode_request;
use uot::magic_address_with_port;

// Re-import shared protocol primitives.
use proto::CHECK_MARK;
use proto::CMD_ALERT;
use proto::CMD_FIN;
use proto::CMD_HEART_REQUEST;
use proto::CMD_HEART_RESPONSE;
use proto::CMD_PSH;
use proto::CMD_SERVER_SETTINGS;
use proto::CMD_SETTINGS;
use proto::CMD_SYN;
use proto::CMD_SYNACK;
use proto::CMD_UPDATE_PADDING_SCHEME;
use proto::CMD_WASTE;
use proto::DEFAULT_PADDING_SCHEME;
use proto::LcgGen;
use proto::PaddingFactory;
use proto::cmd_name;
use proto::encode_frame;
use proto::encode_target;
use proto::read_frame_blocking;

/// Process-wide padding cache shared across all sessions of one client.
///
/// When the server sends `CMD_UPDATE_PADDING_SCHEME`, the new scheme is
/// stored here so that subsequent sessions can skip the update round-trip
/// and start with the correct padding immediately.
struct PaddingCache {
    /// Raw scheme text (same format as `DEFAULT_PADDING_SCHEME`).
    raw: Vec<u8>,
    /// Pre-computed MD5 hex digest of `raw`.
    md5: String,
}
impl PaddingCache {
    fn from_default() -> Self {
        Self::from_raw(DEFAULT_PADDING_SCHEME.as_bytes().to_vec())
    }

    fn from_raw(raw: Vec<u8>) -> Self {
        let md5 = Self::compute_md5(&raw);
        Self { raw, md5 }
    }

    fn compute_md5(raw: &[u8]) -> String {
        PaddingFactory::md5_hex(raw)
    }

    fn md5(&self) -> &str {
        &self.md5
    }

    fn update(&mut self, raw: Vec<u8>) {
        self.md5 = Self::compute_md5(&raw);
        self.raw = raw;
    }
}

// ========== Helpers ==========

enum ControlFrame {
    Fin(u32),
}
enum OutboundMsg {
    StreamData(u32, Vec<u8>),
    RawFrame(Vec<u8>),
    OpenStream { sid: u32, target: Vec<u8> },
}
struct IoThread {
    data_tx: mpsc::UnboundedSender<Vec<u8>>,
    /// Set to true on the first PSH for this stream. Lets the FIN handler
    /// distinguish "rejected before any data" (turn into an error) from
    /// "normal EOF after data" (return Ok(0)).
    received_any: Arc<AtomicBool>,
    /// Set when the server explicitly rejects the stream (SYNACK with
    /// payload, or FIN before any PSH). Read by `StreamHandle::read` to
    /// surface a real error instead of a silent EOF.
    error: Arc<StdMutex<Option<String>>>,
}

/// Shared mutable state between the IO thread and all streams on a session.
struct SessionInner {
    outbound_tx: mpsc::UnboundedSender<OutboundMsg>,
    control_tx: mpsc::UnboundedSender<ControlFrame>,
    streams: StdMutex<HashMap<u32, IoThread>>,
    next_sid: AtomicU32,
    active_streams: AtomicU32,
    closed: AtomicBool,
    padding: StdMutex<PaddingFactory>,
}

/// A handle to one TLS connection (one session). Holds the Arc-shared inner
/// state used by the IO thread and all streams on this session.
struct SessionHandle {
    inner: Arc<SessionInner>,
}

impl SessionHandle {
    /// Open a new stream on this session. Sends SYN + PSH(target) atomically
    /// through the IO thread's outbound channel. anytls does NOT send a
    /// success-SYNACK, so we return immediately; errors surface through
    /// `StreamHandle::read` via the per-stream `error` slot.
    ///
    /// Server behavior (observed against upstream sing-box server):
    ///   - success: no SYNACK at all, just CMD_PSH with data when ready
    ///   - reject : either CMD_SYNACK with payload (error message), or CMD_FIN
    ///     before any CMD_PSH
    /// Do NOT add an `await` on a "synack arrived" notifier here — it will
    /// hang on the success path. See memory `anytls-synack-success-silent`.
    fn open_stream(&self, target: &str) -> std::io::Result<StreamHandle> {
        let sid = self.inner.next_sid.fetch_add(1, SeqCst) + 1;
        let target_enc = encode_target(target)?;

        let (data_tx, data_rx) = mpsc::unbounded_channel();
        let received_any = Arc::new(AtomicBool::new(false));
        let error: Arc<StdMutex<Option<String>>> = Arc::new(StdMutex::new(None));

        self.inner.streams.lock().unwrap().insert(sid, IoThread {
            data_tx,
            received_any: received_any.clone(),
            error: error.clone(),
        });

        self.inner.active_streams.fetch_add(1, SeqCst);

        if self
            .inner
            .outbound_tx
            .send(OutboundMsg::OpenStream {
                sid,
                target: target_enc,
            })
            .is_err()
        {
            self.inner.streams.lock().unwrap().remove(&sid);
            self.inner.active_streams.fetch_sub(1, SeqCst);
            return Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "session closed",
            ));
        }

        Ok(StreamHandle {
            sid,
            data_rx,
            pending: Vec::new(),
            outbound_tx: self.inner.outbound_tx.clone(),
            control_tx: self.inner.control_tx.clone(),
            error,
        })
    }

    fn is_closed(&self) -> bool {
        self.inner.closed.load(SeqCst)
    }
}

pub(crate) struct StreamHandle {
    sid: u32,
    data_rx: mpsc::UnboundedReceiver<Vec<u8>>,
    outbound_tx: mpsc::UnboundedSender<OutboundMsg>,
    control_tx: mpsc::UnboundedSender<ControlFrame>,
    pending: Vec<u8>,
    error: Arc<StdMutex<Option<String>>>,
}

impl StreamHandle {
    pub(super) async fn read(
        &mut self, buf: &mut [u8],
    ) -> std::io::Result<usize> {
        if !self.pending.is_empty() {
            let n = self.pending.len().min(buf.len());
            buf[..n].copy_from_slice(&self.pending[..n]);
            self.pending.drain(..n);
            return Ok(n);
        }
        match self.data_rx.recv().await {
            Some(data) => {
                let n = data.len().min(buf.len());
                buf[..n].copy_from_slice(&data[..n]);
                if n < data.len() {
                    self.pending.extend_from_slice(&data[n..]);
                }
                Ok(n)
            },
            None =>
                if let Some(msg) = self.error.lock().unwrap().take() {
                    Err(std::io::Error::new(
                        std::io::ErrorKind::ConnectionRefused,
                        format!("anytls stream rejected: {msg}"),
                    ))
                } else {
                    Ok(0)
                },
        }
    }

    pub(super) fn write(&self, buf: &[u8]) -> std::io::Result<usize> {
        self.outbound_tx
            .send(OutboundMsg::StreamData(self.sid, buf.to_vec()))
            .map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::BrokenPipe, "closed")
            })?;
        Ok(buf.len())
    }

    pub(super) async fn close(&self) {
        let _ = self.control_tx.send(ControlFrame::Fin(self.sid));
    }
}

// ========== Session Pool ==========

/// Pool configuration sourced from [`OutboundConfig`].
#[derive(Clone, Debug)]
struct SessionPoolConfig {
    /// How often the background cleanup task runs.
    check_interval: Duration,
    /// Sessions idle longer than this are eligible for removal.
    idle_timeout: Duration,
    /// Minimum number of sessions to keep alive in the pool.
    min_idle: usize,
}

impl SessionPoolConfig {
    /// Build pool config from the outbound config, falling back to defaults:
    /// - `idle_session_check_interval`: 60 s
    /// - `idle_session_timeout`: 180 s
    /// - `min_idle_session`: 2
    fn from_outbound_config(cfg: &OutboundConfig) -> Self {
        let check_interval =
            Duration::from_secs(cfg.idle_session_check_interval.unwrap_or(60));
        let idle_timeout =
            Duration::from_secs(cfg.idle_session_timeout.unwrap_or(180));
        let min_idle = cfg.min_idle_session.unwrap_or(2);
        log::debug!(
            "anytls pool: check_interval={:?} idle_timeout={:?} min_idle={}",
            check_interval,
            idle_timeout,
            min_idle,
        );
        Self {
            check_interval,
            idle_timeout,
            min_idle,
        }
    }
}

struct SessionPoolEntry {
    handle: SessionHandle,
    idle_since: Option<std::time::Instant>,
}

struct SessionPool {
    entries: StdMutex<Vec<SessionPoolEntry>>,
    config: SessionPoolConfig,
    cleanup_abort: StdMutex<Option<tokio::task::AbortHandle>>,
}

impl SessionPool {
    fn new(config: SessionPoolConfig) -> Arc<Self> {
        Arc::new(Self {
            entries: StdMutex::new(Vec::new()),
            config,
            cleanup_abort: StdMutex::new(None),
        })
    }

    /// Get a live session from the pool, or create one via `factory`.
    /// Dead sessions are purged lazily.
    fn acquire(
        &self, factory: impl FnOnce() -> std::io::Result<SessionHandle>,
    ) -> std::io::Result<SessionHandle> {
        let mut entries = self.entries.lock().unwrap();

        // Remove dead sessions.
        entries.retain(|e| !e.handle.is_closed());

        // Return the first live session (mark as in-use).
        if let Some(entry) = entries.first_mut() {
            entry.idle_since = None;
            return Ok(SessionHandle {
                inner: entry.handle.inner.clone(),
            });
        }

        // Pool empty — create a new session.
        let handle = factory()?;
        entries.push(SessionPoolEntry {
            handle: SessionHandle {
                inner: handle.inner.clone(),
            },
            idle_since: None,
        });
        Ok(handle)
    }

    /// Background cleanup: evict timed-out sessions, replenish to
    /// `min_idle`, create sessions if pool is empty.
    fn cleanup(&self, factory: impl Fn() -> std::io::Result<SessionHandle>) {
        let mut entries = self.entries.lock().unwrap();

        // Sort by idle_since descending (longest-idle first).
        entries.sort_by(|a, b| match (&a.idle_since, &b.idle_since) {
            (Some(ta), Some(tb)) => tb.cmp(ta),
            (Some(_), None) => std::cmp::Ordering::Less,
            (None, Some(_)) => std::cmp::Ordering::Greater,
            (None, None) => std::cmp::Ordering::Equal,
        });

        let mut to_remove = Vec::new();
        let now = std::time::Instant::now();
        let mut alive = entries.len();

        for (i, entry) in entries.iter().enumerate() {
            if entry.handle.is_closed() {
                to_remove.push(i);
                alive = alive.saturating_sub(1);
                continue;
            }
            if let Some(idle) = entry.idle_since {
                if now.duration_since(idle) >= self.config.idle_timeout &&
                    alive > self.config.min_idle
                {
                    log::debug!(
                        "anytls pool: removing idle session ({:.0?} idle)",
                        now.duration_since(idle)
                    );
                    to_remove.push(i);
                    alive = alive.saturating_sub(1);
                }
            }
        }

        // Remove in reverse to keep indices valid.
        for i in to_remove.into_iter().rev() {
            let entry = entries.remove(i);
            entry.handle.inner.closed.store(true, SeqCst);
        }

        // Replenish if below min_idle (or empty).
        let target = self.config.min_idle.max(1);
        while entries.len() < target {
            match factory() {
                Ok(handle) => {
                    entries.push(SessionPoolEntry {
                        handle: SessionHandle {
                            inner: handle.inner.clone(),
                        },
                        idle_since: Some(std::time::Instant::now()),
                    });
                    log::debug!(
                        "anytls pool: replenished (now {} sessions)",
                        entries.len()
                    );
                },
                Err(e) => {
                    log::debug!("anytls pool: replenish failed: {e}");
                    break;
                },
            }
        }

        // Mark any in-use sessions that became idle.
        for entry in entries.iter_mut() {
            if entry.idle_since.is_none() &&
                entry.handle.inner.active_streams.load(SeqCst) == 0
            {
                entry.idle_since = Some(std::time::Instant::now());
            }
        }
    }

    /// Spawn the periodic cleanup background task.
    fn spawn_cleanup(
        self: &Arc<Self>,
        factory: impl Fn() -> std::io::Result<SessionHandle> + Send + Sync + 'static,
    ) {
        let pool = Arc::clone(self);
        let interval = self.config.check_interval;
        let handle = tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            loop {
                ticker.tick().await;
                pool.cleanup(&factory);
            }
        });
        *self.cleanup_abort.lock().unwrap() = Some(handle.abort_handle());
    }

    /// Close all sessions and cancel the cleanup task.
    fn shutdown(&self) {
        let mut entries = self.entries.lock().unwrap();
        for entry in entries.drain(..) {
            entry.handle.inner.closed.store(true, SeqCst);
        }
        if let Some(abort) = self.cleanup_abort.lock().unwrap().take() {
            abort.abort();
        }
    }
}

// ========== Blocking I/O ==========

fn write_padded(
    stream: &mut SslStream<TcpStream>, mut data: Vec<u8>,
    padding: &StdMutex<PaddingFactory>, pkt: u32,
) -> std::io::Result<()> {
    let pf = padding.lock().unwrap();
    if pkt >= pf.stop() {
        drop(pf);
        stream.write_all(&data)?;
        stream.flush()?;
        return Ok(());
    }
    let sizes = pf.generate_sizes(pkt);
    drop(pf);
    if sizes.is_empty() {
        stream.write_all(&data)?;
        stream.flush()?;
        return Ok(());
    }
    for &size in &sizes {
        let remain = data.len();
        if size == CHECK_MARK {
            if remain == 0 {
                break;
            }
            continue;
        }
        let size = size.max(0) as usize;
        if remain > size {
            let rest = data.split_off(size);
            stream.write_all(&data)?;
            data = rest;
        } else if remain > 0 {
            let pad_len = size.saturating_sub(remain).saturating_sub(7);
            if pad_len > 0 {
                let mut pad = vec![0u8; 7 + pad_len];
                pad[0] = CMD_WASTE;
                pad[5..7].copy_from_slice(&(pad_len as u16).to_be_bytes());
                data.extend_from_slice(&pad);
            }
            stream.write_all(&data)?;
            data.clear();
        } else {
            let mut pad = vec![0u8; 7 + size];
            pad[0] = CMD_WASTE;
            pad[5..7].copy_from_slice(&(size as u16).to_be_bytes());
            stream.write_all(&pad)?;
        }
    }
    if !data.is_empty() {
        stream.write_all(&data)?;
    }
    stream.flush()?;
    Ok(())
}

fn handle_blocking_frame(
    cmd: u8, sid: u32, data: Vec<u8>, inner: &SessionInner,
    padding_cache: Option<&Arc<StdMutex<PaddingCache>>>,
) {
    let outbound_tx = &inner.outbound_tx;
    match cmd {
        CMD_PSH => {
            let map = inner.streams.lock().unwrap();
            if let Some(entry) = map.get(&sid) {
                entry.received_any.store(true, SeqCst);
                let _ = entry.data_tx.send(data);
            }
        },
        CMD_SYNACK => {
            // anytls only emits SYNACK on error; success is silent (or, in
            // some server versions, an empty SYNACK we deliberately ignore).
            // Treat any non-empty payload as a server-side rejection.
            if !data.is_empty() {
                let mut map = inner.streams.lock().unwrap();
                if let Some(entry) = map.remove(&sid) {
                    *entry.error.lock().unwrap() =
                        Some(String::from_utf8_lossy(&data).to_string());
                    drop(entry.data_tx);
                    drop(map);
                    inner.active_streams.fetch_sub(1, SeqCst);
                }
            }
        },
        CMD_FIN => {
            let mut map = inner.streams.lock().unwrap();
            if let Some(entry) = map.remove(&sid) {
                if !entry.received_any.load(SeqCst) {
                    *entry.error.lock().unwrap() =
                        Some("server closed stream before any data".to_string());
                }
                drop(entry.data_tx);
            }
            drop(map);
            inner.active_streams.fetch_sub(1, SeqCst);
        },
        CMD_HEART_RESPONSE => {},
        CMD_HEART_REQUEST => {
            if let Ok(frame) = encode_frame(CMD_HEART_RESPONSE, 0, &[]) {
                let _ = outbound_tx.send(OutboundMsg::RawFrame(frame));
            }
        },
        CMD_UPDATE_PADDING_SCHEME => {
            log::debug!("anytls: received padding scheme update");
            match PaddingFactory::new(&data) {
                Ok(f) => {
                    *inner.padding.lock().unwrap() = f;
                    // Update client-wide cache so new sessions start with
                    // this scheme and skip the update round-trip.
                    if let Some(cache) = padding_cache {
                        cache.lock().unwrap().update(data);
                    }
                },
                Err(e) => log::warn!("anytls padding: {e}"),
            }
        },
        CMD_SERVER_SETTINGS => {
            log::debug!("anytls settings: {}", String::from_utf8_lossy(&data))
        },
        CMD_ALERT => {
            log::warn!("anytls ALERT: {}", String::from_utf8_lossy(&data));
            inner.closed.store(true, SeqCst);
        },
        _ => {},
    }
}

fn run_io_loop(
    mut stream: SslStream<TcpStream>, inner: &SessionInner,
    mut control_rx: mpsc::UnboundedReceiver<ControlFrame>,
    mut outbound_rx: mpsc::UnboundedReceiver<OutboundMsg>,
    padding_cache: Arc<StdMutex<PaddingCache>>,
) {
    stream
        .get_mut()
        .set_read_timeout(Some(Duration::from_secs(3)))
        .ok();
    let mut pkt_counter = 1u32;
    log::debug!("io thread started");
    loop {
        if inner.closed.load(SeqCst) {
            break;
        }

        loop {
            match control_rx.try_recv() {
                Ok(ControlFrame::Fin(sid)) => {
                    if let Ok(frame) = encode_frame(CMD_FIN, sid, &[]) {
                        let pkt = pkt_counter;
                        pkt_counter += 1;
                        let _ =
                            write_padded(&mut stream, frame, &inner.padding, pkt);
                    }
                },
                Err(mpsc::error::TryRecvError::Empty) => break,
                Err(mpsc::error::TryRecvError::Disconnected) => {
                    inner.closed.store(true, SeqCst);
                    let _ = stream.get_mut().shutdown(Shutdown::Both);
                    return;
                },
            }
        }
        loop {
            match outbound_rx.try_recv() {
                Ok(OutboundMsg::OpenStream { sid, target }) => {
                    log::debug!(
                        "io: send cmd=SYN+PSH sid={sid} len={}",
                        target.len()
                    );
                    if let Ok(syn) = encode_frame(CMD_SYN, sid, &[]) {
                        if let Ok(psh) = encode_frame(CMD_PSH, sid, &target) {
                            let mut combined =
                                Vec::with_capacity(syn.len() + psh.len());
                            combined.extend_from_slice(&syn);
                            combined.extend_from_slice(&psh);
                            let pkt = pkt_counter;
                            pkt_counter += 1;
                            if write_padded(
                                &mut stream,
                                combined,
                                &inner.padding,
                                pkt,
                            )
                            .is_err()
                            {
                                break;
                            }
                        }
                    }
                },
                Ok(OutboundMsg::StreamData(sid, data)) => {
                    if let Ok(frame) = encode_frame(CMD_PSH, sid, &data) {
                        let pkt = pkt_counter;
                        pkt_counter += 1;
                        if write_padded(&mut stream, frame, &inner.padding, pkt)
                            .is_err()
                        {
                            break;
                        }
                    }
                },
                Ok(OutboundMsg::RawFrame(frame)) => {
                    let pkt = pkt_counter;
                    pkt_counter += 1;
                    if write_padded(&mut stream, frame, &inner.padding, pkt)
                        .is_err()
                    {
                        break;
                    }
                },
                Err(mpsc::error::TryRecvError::Empty) => break,
                Err(mpsc::error::TryRecvError::Disconnected) => {
                    inner.closed.store(true, SeqCst);
                    let _ = stream.get_mut().shutdown(Shutdown::Both);
                    return;
                },
            }
        }
        match read_frame_blocking(&mut stream) {
            Ok((cmd, sid, data)) => {
                log::debug!(
                    "io: recv cmd={} sid={sid} len={}",
                    cmd_name(cmd),
                    data.len()
                );
                pkt_counter += 1;
                handle_blocking_frame(
                    cmd,
                    sid,
                    data,
                    inner,
                    Some(&padding_cache),
                );
            },
            Err(ref e)
                if e.kind() == std::io::ErrorKind::WouldBlock ||
                    e.kind() == std::io::ErrorKind::TimedOut =>
            {
                if let Ok(frame) = encode_frame(CMD_HEART_REQUEST, 0, &[]) {
                    let pkt = pkt_counter;
                    pkt_counter += 1;
                    let _ = write_padded(&mut stream, frame, &inner.padding, pkt);
                }
            },
            Err(e) => {
                log::debug!("io thread err: {e}");
                break;
            },
        }
    }
    let _ = stream.get_mut().shutdown(Shutdown::Both);
    inner.closed.store(true, SeqCst);
    log::debug!("io thread ended");
}

// ========== Client ==========

pub struct AnyTlsOutboundClient {
    addr: std::net::SocketAddr,
    sni: String,
    password: String,
    fp: bool,
    insecure: bool,
    tcp_pool: Arc<SessionPool>,
    udp_pool: Arc<SessionPool>,
    /// Cached padding scheme shared across TCP and UDP sessions.
    padding_cache: Arc<StdMutex<PaddingCache>>,
}

impl AnyTlsOutboundClient {
    pub async fn from_config(
        configs: Vec<&OutboundConfig>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let config = configs.first().ok_or("no anytls outbound config")?;
        let server = config.server.as_ref().ok_or("anytls missing server")?;
        let password = config.password.clone().unwrap_or_default();
        let sni = resolve_sni(config).map_err(|e| format!("anytls: {e}"))?;
        let addr = crate::outbound::common::resolve_addr(server)
            .map_err(|e| format!("anytls: {e}"))?;
        let padding_cache = Arc::new(StdMutex::new(PaddingCache::from_default()));

        let pool_config = SessionPoolConfig::from_outbound_config(config);
        let tcp_pool = SessionPool::new(pool_config.clone());
        let udp_pool = SessionPool::new(pool_config);

        // Eagerly create one TLS session before TUN comes up, so the
        // initial TCP connection uses normal routing (not TUN). If this
        // fails the session will be lazily re-created on first dial().
        if let Ok(handle) = Self::create_session_inner(
            addr,
            &sni,
            &password,
            config.fp,
            config.insecure,
            padding_cache.clone(),
        ) {
            tcp_pool.entries.lock().unwrap().push(SessionPoolEntry {
                handle,
                idle_since: Some(std::time::Instant::now()),
            });
        }

        let client = Self {
            addr,
            sni,
            password,
            fp: config.fp,
            insecure: config.insecure,
            tcp_pool,
            udp_pool,
            padding_cache,
        };

        // Spawn periodic cleanup for both pools.
        client.spawn_pool_cleanup_tasks();

        Ok(client)
    }

    /// Spawn background cleanup tasks for TCP and UDP session pools.
    fn spawn_pool_cleanup_tasks(&self) {
        let addr = self.addr;
        let sni = self.sni.clone();
        let password = self.password.clone();
        let fp = self.fp;
        let insecure = self.insecure;
        let pc = self.padding_cache.clone();
        self.tcp_pool.spawn_cleanup(move || {
            Self::create_session_inner(
                addr,
                &sni,
                &password,
                fp,
                insecure,
                pc.clone(),
            )
        });

        let addr = self.addr;
        let sni = self.sni.clone();
        let password = self.password.clone();
        let fp = self.fp;
        let insecure = self.insecure;
        let pc = self.padding_cache.clone();
        self.udp_pool.spawn_cleanup(move || {
            Self::create_session_inner(
                addr,
                &sni,
                &password,
                fp,
                insecure,
                pc.clone(),
            )
        });
    }

    /// Create a new TLS session and spawn its IO thread.
    /// Does NOT open the first stream — call `session.open_stream(target)`
    fn create_session(&self) -> std::io::Result<SessionHandle> {
        Self::create_session_inner(
            self.addr,
            &self.sni,
            &self.password,
            self.fp,
            self.insecure,
            self.padding_cache.clone(),
        )
    }

    /// Static version of create_session — used both by from_config (eager
    /// pre-connect) and by ensure_session (lazy reconnect).
    fn create_session_inner(
        addr: std::net::SocketAddr, sni: &str, password: &str, fp: bool,
        insecure: bool, padding_cache: Arc<StdMutex<PaddingCache>>,
    ) -> std::io::Result<SessionHandle> {
        let (control_tx, control_rx) = mpsc::unbounded_channel();
        let (outbound_tx, outbound_rx) = mpsc::unbounded_channel::<OutboundMsg>();

        // Initialize padding from the client-wide cache (avoids update
        // round-trip when reconnecting).
        let cached_raw = padding_cache.lock().unwrap().raw.clone();
        let initial_padding = PaddingFactory::new(&cached_raw)
            .unwrap_or_else(|_| PaddingFactory::default_factory());

        let inner = Arc::new(SessionInner {
            outbound_tx: outbound_tx.clone(),
            control_tx: control_tx.clone(),
            streams: StdMutex::new(HashMap::new()),
            next_sid: AtomicU32::new(0),
            active_streams: AtomicU32::new(0),
            closed: AtomicBool::new(false),
            padding: StdMutex::new(initial_padding),
        });

        let inner_clone = inner.clone();
        let sni = sni.to_string();
        let password = password.to_string();

        tokio::task::spawn_blocking(move || {
            let tcp = match connect_tcp_bypass_sync(addr) {
                Ok(s) => s,
                Err(e) => {
                    log::error!("anytls tcp: {e}");
                    inner_clone.closed.store(true, SeqCst);
                    return;
                },
            };
            let mut stream = match create_tls_stream(tcp, &sni, fp, insecure) {
                Ok(s) => s,
                Err(e) => {
                    log::error!("anytls tls: {e}");
                    inner_clone.closed.store(true, SeqCst);
                    return;
                },
            };
            log::debug!("anytls TLS OK");

            // Auth
            let pwd_hash = match proto::sha256(password.as_bytes()) {
                Ok(h) => h,
                Err(e) => {
                    log::error!("anytls hash: {e}");
                    inner_clone.closed.store(true, SeqCst);
                    return;
                },
            };
            let mut auth_padding = [0u8; 30];
            let mut rng = LcgGen::new();
            rng.fill_bytes(&mut auth_padding);
            let auth: Vec<u8> =
                [pwd_hash.as_slice(), &30u16.to_be_bytes(), &auth_padding]
                    .concat();
            if let Err(e) = stream.write_all(&auth) {
                log::error!("anytls auth: {e}");
                inner_clone.closed.store(true, SeqCst);
                return;
            }
            stream.flush().ok();

            // Settings (sent once per session)
            let settings_md5 = padding_cache.lock().unwrap().md5().to_string();
            let settings = format!(
                "v=2\nclient=anywhere/0.1.0\npadding-md5={}",
                settings_md5
            );
            let mut settings_buf = Vec::new();
            if let Ok(frame) = encode_frame(CMD_SETTINGS, 0, settings.as_bytes())
            {
                settings_buf.extend_from_slice(&frame);
            }
            if let Err(e) =
                write_padded(&mut stream, settings_buf, &inner_clone.padding, 0)
            {
                log::error!("anytls settings: {e}");
                inner_clone.closed.store(true, SeqCst);
                return;
            }
            log::debug!("anytls settings sent");

            // Read settings response
            let mut resp = [0u8; 4096];
            match stream.read(&mut resp) {
                Ok(n) => {
                    log::debug!("anytls settings response: {} bytes", n);
                    let mut off = 0;
                    while off + 7 <= n {
                        let cmd = resp[off];
                        let sid_val = u32::from_be_bytes([
                            resp[off + 1],
                            resp[off + 2],
                            resp[off + 3],
                            resp[off + 4],
                        ]);
                        let len =
                            u16::from_be_bytes([resp[off + 5], resp[off + 6]])
                                as usize;
                        if off + 7 + len > n {
                            break;
                        }
                        let d = resp[off + 7..off + 7 + len].to_vec();
                        handle_blocking_frame(
                            cmd,
                            sid_val,
                            d,
                            &inner_clone,
                            Some(&padding_cache),
                        );
                        off += 7 + len;
                    }
                },
                Err(e) => {
                    log::error!("anytls settings read: {e}");
                    inner_clone.closed.store(true, SeqCst);
                    return;
                },
            }

            // Enter IO loop
            run_io_loop(
                stream,
                &inner_clone,
                control_rx,
                outbound_rx,
                padding_cache,
            );
        });

        Ok(SessionHandle { inner })
    }
}

#[async_trait]
impl OutboundClient for AnyTlsOutboundClient {
    async fn dial(
        &self, dest: &Destination,
    ) -> Result<Box<dyn StreamRelay>, Box<dyn std::error::Error>> {
        let target = dest.to_string();
        let session = self.tcp_pool.acquire(|| self.create_session())?;
        let stream = session.open_stream(&target)?;
        Ok(Box::new(AnyTlsStreamRelay::new(stream)))
    }

    async fn dial_udp(
        &self, initial_dest: &Destination,
    ) -> Result<Box<dyn PacketRelay>, Box<dyn std::error::Error>> {
        let session = self.udp_pool.acquire(|| self.create_session())?;
        let magic = magic_address_with_port();
        let stream = session.open_stream(&magic)?;

        let req = encode_request(false, initial_dest)?;
        stream.write(&req)?;
        Ok(Box::new(UotPacketRelay::new(stream)))
    }

}

impl Drop for AnyTlsOutboundClient {
    fn drop(&mut self) {
        // Shut down session pools: close all sessions and abort cleanup
        // tasks so tokio runtime shutdown doesn't hang.
        self.tcp_pool.shutdown();
        self.udp_pool.shutdown();
    }
}

// ========== StreamRelay ==========

pub(crate) struct AnyTlsStreamRelay {
    handle: Option<StreamHandle>,
}
impl AnyTlsStreamRelay {
    fn new(handle: StreamHandle) -> Self {
        Self {
            handle: Some(handle),
        }
    }
}

#[async_trait]
impl StreamRelay for AnyTlsStreamRelay {
    async fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self.handle.as_mut() {
            Some(h) => h.read(buf).await,
            None => Ok(0),
        }
    }

    async fn write(&mut self, buf: &[u8]) -> std::io::Result<()> {
        match self.handle.as_ref() {
            Some(h) => {
                h.write(buf).map(|_| ())?;
                Ok(())
            },
            None => Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "closed",
            )),
        }
    }

    async fn shutdown(&mut self) -> std::io::Result<()> {
        if let Some(h) = self.handle.take() {
            h.close().await;
        }
        Ok(())
    }
}
