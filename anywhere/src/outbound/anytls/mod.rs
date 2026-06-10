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
use boring::hash::MessageDigest;
use boring::hash::hash;
use boring::ssl::SslStream;
use bytes::BufMut;
use tokio::sync::mpsc;

use crate::config::OutboundConfig;
use crate::inbound::Destination;
use crate::outbound::OutboundClient;
use crate::outbound::common::connect_tcp_bypass_sync;
use crate::outbound::common::create_tls_stream;
use crate::outbound::common::resolve_sni;
use crate::relay::PacketRelay;
use crate::relay::StreamRelay;

pub mod uot;

use uot::UotPacketRelay;
use uot::encode_request;
use uot::magic_address_with_port;

// ========== LCG PRNG ==========

struct LcgGen(u64);
impl LcgGen {
    fn new() -> Self {
        Self(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos() as u64)
                .unwrap_or(1),
        )
    }

    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0
    }

    fn range(&mut self, min: i64, max: i64) -> i64 {
        min + (self.next() % (max - min + 1) as u64) as i64
    }
}

// ========== Protocol Constants ==========

const CMD_WASTE: u8 = 0;
const CMD_SYN: u8 = 1;
const CMD_PSH: u8 = 2;
const CMD_FIN: u8 = 3;
const CMD_SETTINGS: u8 = 4;
const CMD_ALERT: u8 = 5;
const CMD_UPDATE_PADDING_SCHEME: u8 = 6;
const CMD_SYNACK: u8 = 7;
const CMD_HEART_REQUEST: u8 = 8;
const CMD_HEART_RESPONSE: u8 = 9;
const CMD_SERVER_SETTINGS: u8 = 10;

fn cmd_name(cmd: u8) -> &'static str {
    match cmd {
        CMD_WASTE => "WASTE",
        CMD_SYN => "SYN",
        CMD_PSH => "PSH",
        CMD_FIN => "FIN",
        CMD_SETTINGS => "SETTINGS",
        CMD_ALERT => "ALERT",
        CMD_UPDATE_PADDING_SCHEME => "UPDATE_PADDING_SCHEME",
        CMD_SYNACK => "SYNACK",
        CMD_HEART_REQUEST => "HEART_REQUEST",
        CMD_HEART_RESPONSE => "HEART_RESPONSE",
        CMD_SERVER_SETTINGS => "SERVER_SETTINGS",
        _ => "UNKNOWN",
    }
}

// ========== Padding ==========

const CHECK_MARK: i32 = -1;
const DEFAULT_PADDING_SCHEME: &str = r#"stop=8
0=30-30
1=100-400
2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000
3=9-9,500-1000
4=500-1000
5=500-1000
6=500-1000
7=500-1000"#;

#[derive(Clone)]
struct PaddingFactory {
    scheme: HashMap<String, String>,
    stop: u32,
}
impl PaddingFactory {
    fn new(raw: &[u8]) -> std::io::Result<Self> {
        let mut scheme = HashMap::new();
        for line in std::str::from_utf8(raw)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?
            .lines()
        {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let Some((k, v)) = line.split_once('=') else {
                continue;
            };
            scheme.insert(k.trim().to_string(), v.trim().to_string());
        }
        let stop =
            scheme
                .get("stop")
                .and_then(|s| s.parse().ok())
                .ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "missing stop",
                    )
                })?;
        Ok(Self { scheme, stop })
    }

    fn default_factory() -> Self {
        Self::new(DEFAULT_PADDING_SCHEME.as_bytes()).expect("default")
    }

    fn generate_sizes(&self, pkt: u32) -> Vec<i32> {
        let mut sizes = Vec::new();
        let Some(spec) = self.scheme.get(&pkt.to_string()) else {
            return sizes;
        };
        let mut rng = LcgGen::new();
        for part in spec.split(',') {
            let part = part.trim();
            if part == "c" {
                sizes.push(CHECK_MARK);
                continue;
            }
            let Some((a, b)) = part.split_once('-') else {
                continue;
            };
            let min: i64 = a.trim().parse().unwrap_or(0);
            let max: i64 = b.trim().parse().unwrap_or(0);
            if min <= 0 || max <= 0 {
                continue;
            }
            let (mn, mx) = (min.min(max), min.max(max));
            sizes.push(if mn == mx {
                mn as i32
            } else {
                rng.range(mn, mx) as i32
            });
        }
        sizes
    }

    fn stop(&self) -> u32 {
        self.stop
    }
}

// ========== Helpers ==========

fn encode_target(target: &str) -> std::io::Result<Vec<u8>> {
    let mut buf = Vec::new();
    let (host, port_str) = if let Some(rest) = target.strip_prefix('[') {
        let (host, rest) = rest.split_once(']').ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "unclosed bracket",
            )
        })?;
        (host, rest.strip_prefix(':').unwrap_or(""))
    } else {
        let Some((h, p)) = target.rsplit_once(':') else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("no port: {target}"),
            ));
        };
        (h, p)
    };
    let port: u16 = port_str.parse().map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid port")
    })?;
    if let Ok(ip) = host.parse::<std::net::Ipv4Addr>() {
        buf.put_u8(0x01);
        buf.extend_from_slice(&ip.octets());
    } else if let Ok(ip) = host.parse::<std::net::Ipv6Addr>() {
        buf.put_u8(0x04);
        buf.extend_from_slice(&ip.octets());
    } else {
        if host.len() > 255 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "domain too long",
            ));
        }
        buf.put_u8(0x03);
        buf.put_u8(host.len() as u8);
        buf.extend_from_slice(host.as_bytes());
    }
    buf.put_u16(port);
    Ok(buf)
}

fn encode_frame(
    cmd: u8, stream_id: u32, data: &[u8],
) -> std::io::Result<Vec<u8>> {
    if data.len() > u16::MAX as usize {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "payload too large",
        ));
    }
    let mut buf = Vec::with_capacity(7 + data.len());
    buf.push(cmd);
    buf.extend_from_slice(&stream_id.to_be_bytes());
    buf.extend_from_slice(&(data.len() as u16).to_be_bytes());
    buf.extend_from_slice(data);
    Ok(buf)
}

fn read_frame_blocking(
    stream: &mut SslStream<TcpStream>,
) -> std::io::Result<(u8, u32, Vec<u8>)> {
    let mut hdr = [0u8; 7];
    stream.read_exact(&mut hdr)?;
    let command = hdr[0];
    let stream_id = u32::from_be_bytes([hdr[1], hdr[2], hdr[3], hdr[4]]);
    let data_len = u16::from_be_bytes([hdr[5], hdr[6]]) as usize;
    let mut data = vec![0u8; data_len];
    if data_len > 0 {
        stream.read_exact(&mut data)?;
    }
    Ok((command, stream_id, data))
}

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

fn handle_blocking_frame(cmd: u8, sid: u32, data: Vec<u8>, inner: &SessionInner) {
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
        CMD_UPDATE_PADDING_SCHEME => match PaddingFactory::new(&data) {
            Ok(f) => {
                *inner.padding.lock().unwrap() = f;
            },
            Err(e) => log::warn!("anytls padding: {e}"),
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

/// Duration after which an idle session (0 active streams) self-closes.
const IDLE_SESSION_TIMEOUT: std::time::Duration =
    std::time::Duration::from_secs(300);

fn run_io_loop(
    mut stream: SslStream<TcpStream>, inner: &SessionInner,
    mut control_rx: mpsc::UnboundedReceiver<ControlFrame>,
    mut outbound_rx: mpsc::UnboundedReceiver<OutboundMsg>,
) {
    stream
        .get_mut()
        .set_read_timeout(Some(Duration::from_secs(3)))
        .ok();
    let mut pkt_counter = 1u32;
    let mut idle_since: Option<std::time::Instant> = None;
    log::debug!("io thread started");
    loop {
        if inner.closed.load(SeqCst) {
            break;
        }

        // Idle timeout: if no active streams for 30s, shut down.
        if inner.active_streams.load(SeqCst) == 0 {
            let now = std::time::Instant::now();
            match idle_since {
                None => idle_since = Some(now),
                Some(t) if now.duration_since(t) >= IDLE_SESSION_TIMEOUT => {
                    log::debug!("anytls session idle timeout");
                    break;
                },
                _ => {},
            }
        } else {
            idle_since = None;
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
                handle_blocking_frame(cmd, sid, data, inner);
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
    session: StdMutex<Option<SessionHandle>>,
    udp_session: StdMutex<Option<SessionHandle>>,
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
        // Eagerly create the TLS session before TUN comes up, so the initial
        // TCP connection to the proxy server uses normal routing (not TUN).
        // If this fails the session will be lazily re-created on first dial().
        let session = Self::create_session_inner(
            addr,
            &sni,
            &password,
            config.fp,
            config.insecure,
        )
        .ok();

        Ok(Self {
            addr,
            sni,
            password,
            fp: config.fp,
            insecure: config.insecure,
            session: StdMutex::new(session),
            udp_session: StdMutex::new(None),
        })
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
        )
    }

    /// Static version of create_session — used both by from_config (eager
    /// pre-connect) and by ensure_session (lazy reconnect).
    fn create_session_inner(
        addr: std::net::SocketAddr, sni: &str, password: &str, fp: bool,
        insecure: bool,
    ) -> std::io::Result<SessionHandle> {
        let (control_tx, control_rx) = mpsc::unbounded_channel();
        let (outbound_tx, outbound_rx) = mpsc::unbounded_channel::<OutboundMsg>();

        let inner = Arc::new(SessionInner {
            outbound_tx: outbound_tx.clone(),
            control_tx: control_tx.clone(),
            streams: StdMutex::new(HashMap::new()),
            next_sid: AtomicU32::new(0),
            active_streams: AtomicU32::new(0),
            closed: AtomicBool::new(false),
            padding: StdMutex::new(PaddingFactory::default_factory()),
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
            let pwd_hash =
                match hash(MessageDigest::sha256(), password.as_bytes()) {
                    Ok(h) => h,
                    Err(e) => {
                        log::error!("anytls hash: {e}");
                        inner_clone.closed.store(true, SeqCst);
                        return;
                    },
                };
            let mut auth_padding = [0u8; 30];
            let mut rng = LcgGen::new();
            for b in auth_padding.iter_mut() {
                *b = rng.next() as u8;
            }
            let auth =
                [pwd_hash.as_ref(), &30u16.to_be_bytes(), &auth_padding].concat();
            if let Err(e) = stream.write_all(&auth) {
                log::error!("anytls auth: {e}");
                inner_clone.closed.store(true, SeqCst);
                return;
            }
            stream.flush().ok();

            // Settings (sent once per session)
            let settings_md5 = match hash(
                MessageDigest::md5(),
                DEFAULT_PADDING_SCHEME.as_bytes(),
            ) {
                Ok(h) => h
                    .as_ref()
                    .iter()
                    .map(|b| format!("{:02x}", b))
                    .collect::<String>(),
                Err(e) => {
                    log::error!("anytls settings md5: {e}");
                    inner_clone.closed.store(true, SeqCst);
                    return;
                },
            };
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
                        handle_blocking_frame(cmd, sid_val, d, &inner_clone);
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
            run_io_loop(stream, &inner_clone, control_rx, outbound_rx);
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
        let guard = self.ensure_session()?;
        let stream = guard.as_ref().unwrap().open_stream(&target)?;
        Ok(Box::new(AnyTlsStreamRelay::new(stream)))
    }

    async fn dial_udp(
        &self, initial_dest: &Destination,
    ) -> Result<Box<dyn PacketRelay>, Box<dyn std::error::Error>> {
        let guard = self.ensure_udp_session()?;
        let magic = magic_address_with_port();
        let stream = guard.as_ref().unwrap().open_stream(&magic)?;

        let req = encode_request(false, initial_dest)?;
        stream.write(&req)?;
        Ok(Box::new(UotPacketRelay::new(stream)))
    }

    async fn test_latency(&self, _host: &str, _port: u16) -> Option<u64> {
        let addr = self.addr;
        let sni = self.sni.clone();
        let fp = self.fp;
        let insecure = self.insecure;

        tokio::time::timeout(
            Duration::from_secs(5),
            tokio::task::spawn_blocking(move || {
                use std::time::Instant;

                let start = Instant::now();

                let tcp = connect_tcp_bypass_sync(addr).ok()?;
                let stream = create_tls_stream(tcp, &sni, fp, insecure).ok()?;
                let elapsed = start.elapsed().as_millis() as u64;
                let _ = stream.get_ref().shutdown(std::net::Shutdown::Both);
                Some(elapsed)
            }),
        )
        .await
        .ok()?
        .ok()?
    }
}

impl AnyTlsOutboundClient {
    /// Reuse the current session if alive; otherwise build a fresh one.
    fn ensure_session(
        &self,
    ) -> std::io::Result<std::sync::MutexGuard<'_, Option<SessionHandle>>> {
        let mut guard = self.session.lock().unwrap();
        let need_new = match &*guard {
            Some(s) => s.is_closed(),
            None => true,
        };
        if need_new {
            if guard.is_some() {
                log::debug!("anytls session closed, creating new one");
            }
            let session = self.create_session()?;
            *guard = Some(session);
        }
        Ok(guard)
    }

    /// Separate session for UDP traffic — avoids head-of-line blocking from
    /// TCP streams on the main session.
    fn ensure_udp_session(
        &self,
    ) -> std::io::Result<std::sync::MutexGuard<'_, Option<SessionHandle>>> {
        let mut guard = self.udp_session.lock().unwrap();
        let need_new = match &*guard {
            Some(s) => s.is_closed(),
            None => true,
        };
        if need_new {
            let session = self.create_session()?;
            *guard = Some(session);
        }
        Ok(guard)
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
