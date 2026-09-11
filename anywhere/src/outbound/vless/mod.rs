use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::time::Duration;

use crate::config::OutboundConfig;
use crate::inbound::Address;
use crate::inbound::Destination;
use crate::obfuscation::vision::VisionFilterState;
use crate::obfuscation::vision::VisionReader;
use crate::obfuscation::vision::VisionWriter;
use crate::outbound::OutboundClient;
use crate::outbound::common::AsyncTlsStream;
use crate::outbound::common::connect_tcp_bypass;
use crate::outbound::common::resolve_sni;
use crate::protocol::vless::VlessCommand;
use crate::protocol::vless::encode_request_bytes;
use crate::relay::PacketRelay;
use crate::relay::StreamRelay;
use crate::tlsfragment::FragmentConfig;
use crate::transport::reality::RealityParams;
use crate::transport::reality::connect_reality_stream;
use crate::transport::ws::WsConnAsync;
use crate::transport::ws::WsConnAsyncReader;
use crate::transport::ws::WsConnAsyncWriter;
use crate::transport::ws::WsFrame;
use async_trait::async_trait;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio::io::ReadHalf;
use tokio::io::WriteHalf;
use tokio::sync::mpsc;
use tokio::sync::mpsc::error::TryRecvError;

// ---------------------------------------------------------------------------
// UUID parsing
// ---------------------------------------------------------------------------

pub(crate) fn parse_uuid(
    s: &str,
) -> Result<[u8; 16], Box<dyn std::error::Error>> {
    let s = s.replace('-', "");
    if s.len() != 32 {
        return Err("vless: invalid UUID".into());
    }
    let mut out = [0u8; 16];
    for i in 0..16 {
        out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16)
            .map_err(|_| format!("vless: invalid UUID hex byte at offset {i}"))?;
    }
    Ok(out)
}

/// Validate the vless outbound config (WS path and REALITY path rules).
///
/// - `flow` set requires the `reality` section (Xray refuses flow over
///   non-TLS/REALITY transports, §S2.7);
/// - `reality` cannot coexist with a `[transport]` (WS) section — ws-over-
///   REALITY is not supported yet;
/// - `reality` cannot coexist with `insecure = true` — REALITY's certificate
///   check is a custom algorithm, "skip verification" is undefined for it;
/// - `reality` field decoding is validated by `RealityConfig::parse`.
pub(crate) fn validate_vless_config(
    cfg: &OutboundConfig,
) -> Result<(), String> {
    if let Some(flow) = cfg.flow.as_deref() {
        if !flow.is_empty() && cfg.reality.is_none() {
            return Err(format!(
                "vless: flow '{flow}' requires a [outbounds.reality] section \
                 (only TLS/REALITY transports support flow)"
            ));
        }
    }
    if cfg.reality.is_some() {
        if cfg.insecure {
            return Err(
                "vless: reality and insecure=true are mutually exclusive"
                    .to_string(),
            );
        }
        if cfg.transport.is_some() {
            return Err(
                "vless: reality cannot be combined with a [transport] (WS) \
                 section"
                    .to_string(),
            );
        }
        if cfg.ech {
            return Err(
                "vless: reality cannot be combined with ech=true — the \
                 borrowed-target SNI is the camouflage itself, there is no \
                 ECH offer to make"
                    .to_string(),
            );
        }
    }
    Ok(())
}
// ---------------------------------------------------------------------------
// Constants — tune pool size
// ---------------------------------------------------------------------------
// Pool water mark — read from config at construction time.
// Default matches the old hardcoded value for backward compatibility.
// ---------------------------------------------------------------------------

/// Default number of pre-built WS connections the pool tries to keep ready.
const DEFAULT_POOL_WATER_MARK: usize = 30;

// ---------------------------------------------------------------------------
// VLESS Pool — pre-built transports ready for immediate VLESS handshake
// ---------------------------------------------------------------------------

/// Transport builder for one pool: WS (framed) or REALITY (raw TLS byte
/// stream). Both share the water-mark management below.
enum TransportBuilder {
    Ws {
        path: String,
        headers: HashMap<String, String>,
        /// ECH offer for the TLS handshake (config / grease / none).
        ech: crate::ech::EchOffer<'static>,
    },
    Reality {
        params: RealityParams,
    },
}

/// An established transport connection ready for the VLESS handshake.
pub(crate) enum VlessStream {
    Ws(WsStreamAsync),
    Reality(AsyncTlsStream),
}

/// REALITY+VLESS servers reap inbound connections whose VLESS request has
/// not arrived within their handshake window (xray default: 60s,
/// `features/policy/default.go` SessionDefault → Timeouts.Handshake). A
/// pre-built transport older than half of that window is therefore already
/// dead on the server side; `VlessPool::acquire` discards such entries and
/// lets the replenisher rebuild. WS transports have no equivalent server
/// contract and keep the old age-unbounded behavior.
const REALITY_POOL_MAX_IDLE: Duration = Duration::from_secs(30);

struct VlessPool {
    ready: tokio::sync::Mutex<std::collections::VecDeque<(VlessStream, std::time::Instant)>>,
    building: AtomicUsize,
    addr: SocketAddr,
    /// TLS SNI — also the REALITY borrow-target name.
    tls_server: String,
    insecure: bool,
    tls_fp: bool,
    fragment: Option<FragmentConfig>,
    builder: TransportBuilder,
    /// Target pool size (water mark).
    water_mark: usize,
}

impl VlessPool {
    fn new(
        addr: SocketAddr, tls_server: String, insecure: bool, tls_fp: bool,
        fragment: Option<FragmentConfig>, builder: TransportBuilder,
        water_mark: usize,
    ) -> Arc<Self> {
        Arc::new(Self {
            ready: tokio::sync::Mutex::new(std::collections::VecDeque::new()),
            building: AtomicUsize::new(0),
            addr,
            tls_server,
            insecure,
            tls_fp,
            fragment,
            builder,
            water_mark,
        })
    }

    /// Take a ready connection, discarding REALITY entries the server has
    /// already reaped (older than [`REALITY_POOL_MAX_IDLE`]).
    async fn acquire(&self) -> Option<VlessStream> {
        let ttl = match self.builder {
            TransportBuilder::Reality { .. } => Some(REALITY_POOL_MAX_IDLE),
            TransportBuilder::Ws { .. } => None,
        };
        let mut ready = self.ready.lock().await;
        while let Some((stream, born)) = ready.pop_front() {
            if ttl.is_some_and(|ttl| born.elapsed() >= ttl) {
                continue;
            }
            return Some(stream);
        }
        None
    }

    /// Build a fresh transport connection (TCP + optional TLS + WS upgrade,
    /// or TCP + REALITY TLS), fully async.
    async fn build_one(&self) -> io::Result<VlessStream> {
        let tcp = connect_tcp_bypass(self.addr).await?;
        match &self.builder {
            TransportBuilder::Ws { path, headers, ech } => build_ws_async(
                tcp,
                &self.tls_server,
                self.insecure,
                self.tls_fp,
                self.fragment.as_ref(),
                ech,
                path,
                headers,
            )
            .await
            .map(VlessStream::Ws),
            TransportBuilder::Reality { params } => {
                // The session_id timestamp is derived at build time; pooled
                // connections may age, but servers only check it when an
                // explicit MaxTimeDiff is configured (§S1.1).
                connect_reality_stream(
                    tcp,
                    &self.tls_server,
                    params,
                    self.fragment.as_ref(),
                )
                .await
                .map(VlessStream::Reality)
            },
        }
    }

    /// Push a pre-built WS connection back into the pool.
    async fn replenish(&self) {
        match self.build_one().await {
            Ok(ws) => {
                let mut ready = self.ready.lock().await;
                if ready.len() < self.water_mark {
                    ready.push_back((ws, std::time::Instant::now()));
                }
            },
            Err(e) => {
                log::warn!("vless pool: build failed: {e}");
            },
        }
    }

    fn spawn_build(self: &Arc<Self>) {
        let current = self.building.load(Ordering::Relaxed);
        if current >= self.water_mark {
            return;
        }
        if self
            .building
            .compare_exchange(
                current,
                current + 1,
                Ordering::Relaxed,
                Ordering::Relaxed,
            )
            .is_err()
        {
            return;
        }

        let this = self.clone();
        tokio::spawn(async move {
            this.replenish().await;
            this.building.fetch_sub(1, Ordering::Relaxed);
        });
    }

    /// Fast bounded replenisher — keeps ready + building near watermark.
    fn spawn_replenish(self: &Arc<Self>) {
        let this = self.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_millis(250)).await;
                let ready = this.ready.lock().await.len();
                let building = this.building.load(Ordering::Relaxed);
                for _ in (ready + building)..this.water_mark {
                    this.spawn_build();
                }
            }
        });
    }
}

// ---------------------------------------------------------------------------
// VLESS Outbound Client
pub struct VlessOutboundClient {
    pool: Arc<VlessPool>,
    uuid: [u8; 16],
    /// VLESS flow control, sent only on TCP requests (§S2.8: servers reject
    /// UDP + flow).
    flow: Option<String>,
}

impl VlessOutboundClient {
    pub async fn from_config(
        configs: Vec<&OutboundConfig>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let cfg = configs
            .into_iter()
            .next()
            .ok_or("vless: no config provided")?;
        let server =
            cfg.server.as_deref().ok_or("vless: missing server field")?;

        validate_vless_config(cfg)
            .map_err(|e| format!("vless: {e}"))?;

        let tls_server = resolve_sni(cfg).map_err(|e| format!("vless: {e}"))?;
        let addr = crate::outbound::common::resolve_addr(server)
            .map_err(|e| format!("vless: {e}"))?;
        let uuid_str = cfg
            .password
            .as_deref()
            .ok_or("vless: missing password (uuid)")?;
        let uuid = parse_uuid(uuid_str)?;
        let insecure = cfg.insecure;
        let tls_fp = cfg.fp;
        let flow = cfg.flow.clone();

        let builder = if let Some(reality) = &cfg.reality {
            // REALITY transport: raw TLS byte stream, no WS framing.
            let params =
                reality.parse().map_err(|e| format!("vless: {e}"))?;
            TransportBuilder::Reality { params }
        } else {
            let transport = cfg
                .transport
                .as_ref()
                .ok_or("vless: missing [transport] config")?;
            if transport.type_ != "ws" {
                return Err(format!(
                    "vless: unsupported transport type '{}'",
                    transport.type_
                )
                .into());
            }
            let ws = transport
                .ws
                .as_ref()
                .ok_or("vless: missing [transport.ws] config")?;
            let transport_path = ws.path.clone().unwrap_or_else(|| "/".to_string());
            let mut transport_headers = ws.headers.clone().unwrap_or_default();
            transport_headers
                .entry("Host".to_string())
                .or_insert_with(|| tls_server.clone());
            TransportBuilder::Ws {
                path: transport_path,
                headers: transport_headers,
                ech: crate::ech::EchOffer::for_outbound(
                    cfg.ech,
                    cfg.ech_config.as_deref(),
                ),
            }
        };
        let fragment = if cfg.tls_fragment {
            Some(cfg.tls_fragment_config.clone().unwrap_or_default())
        } else {
            None
        };

        // Pool size from [outbounds.xmux].pool_size (default: 30).
        let water_mark = cfg
            .xmux
            .as_ref()
            .and_then(|x| x.pool_size)
            .unwrap_or(DEFAULT_POOL_WATER_MARK)
            .max(1);

        let pool = VlessPool::new(
            addr,
            tls_server.clone(),
            insecure,
            tls_fp,
            fragment,
            builder,
            water_mark,
        );
        pool.spawn_replenish();

        Ok(Self { pool, uuid, flow })
    }
}

#[async_trait]
impl OutboundClient for VlessOutboundClient {
    async fn dial(
        &self, dest: &Destination,
    ) -> Result<Box<dyn StreamRelay>, Box<dyn std::error::Error>> {
        let stream = if let Some(stream) = self.pool.acquire().await {
            self.pool.spawn_build();
            stream
        } else {
            self.pool.build_one().await?
        };
        let state =
            Arc::new(tokio::sync::Mutex::new(DeferredTcpState::Pending {
                stream: Some(stream),
                uuid: self.uuid,
                dest: dest.clone(),
                flow: self.flow.clone(),
            }));
        Ok(Box::new(VlessDeferredStreamRelay {
            state,
            pending: Vec::new(),
        }))
    }

    async fn dial_udp(
        &self, initial_dest: &Destination,
    ) -> Result<Box<dyn PacketRelay>, Box<dyn std::error::Error>> {
        // Server only supports DNS (port 53) over UDP. Non-53 UDP would be
        // rejected by the server anyway — fail fast on the client side.
        if initial_dest.port != 53 {
            log::debug!(
                "vless: rejecting udp/{} (only port 53 supported)",
                initial_dest.port,
            );
            return Err(crate::outbound::common::ERR_UDP_NOT_SUPPORTED.into());
        }

        let stream = if let Some(stream) = self.pool.acquire().await {
            self.pool.spawn_build();
            stream
        } else {
            self.pool.build_one().await?
        };
        let state =
            Arc::new(tokio::sync::Mutex::new(DeferredUdpState::Pending {
                stream: Some(stream),
                uuid: self.uuid,
                dest: initial_dest.clone(),
                flow: self.flow.clone(),
            }));
        Ok(Box::new(VlessDeferredPacketRelay { state }))
    }
}

// ---------------------------------------------------------------------------
// Standalone helpers (no self)
// ---------------------------------------------------------------------------

fn split_vless_response(resp: Vec<u8>) -> io::Result<Vec<u8>> {
    log::debug!(
        "vless response frame len={} head={:02x?}",
        resp.len(),
        &resp[..resp.len().min(16)],
    );
    if resp.len() < 2 {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "short vless response",
        ));
    }
    if resp[1] != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("vless response status {}", resp[1]),
        ));
    }
    let data = resp[2..].to_vec();
    log::debug!(
        "vless response payload len={} head={:02x?}",
        data.len(),
        &data[..data.len().min(16)],
    );
    Ok(data)
}

/// Spawn an async relay for an established VLESS connection.
///
/// Performs the VLESS handshake (header + bundled first payload), then splits
/// the transport into reader/writer halves and runs async read/write loops —
/// fully async, no `spawn_blocking`, so a stuck connection can't wedge the
/// tokio blocking pool (and thus Ctrl+C shutdown).
///
/// `flow` is only sent on TCP requests (§S2.8); `VlessCommand::Udp` keeps it
/// empty so servers that accept UDP without flow don't reject the request.
fn spawn_vless_relay(
    stream: VlessStream, uuid: [u8; 16], dest: Destination,
    command: VlessCommand, flow: Option<String>, first_payload: Vec<u8>,
    data_tx: mpsc::UnboundedSender<Vec<u8>>,
    mut outbound_rx: mpsc::UnboundedReceiver<Vec<u8>>,
) {
    tokio::spawn(async move {
        // 1. VLESS handshake: send header + first payload, read response.
        let flow_for_request = match command {
            VlessCommand::Tcp => flow.as_deref(),
            VlessCommand::Udp => None,
        };
        // Vision data plane (M2): flow=xtls-rprx-vision on a TCP request
        // switches the relay to the Vision state machines (§S2). UDP keeps
        // flow empty (§S2.8) → never Vision.
        let vision = matches!(command, VlessCommand::Tcp)
            && flow_for_request == Some("xtls-rprx-vision");
        let header =
            encode_request_bytes(&uuid, flow_for_request, command, &dest);
        let mut req = header.clone();
        req.extend_from_slice(&first_payload);

        let (reader, writer, initial) = match stream {
            VlessStream::Ws(ws) => {
                let mut ws = ws;
                if let Err(e) = ws.send(&req).await {
                    log::error!("vless relay handshake send: {e}");
                    return;
                }
                let resp = match ws.recv().await {
                    Ok(r) => r,
                    Err(e) => {
                        log::error!("vless relay handshake recv: {e}");
                        return;
                    },
                };
                let initial = match split_vless_response(resp) {
                    Ok(d) => d,
                    Err(e) => {
                        log::error!("vless relay handshake decode: {e}");
                        return;
                    },
                };
                let (reader, writer) = ws.into_split();
                (VlessReader::Ws(reader), VlessWriter::Ws(writer), initial)
            },
            VlessStream::Reality(tls) => {
                let mut tls = tls;
                if !vision {
                    if let Err(e) = tls.write_all(&req).await {
                        log::error!("vless relay handshake send: {e}");
                        return;
                    }
                    // Byte-stream response header: version(1) + status(1).
                    // The remainder is the payload continuation of the same
                    // stream.
                    let mut head = [0u8; 2];
                    if let Err(e) = tls.read_exact(&mut head).await {
                        log::error!("vless relay handshake recv: {e}");
                        return;
                    }
                    if head[1] != 0 {
                        log::error!(
                            "vless relay handshake: response status {}",
                            head[1]
                        );
                        return;
                    }
                    let (reader, writer) = tokio::io::split(tls);
                    (VlessReader::Reality(reader), VlessWriter::Reality(writer), Vec::new())
                } else {
                    // ---- Vision handshake (§S2.1/§S2.2) ----
                    // The VLESS header goes out raw: Xray writes it through
                    // the buffered writer *below* the VisionWriter
                    // (outbound.go:311-318) and flushes header + first
                    // frame together (:355-358). Vision framing starts at
                    // the first payload.
                    //
                    // Duplicate the raw socket up front for the Direct-
                    // phase handoff (§S2.6). Boring's switch-point buffers
                    // are provably empty — see the
                    // `obfuscation::vision` module docs for the full
                    // drainage argument.
                    let raw = match dup_reactor_stream(tls.get_ref().get_ref())
                    {
                        Ok(s) => s,
                        Err(e) => {
                            log::error!(
                                "vless vision: cannot duplicate raw socket: {e}"
                            );
                            return;
                        },
                    };
                    let raw_read = match dup_reactor_stream(&raw) {
                        Ok(s) => s,
                        Err(e) => {
                            log::error!(
                                "vless vision: cannot duplicate raw socket: {e}"
                            );
                            return;
                        },
                    };
                    let filter =
                        Arc::new(Mutex::new(VisionFilterState::new()));
                    let mut vision_writer =
                        VisionWriter::new(uuid, filter.clone());

                    let mut first_write = header;
                    if first_payload.is_empty() {
                        // outbound.go:343-348 — no first packet within
                        // 500 ms: flush header + pure long-padding frame
                        // to camouflage the header's length signature.
                        match tokio::time::timeout(
                            Duration::from_millis(500),
                            outbound_rx.recv(),
                        )
                        .await
                        {
                            Ok(Some(chunk)) => first_write.extend_from_slice(
                                &vision_writer.write_chunk(&chunk),
                            ),
                            Ok(None) => {
                                log::debug!(
                                    "vless vision: app closed before first packet"
                                );
                                return;
                            },
                            Err(_) => {
                                first_write.extend_from_slice(
                                    &vision_writer.write_pad_only(),
                                );
                            },
                        }
                    } else {
                        first_write.extend_from_slice(
                            &vision_writer.write_chunk(&first_payload),
                        );
                    }
                    if let Err(e) = tls.write_all(&first_write).await {
                        log::error!("vless relay handshake send: {e}");
                        return;
                    }
                    // Response header: raw 2 bytes — the server writes them
                    // below its own VisionWriter (inbound.go:597-601,
                    // SetFlushNext); Vision frames follow.
                    let mut head = [0u8; 2];
                    if let Err(e) = tls.read_exact(&mut head).await {
                        log::error!("vless relay handshake recv: {e}");
                        return;
                    }
                    if head[1] != 0 {
                        log::error!(
                            "vless relay handshake: response status {}",
                            head[1]
                        );
                        return;
                    }
                    // The handshake writes may already have emitted the
                    // Direct frame (pathological first payload); consume
                    // the flag so the write task starts in the right phase.
                    let direct = vision_writer.take_direct_switch();
                    let (reader, writer) = tokio::io::split(tls);
                    (
                        VlessReader::VisionReality(VisionRelayReader {
                            ssl: reader,
                            vision: VisionReader::new(uuid, filter),
                            raw: raw_read,
                            direct: false,
                        }),
                        VlessWriter::VisionReality(VisionRelayWriter {
                            ssl: writer,
                            vision: vision_writer,
                            raw,
                            direct,
                        }),
                        Vec::new(),
                    )
                }
            },
        };
        log::debug!("vless relay handshake complete ({dest})");

        if !initial.is_empty() {
            let _ = data_tx.send(initial);
        }

        // 2. Split into independent reader/writer tasks (concurrent I/O).
        let (pong_tx, pong_rx) = mpsc::channel::<Vec<u8>>(8);
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();

        let read_task = {
            let data_tx = data_tx.clone();
            let pong_tx = pong_tx.clone();
            tokio::spawn(async move {
                match reader {
                    VlessReader::Ws(mut reader) => loop {
                        match reader.recv().await {
                            Ok(WsFrame::Binary(d)) => {
                                if data_tx.send(d).is_err() {
                                    break;
                                }
                            },
                            Ok(WsFrame::Ping(p)) => {
                                let _ = pong_tx.send(p).await;
                            },
                            Err(e) => {
                                log::debug!("vless relay recv error: {e}");
                                break;
                            },
                        }
                    },
                    VlessReader::Reality(mut reader) => loop {
                        let mut buf = vec![0u8; 16 * 1024];
                        match reader.read(&mut buf).await {
                            Ok(0) => break,
                            Ok(n) => {
                                if data_tx.send(buf[..n].to_vec()).is_err() {
                                    break;
                                }
                            },
                            Err(e) => {
                                log::debug!("vless relay recv error: {e}");
                                break;
                            },
                        }
                    },
                    VlessReader::VisionReality(mut vr) => loop {
                        let mut buf = vec![0u8; 16 * 1024];
                        let n = if vr.direct {
                            // Direct phase: pure raw-socket splice (§S2.6);
                            // the SSL stream is abandoned.
                            match vr.raw.read(&mut buf).await {
                                Ok(n) => n,
                                Err(e) => {
                                    log::debug!(
                                        "vless vision direct recv error: {e}"
                                    );
                                    break;
                                },
                            }
                        } else {
                            match vr.ssl.read(&mut buf).await {
                                Ok(n) => n,
                                Err(e) => {
                                    log::debug!("vless relay recv error: {e}");
                                    break;
                                },
                            }
                        };
                        if n == 0 {
                            break;
                        }
                        let content = if vr.direct {
                            buf[..n].to_vec()
                        } else {
                            let content = vr.vision.read_chunk(&buf[..n]);
                            if vr.vision.take_direct_switch() {
                                vr.direct = true;
                                log::debug!(
                                    "vless vision: downlink switched to direct raw copy"
                                );
                            }
                            content
                        };
                        // Pure-padding frames decode to empty content —
                        // forwarding an empty Vec would read as EOF.
                        if !content.is_empty()
                            && data_tx.send(content).is_err()
                        {
                            break;
                        }
                    },
                }
                let _ = shutdown_tx.send(());
            })
        };

        let write_task = tokio::spawn(async move {
            let mut writer = writer;
            let mut pong_rx = pong_rx;
            let mut outbound_rx = outbound_rx;
            let mut shutdown_rx = shutdown_rx;
            loop {
                tokio::select! {
                    biased;
                    _ = &mut shutdown_rx => break,
                    pong = pong_rx.recv() => {
                        match pong {
                            Some(p) => {
                                let ok = match &mut writer {
                                    VlessWriter::Ws(w) => w.send_pong(&p).await.is_ok(),
                                    // Raw TLS streams have no control frames.
                                    VlessWriter::Reality(_) => true,
                                    VlessWriter::VisionReality(_) => true,
                                };
                                if !ok {
                                    break;
                                }
                            }
                            None => break,
                        }
                    }
                    data = outbound_rx.recv() => {
                        match data {
                            Some(d) => {
                                let ok = match &mut writer {
                                    VlessWriter::Ws(w) => w.send(&d).await.is_ok(),
                                    VlessWriter::Reality(w) => w.write_all(&d).await.is_ok(),
                                    VlessWriter::VisionReality(w) => {
                                        // Frame the chunk (identity once
                                        // padding ended; still runs the
                                        // filter quota, proxy.go:352-354).
                                        let framed =
                                            w.vision.write_chunk(&d);
                                        if w.direct {
                                            w.raw.write_all(&framed)
                                                .await
                                                .is_ok()
                                        } else {
                                            // The frame just produced may
                                            // be the Direct frame itself —
                                            // it still goes through the
                                            // outer TLS stream (Xray swaps
                                            // the writer at the start of
                                            // the *next* call, :343-347).
                                            if w.ssl.write_all(&framed)
                                                .await
                                                .is_ok()
                                            {
                                                if w.vision
                                                    .take_direct_switch()
                                                {
                                                    w.direct = true;
                                                    log::debug!(
                                                        "vless vision: uplink switched to direct raw copy"
                                                    );
                                                }
                                                true
                                            } else {
                                                false
                                            }
                                        }
                                    }
                                };
                                if !ok {
                                    break;
                                }
                            }
                            None => break,
                        }
                    }
                }
            }
            match &mut writer {
                VlessWriter::Ws(w) => { let _ = w.close().await; },
                VlessWriter::Reality(w) => { let _ = w.shutdown().await; },
                VlessWriter::VisionReality(w) => {
                    // After the Direct switch the SSL stream is abandoned:
                    // a close_notify would inject a TLS record into the raw
                    // byte stream the peer splices on.
                    if w.direct {
                        let _ = w.raw.shutdown().await;
                    } else {
                        let _ = w.ssl.shutdown().await;
                    }
                },
            }
        });

        let _ = tokio::join!(read_task, write_task);
    });
}

/// Read half of a [`VlessStream`] after splitting.
enum VlessReader {
    Ws(WsStreamAsyncReader),
    Reality(ReadHalf<AsyncTlsStream>),
    /// REALITY + flow=xtls-rprx-vision: Vision padding phase with the
    /// Direct-phase raw-socket splice (§S2.6).
    VisionReality(VisionRelayReader),
}

/// Write half of a [`VlessStream`] after splitting.
enum VlessWriter {
    Ws(WsStreamAsyncWriter),
    Reality(WriteHalf<AsyncTlsStream>),
    /// REALITY + flow=xtls-rprx-vision (see [`VlessReader::VisionReality`]).
    VisionReality(VisionRelayWriter),
}

/// Read half of the Vision REALITY relay: SSL stream during the padding
/// phase, pre-cloned raw `TcpStream` after the Direct handoff.
struct VisionRelayReader {
    ssl: ReadHalf<AsyncTlsStream>,
    vision: VisionReader,
    raw: tokio::net::TcpStream,
    direct: bool,
}

/// Write half of the Vision REALITY relay.
struct VisionRelayWriter {
    ssl: WriteHalf<AsyncTlsStream>,
    vision: VisionWriter,
    raw: tokio::net::TcpStream,
    direct: bool,
}

/// Duplicate a tokio `TcpStream` (dup the fd and register the copy with the
/// current reactor). tokio ≥1.49 removed `TcpStream::try_clone`, so this
/// goes through the std fd/socket traits. The dup shares the open file
/// description (and its O_NONBLOCK flag) with the original; only one of the
/// two handles is ever polled at a time (the SSL halves are abandoned at the
/// Direct switch), so the double reactor registration is inert.
fn dup_reactor_stream(tcp: &tokio::net::TcpStream) -> io::Result<tokio::net::TcpStream> {
    #[cfg(unix)]
    {
        use std::os::fd::AsFd;
        let owned = tcp.as_fd().try_clone_to_owned()?;
        tokio::net::TcpStream::from_std(std::net::TcpStream::from(owned))
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::AsSocket;
        let owned = tcp.as_socket().try_clone_to_owned()?;
        tokio::net::TcpStream::from_std(std::net::TcpStream::from(owned))
    }
}

// ---------------------------------------------------------------------------
// Async WS stream — for mless transport (fully async, no spawn_blocking)
// ---------------------------------------------------------------------------

/// Async WebSocket stream supporting both plain TCP and TLS.
///
/// Uses `WsConnAsync` which implements `AsyncRead + AsyncWrite` natively,
/// eliminating the need for `spawn_blocking` and background reader threads.
pub(crate) enum WsStreamAsync {
    Plain(WsConnAsync<tokio::net::TcpStream>),
    Tls(WsConnAsync<crate::outbound::common::AsyncTlsStream>),
}

/// Read half of `WsStreamAsync` after splitting.
pub(crate) enum WsStreamAsyncReader {
    Plain(WsConnAsyncReader<ReadHalf<tokio::net::TcpStream>>),
    Tls(WsConnAsyncReader<ReadHalf<crate::outbound::common::AsyncTlsStream>>),
}

impl WsStreamAsyncReader {
    pub(crate) async fn recv(&mut self) -> io::Result<WsFrame> {
        match self {
            WsStreamAsyncReader::Plain(r) => r.recv().await,
            WsStreamAsyncReader::Tls(r) => r.recv().await,
        }
    }
}

/// Write half of `WsStreamAsync` after splitting.
pub(crate) enum WsStreamAsyncWriter {
    Plain(WsConnAsyncWriter<WriteHalf<tokio::net::TcpStream>>),
    Tls(WsConnAsyncWriter<WriteHalf<crate::outbound::common::AsyncTlsStream>>),
}

impl WsStreamAsyncWriter {
    pub(crate) async fn send(&mut self, data: &[u8]) -> io::Result<()> {
        match self {
            WsStreamAsyncWriter::Plain(w) => w.send(data).await,
            WsStreamAsyncWriter::Tls(w) => w.send(data).await,
        }
    }

    pub(crate) async fn close(&mut self) -> io::Result<()> {
        match self {
            WsStreamAsyncWriter::Plain(w) => w.close().await,
            WsStreamAsyncWriter::Tls(w) => w.close().await,
        }
    }

    pub(crate) async fn send_pong(&mut self, data: &[u8]) -> io::Result<()> {
        match self {
            WsStreamAsyncWriter::Plain(w) => w.send_pong(data).await,
            WsStreamAsyncWriter::Tls(w) => w.send_pong(data).await,
        }
    }
}

#[allow(dead_code)]
impl WsStreamAsync {
    pub(crate) async fn send(&mut self, data: &[u8]) -> io::Result<()> {
        match self {
            WsStreamAsync::Plain(c) => c.send(data).await,
            WsStreamAsync::Tls(c) => c.send(data).await,
        }
    }

    pub(crate) async fn recv(&mut self) -> io::Result<Vec<u8>> {
        match self {
            WsStreamAsync::Plain(c) => c.recv().await,
            WsStreamAsync::Tls(c) => c.recv().await,
        }
    }

    pub(crate) async fn close(&mut self) -> io::Result<()> {
        match self {
            WsStreamAsync::Plain(c) => c.close().await,
            WsStreamAsync::Tls(c) => c.close().await,
        }
    }

    /// Split into a reader and writer half so they can run in separate
    /// tokio tasks. This enables true concurrent read/write on the
    /// underlying TLS/TCP stream.
    pub(crate) fn into_split(self) -> (WsStreamAsyncReader, WsStreamAsyncWriter) {
        match self {
            WsStreamAsync::Plain(c) => {
                let (r, w) = tokio::io::split(c.inner);
                let reader = WsConnAsyncReader {
                    inner: r,
                    recv_buf: c.recv_buf,
                };
                let writer = WsConnAsyncWriter { inner: w };
                (
                    WsStreamAsyncReader::Plain(reader),
                    WsStreamAsyncWriter::Plain(writer),
                )
            },
            WsStreamAsync::Tls(c) => {
                let (r, w) = tokio::io::split(c.inner);
                let reader = WsConnAsyncReader {
                    inner: r,
                    recv_buf: c.recv_buf,
                };
                let writer = WsConnAsyncWriter { inner: w };
                (
                    WsStreamAsyncReader::Tls(reader),
                    WsStreamAsyncWriter::Tls(writer),
                )
            },
        }
    }
}

/// Build an async WebSocket connection over TCP (optional TLS).
///
/// Uses `tokio_boring` for async TLS and `WsConnAsync` for async WebSocket
/// framing. The entire handshake is fully async — no `spawn_blocking`.
pub(crate) async fn build_ws_async(
    tcp: tokio::net::TcpStream, tls_server: &str, insecure: bool, tls_fp: bool,
    fragment: Option<&FragmentConfig>, ech: &crate::ech::EchOffer<'_>,
    path: &str, headers: &HashMap<String, String>,
) -> io::Result<WsStreamAsync> {
    let host = tls_server;
    let hdrs: Vec<(&str, &str)> = headers
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    if tls_server.is_empty() {
        // Plain WS — no TLS
        let ws = WsConnAsync::upgrade(tcp, path, host, &hdrs).await?;
        return Ok(WsStreamAsync::Plain(ws));
    }
    // TLS fragment is now supported via AsyncFragmentStream in create_tls_stream_async.
    let ssl_stream = crate::outbound::common::create_tls_stream_async(
        tcp, host, tls_fp, insecure, fragment, ech,
    )
    .await?;
    let ws = WsConnAsync::upgrade(ssl_stream, path, host, &hdrs).await?;
    Ok(WsStreamAsync::Tls(ws))
}

// ---------------------------------------------------------------------------
// Stream / Packet relay
// ---------------------------------------------------------------------------

pub struct VlessStreamRelay {
    pub(super) data_rx: mpsc::UnboundedReceiver<Vec<u8>>,
    pub(super) outbound_tx: mpsc::UnboundedSender<Vec<u8>>,
}

#[async_trait]
impl StreamRelay for VlessStreamRelay {
    async fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self.data_rx.recv().await {
            Some(data) => {
                let n = data.len().min(buf.len());
                buf[..n].copy_from_slice(&data[..n]);
                Ok(n)
            },
            None => Ok(0),
        }
    }

    async fn write(&mut self, buf: &[u8]) -> io::Result<()> {
        self.outbound_tx.send(buf.to_vec()).map_err(|_| {
            io::Error::new(io::ErrorKind::BrokenPipe, "vless stream closed")
        })
    }

    async fn shutdown(&mut self) -> io::Result<()> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Deferred TCP StreamRelay — bundles first payload with VLESS header
// ---------------------------------------------------------------------------

enum DeferredTcpState {
    Pending {
        stream: Option<VlessStream>,
        uuid: [u8; 16],
        dest: Destination,
        flow: Option<String>,
    },
    Active {
        data_rx: mpsc::UnboundedReceiver<Vec<u8>>,
        outbound_tx: mpsc::UnboundedSender<Vec<u8>>,
    },
}

pub struct VlessDeferredStreamRelay {
    state: Arc<tokio::sync::Mutex<DeferredTcpState>>,
    pending: Vec<u8>,
}

#[async_trait]
impl StreamRelay for VlessDeferredStreamRelay {
    async fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if !self.pending.is_empty() {
            let n = self.pending.len().min(buf.len());
            buf[..n].copy_from_slice(&self.pending[..n]);
            self.pending.drain(..n);
            return Ok(n);
        }

        loop {
            let mut guard = self.state.lock().await;
            match &mut *guard {
                DeferredTcpState::Pending { .. } => {
                    drop(guard);
                    tokio::time::sleep(Duration::from_millis(1)).await;
                },
                DeferredTcpState::Active { data_rx, .. } => {
                    match data_rx.try_recv() {
                        Ok(data) => {
                            let n = data.len().min(buf.len());
                            buf[..n].copy_from_slice(&data[..n]);
                            if n < data.len() {
                                self.pending.extend_from_slice(&data[n..]);
                            }
                            return Ok(n);
                        },
                        Err(TryRecvError::Empty) => {
                            drop(guard);
                            tokio::time::sleep(Duration::from_millis(1)).await;
                        },
                        Err(TryRecvError::Disconnected) => return Ok(0),
                    }
                },
            }
        }
    }

    async fn write(&mut self, buf: &[u8]) -> io::Result<()> {
        let mut guard = self.state.lock().await;
        if let DeferredTcpState::Pending { stream, uuid, dest, flow } =
            &mut *guard
        {
            let stream = stream.take().expect("stream already taken");
            let uuid = *uuid;
            let dest = dest.clone();
            let flow = flow.clone();
            let first = buf.to_vec();
            let (data_tx, data_rx) = mpsc::unbounded_channel();
            let (outbound_tx, outbound_rx) = mpsc::unbounded_channel();
            spawn_vless_relay(
                stream,
                uuid,
                dest,
                VlessCommand::Tcp,
                flow,
                first,
                data_tx,
                outbound_rx,
            );
            *guard = DeferredTcpState::Active {
                data_rx,
                outbound_tx,
            };
            return Ok(());
        }
        if let DeferredTcpState::Active { outbound_tx, .. } = &*guard {
            outbound_tx.send(buf.to_vec()).map_err(|_| {
                io::Error::new(io::ErrorKind::BrokenPipe, "vless stream closed")
            })
        } else {
            Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "vless stream not ready",
            ))
        }
    }

    async fn shutdown(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub struct VlessPacketRelay {
    pub(super) data_rx: mpsc::UnboundedReceiver<Vec<u8>>,
    pub(super) outbound_tx: mpsc::UnboundedSender<Vec<u8>>,
}

#[async_trait]
impl PacketRelay for VlessPacketRelay {
    async fn read_packet(
        &mut self, buf: &mut [u8],
    ) -> io::Result<(usize, Destination)> {
        match self.data_rx.recv().await {
            Some(data) => {
                let n = data.len().min(buf.len());
                buf[..n].copy_from_slice(&data[..n]);
                let addr = Destination::new(Address::Domain(String::new()), 0);
                Ok((n, addr))
            },
            None => Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "vless udp closed",
            )),
        }
    }

    async fn write_packet(
        &mut self, buf: &[u8], _dest: &Destination,
    ) -> io::Result<()> {
        self.outbound_tx.send(buf.to_vec()).map_err(|_| {
            io::Error::new(io::ErrorKind::BrokenPipe, "vless udp closed")
        })
    }

    async fn close(&mut self) -> io::Result<()> {
        self.outbound_tx = {
            let (tx, _) = mpsc::unbounded_channel::<Vec<u8>>();
            tx
        };
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Deferred UDP PacketRelay — bundles first packet with VLESS header
// ---------------------------------------------------------------------------

enum DeferredUdpState {
    Pending {
        stream: Option<VlessStream>,
        uuid: [u8; 16],
        dest: Destination,
        flow: Option<String>,
    },
    Active {
        data_rx: mpsc::UnboundedReceiver<Vec<u8>>,
        outbound_tx: mpsc::UnboundedSender<Vec<u8>>,
    },
}

pub struct VlessDeferredPacketRelay {
    state: Arc<tokio::sync::Mutex<DeferredUdpState>>,
}

#[async_trait]
impl PacketRelay for VlessDeferredPacketRelay {
    async fn read_packet(
        &mut self, buf: &mut [u8],
    ) -> io::Result<(usize, Destination)> {
        let mut guard = self.state.lock().await;
        match &mut *guard {
            DeferredUdpState::Pending { .. } => Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "must write first before read",
            )),
            DeferredUdpState::Active { data_rx, .. } => {
                // tokio::sync::Mutex is safe to hold across .await.
                match data_rx.recv().await {
                    Some(data) => {
                        let n = data.len().min(buf.len());
                        buf[..n].copy_from_slice(&data[..n]);
                        Ok((
                            n,
                            Destination::new(Address::Domain(String::new()), 0),
                        ))
                    },
                    None => Err(io::Error::new(
                        io::ErrorKind::ConnectionAborted,
                        "vless udp closed",
                    )),
                }
            },
        }
    }

    async fn write_packet(
        &mut self, buf: &[u8], _dest: &Destination,
    ) -> io::Result<()> {
        let mut guard = self.state.lock().await;
        // On first write: do VLESS handshake with payload bundled.
        if let DeferredUdpState::Pending { stream, uuid, dest, flow } =
            &mut *guard
        {
            let stream = stream.take().expect("stream already taken");
            let uuid = *uuid;
            let dest = dest.clone();
            let flow = flow.clone();
            let first = buf.to_vec();
            let (data_tx, data_rx) = mpsc::unbounded_channel();
            let (outbound_tx, outbound_rx) = mpsc::unbounded_channel();
            spawn_vless_relay(
                stream,
                uuid,
                dest,
                VlessCommand::Udp,
                flow,
                first,
                data_tx,
                outbound_rx,
            );
            *guard = DeferredUdpState::Active {
                data_rx,
                outbound_tx,
            };
            return Ok(());
        }
        // Send subsequent packets via the active relay.
        if let DeferredUdpState::Active { outbound_tx, .. } = &*guard {
            outbound_tx.send(buf.to_vec()).map_err(|_| {
                io::Error::new(io::ErrorKind::BrokenPipe, "vless udp closed")
            })
        } else {
            Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "vless udp not ready",
            ))
        }
    }

    async fn close(&mut self) -> io::Result<()> {
        let mut guard = self.state.lock().await;
        match &mut *guard {
            DeferredUdpState::Active { outbound_tx, .. } => {
                *outbound_tx = {
                    let (tx, _) = mpsc::unbounded_channel::<Vec<u8>>();
                    tx
                };
            },
            DeferredUdpState::Pending { .. } => {},
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::reality::RealityConfig;

    #[test]
    fn test_parse_uuid() {
        let uuid_str = "b831381d-6324-4d53-ad4f-8cda48b30811";
        let uuid = parse_uuid(uuid_str).unwrap();
        assert_eq!(uuid.len(), 16);
        assert_eq!(uuid[0], 0xb8);
        assert_eq!(uuid[1], 0x31);
        assert_eq!(uuid[15], 0x11);
    }
    #[test]
    fn test_parse_uuid_invalid() {
        assert!(parse_uuid("not-a-uuid").is_err());
        assert!(parse_uuid("").is_err());
        assert!(parse_uuid("zzzzzzzz-zzzz-zzzz-zzzz-zzzzzzzzzzzz").is_err());
    }

    fn cfg_with(flow: Option<&str>, reality: Option<RealityConfig>, transport: bool, insecure: bool) -> OutboundConfig {
        OutboundConfig {
            flow: flow.map(str::to_string),
            reality,
            transport: transport.then(|| crate::config::TransportConfig {
                type_: "ws".to_string(),
                ws: Some(crate::config::WsConfig { path: None, headers: None }),
                xhttp: None,
            }),
            insecure,
            ..Default::default()
        }
    }

    fn reality_cfg(pk: &str, sid: &str) -> RealityConfig {
        RealityConfig {
            public_key: pk.to_string(),
            short_id: sid.to_string(),
        }
    }

    #[test]
    fn ws_config_without_flow_or_reality_is_valid() {
        assert!(validate_vless_config(&cfg_with(None, None, true, false)).is_ok());
    }

    #[test]
    fn flow_requires_reality_section() {
        let cfg = cfg_with(Some("xtls-rprx-vision"), None, true, false);
        let err = validate_vless_config(&cfg).unwrap_err();
        assert!(err.contains("flow"), "{err}");

        // Empty flow is treated as no flow.
        assert!(validate_vless_config(&cfg_with(Some(""), None, true, false)).is_ok());
    }

    #[test]
    fn flow_with_reality_is_valid() {
        let cfg = cfg_with(
            Some("xtls-rprx-vision"),
            Some(reality_cfg(
                "Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc=",
                "01ab",
            )),
            false,
            false,
        );
        assert!(validate_vless_config(&cfg).is_ok());
    }

    #[test]
    fn reality_without_flow_is_valid() {
        // Plain REALITY without Vision (no flow field) — legal Xray server
        // combination, must be accepted.
        let cfg = cfg_with(
            None,
            Some(reality_cfg(
                "Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc=",
                "01ab",
            )),
            false,
            false,
        );
        assert!(validate_vless_config(&cfg).is_ok());

        // An explicitly empty flow string is equally treated as no flow.
        let empty_flow = cfg_with(
            Some(""),
            Some(reality_cfg(
                "Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc=",
                "01ab",
            )),
            false,
            false,
        );
        assert!(validate_vless_config(&empty_flow).is_ok());
    }

    #[test]
    fn reality_rejects_transport_section() {
        let cfg = cfg_with(
            None,
            Some(reality_cfg(
                "Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc=",
                "01ab",
            )),
            true,
            false,
        );
        let err = validate_vless_config(&cfg).unwrap_err();
        assert!(err.contains("[transport]"), "{err}");
    }

    #[test]
    fn reality_rejects_insecure() {
        let cfg = cfg_with(
            None,
            Some(reality_cfg(
                "Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc=",
                "01ab",
            )),
            false,
            true,
        );
        let err = validate_vless_config(&cfg).unwrap_err();
        assert!(err.contains("insecure"), "{err}");
    }

    #[test]
    fn reality_field_decoding_is_validated() {
        // Bad public_key length.
        let bad_pk = cfg_with(None, Some(reality_cfg("Nzc3Nzc3", "01ab")), false, false);
        assert!(bad_pk.reality.as_ref().unwrap().parse().is_err());
        // Bad short_id (10 bytes > 8).
        let bad_sid = reality_cfg(
            "Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc=",
            "0123456789abcdef00",
        );
        assert!(bad_sid.parse().is_err());
    }

    #[test]
    fn reality_toml_section_deserializes() {
        let toml = r#"
            type = "vless"
            tag = "reality-relay"
            server = "127.0.0.1:8443"
            password = "b831381d-6324-4d53-ad4f-8cda48b30811"
            flow = "xtls-rprx-vision"
            sni = "www.example.com"
            [reality]
            public_key = "Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc="
            short_id = "0123abcd"
        "#;
        let cfg: OutboundConfig = toml::from_str(&toml).unwrap();
        assert_eq!(cfg.flow.as_deref(), Some("xtls-rprx-vision"));
        let reality = cfg.reality.as_ref().unwrap();
        let params = reality.parse().unwrap();
        assert_eq!(params.public_key, [0x37; 32]);
        assert_eq!(params.short_id, [0x01, 0x23, 0xab, 0xcd, 0, 0, 0, 0]);
    }

    /// The Android JNI path hands an inline TOML string to
    /// `Config::from_string` (`android/jni.rs` → `runner::run`); a reality
    /// outbound must survive that parse identically.
    #[test]
    fn jni_inline_config_parses_reality_outbound() {
        let full = r#"
            [[inbounds]]
            type = "tun"

            [[outbounds]]
            type = "vless"
            tag = "reality-relay"
            server = "127.0.0.1:8443"
            password = "b831381d-6324-4d53-ad4f-8cda48b30811"
            flow = "xtls-rprx-vision"
            sni = "www.example.com"

            [outbounds.reality]
            public_key = "Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc="
            short_id = "0123abcd"
        "#;
        let cfg = crate::config::Config::from_string(full).unwrap();
        let ob = cfg
            .outbounds
            .iter()
            .find(|o| o.type_ == "vless")
            .expect("vless outbound present");
        assert_eq!(ob.tag.as_deref(), Some("reality-relay"));
        assert_eq!(ob.flow.as_deref(), Some("xtls-rprx-vision"));
        let params = ob.reality.as_ref().unwrap().parse().unwrap();
        assert_eq!(params.public_key, [0x37; 32]);
        assert_eq!(params.short_id, [0x01, 0x23, 0xab, 0xcd, 0, 0, 0, 0]);
        validate_vless_config(ob).unwrap();
    }

    #[test]
    fn legacy_ws_toml_section_unchanged() {
        let toml = r#"
            type = "vless"
            tag = "ws-relay"
            server = "127.0.0.1:8443"
            password = "b831381d-6324-4d53-ad4f-8cda48b30811"
            sni = "www.example.com"
            [transport]
            type = "ws"
            [transport.ws]
            path = "/ws"
        "#;
        let cfg: OutboundConfig = toml::from_str(toml).unwrap();
        assert!(cfg.flow.is_none());
        assert!(cfg.reality.is_none());
        assert!(cfg.transport.is_some());
        validate_vless_config(&cfg).unwrap();
    }

    /// Reality outbound through the UI latency path: `OutboundClient::
    /// test_latency` (the default impl used by `ui/mod.rs`'s delay handlers)
    /// must drive the REALITY dial path and report failure gracefully —
    /// here against a plain TCP listener that cannot answer a TLS handshake.
    #[tokio::test]
    async fn test_latency_drives_reality_dial_path() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            // Accept and immediately close: the REALITY handshake must fail.
            for conn in listener.incoming() {
                drop(conn);
            }
        });

        let toml = format!(
            r#"
            type = "vless"
            tag = "reality-latency"
            server = "127.0.0.1:{port}"
            password = "b831381d-6324-4d53-ad4f-8cda48b30811"
            sni = "www.example.com"
            tls_fragment = false
            [reality]
            public_key = "Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc="
            short_id = "0123abcd"
        "#
        );
        let cfg: OutboundConfig = toml::from_str(&toml).unwrap();
        validate_vless_config(&cfg).unwrap();
        let client = VlessOutboundClient::from_config(vec![&cfg])
            .await
            .expect("reality outbound must build");

        // Through the trait object — exactly what the UI delay endpoints do.
        let client: Box<dyn OutboundClient> = Box::new(client);
        let latency = client.test_latency("www.example.com", 443).await;
        assert!(
            latency.is_none(),
            "dial against a non-REALITY endpoint must fail, got {latency:?}"
        );
    }
}
