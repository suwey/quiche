use std::collections::HashMap;
use std::io::{self};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::time::Duration;

use crate::config::OutboundConfig;
use crate::inbound::Address;
use crate::inbound::Destination;
use crate::outbound::OutboundClient;
use crate::outbound::common::connect_tcp_bypass;
use crate::outbound::common::resolve_sni;
use crate::protocol::vless::VlessCommand;
use crate::protocol::vless::encode_request_bytes;
use crate::relay::PacketRelay;
use crate::relay::StreamRelay;
use crate::tlsfragment::FragmentConfig;
use crate::transport::ws::WsConnAsync;
use crate::transport::ws::WsConnAsyncReader;
use crate::transport::ws::WsConnAsyncWriter;
use crate::transport::ws::WsFrame;
use async_trait::async_trait;
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
// ---------------------------------------------------------------------------
// Constants — tune pool size
// ---------------------------------------------------------------------------
// Pool water mark — read from config at construction time.
// Default matches the old hardcoded value for backward compatibility.
// ---------------------------------------------------------------------------

/// Default number of pre-built WS connections the pool tries to keep ready.
const DEFAULT_POOL_WATER_MARK: usize = 30;

// ---------------------------------------------------------------------------
// VLESS Pool — a set of WS connections ready for immediate VLESS handshake
// ---------------------------------------------------------------------------

struct VlessPool {
    ready: tokio::sync::Mutex<std::collections::VecDeque<WsStreamAsync>>,
    building: AtomicUsize,
    addr: SocketAddr,
    tls_server: String,
    insecure: bool,
    tls_fp: bool,
    fragment: Option<FragmentConfig>,
    transport_path: String,
    transport_headers: HashMap<String, String>,
    /// Target pool size (water mark).
    water_mark: usize,
}

impl VlessPool {
    fn new(
        addr: SocketAddr, tls_server: String, insecure: bool, tls_fp: bool,
        fragment: Option<FragmentConfig>,
        transport_path: String, transport_headers: HashMap<String, String>,
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
            transport_path,
            transport_headers,
            water_mark,
        })
    }

    /// Take a ready WS connection. Returns `None` if the pool is empty.
    async fn acquire(&self) -> Option<WsStreamAsync> {
        self.ready.lock().await.pop_front()
    }

    /// Build a fresh WS connection (TCP + optional TLS + WS upgrade), fully async.
    async fn build_one(&self) -> io::Result<WsStreamAsync> {
        let tcp = connect_tcp_bypass(self.addr).await?;
        build_ws_async(
            tcp,
            &self.tls_server,
            self.insecure,
            self.tls_fp,
            self.fragment.as_ref(),
            &self.transport_path,
            &self.transport_headers,
        )
        .await
    }

    /// Push a pre-built WS connection back into the pool.
    async fn replenish(&self) {
        match self.build_one().await {
            Ok(ws) => {
                let mut ready = self.ready.lock().await;
                if ready.len() < self.water_mark {
                    ready.push_back(ws);
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

        let transport = cfg.transport.as_ref().ok_or("vless: missing [transport] config")?;
        if transport.type_ != "ws" {
            return Err(format!(
                "vless: unsupported transport type '{}'", transport.type_
            )
            .into());
        }
        let ws = transport.ws.as_ref().ok_or("vless: missing [transport.ws] config")?;
        let transport_path = ws.path.clone().unwrap_or_else(|| "/".to_string());
        let mut transport_headers = ws.headers.clone().unwrap_or_default();
        transport_headers
            .entry("Host".to_string())
            .or_insert_with(|| tls_server.clone());
        let fragment = if cfg.tls_fragment {
            Some(FragmentConfig::default())
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
            transport_path.clone(),
            transport_headers.clone(),
            water_mark,
        );
        pool.spawn_replenish();

        Ok(Self {
            pool,
            uuid,
        })
    }
}

#[async_trait]
impl OutboundClient for VlessOutboundClient {
    async fn dial(
        &self, dest: &Destination,
    ) -> Result<Box<dyn StreamRelay>, Box<dyn std::error::Error>> {
        let ws = if let Some(ws) = self.pool.acquire().await {
            self.pool.spawn_build();
            ws
        } else {
            self.pool.build_one().await?
        };
        let state =
            Arc::new(tokio::sync::Mutex::new(DeferredTcpState::Pending {
                ws: Some(ws),
                uuid: self.uuid,
                dest: dest.clone(),
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

        let ws = if let Some(ws) = self.pool.acquire().await {
            self.pool.spawn_build();
            ws
        } else {
            self.pool.build_one().await?
        };
        let state =
            Arc::new(tokio::sync::Mutex::new(DeferredUdpState::Pending {
                ws: Some(ws),
                uuid: self.uuid,
                dest: initial_dest.clone(),
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
/// the WS into reader/writer halves and runs async read/write loops — fully
/// async, no `spawn_blocking`, so a stuck connection can't wedge the tokio
/// blocking pool (and thus Ctrl+C shutdown).
fn spawn_vless_relay(
    ws: WsStreamAsync,
    uuid: [u8; 16],
    dest: Destination,
    command: VlessCommand,
    first_payload: Vec<u8>,
    data_tx: mpsc::UnboundedSender<Vec<u8>>,
    outbound_rx: mpsc::UnboundedReceiver<Vec<u8>>,
) {
    tokio::spawn(async move {
        let mut ws = ws;

        // 1. VLESS handshake: send header + first payload, read response.
        let mut req = encode_request_bytes(&uuid, None, command, &dest);
        req.extend_from_slice(&first_payload);
        if let Err(e) = ws.send(&req).await {
            log::error!("vless relay handshake send: {e}");
            return;
        }
        let resp = match ws.recv().await {
            Ok(r) => r,
            Err(e) => {
                log::error!("vless relay handshake recv: {e}");
                return;
            }
        };
        let initial = match split_vless_response(resp) {
            Ok(d) => d,
            Err(e) => {
                log::error!("vless relay handshake decode: {e}");
                return;
            }
        };
        if !initial.is_empty() {
            let _ = data_tx.send(initial);
        }
        log::debug!("vless relay handshake complete ({dest})");

        // 2. Split into independent reader/writer tasks (concurrent I/O).
        let (reader, writer) = ws.into_split();
        let (pong_tx, pong_rx) = mpsc::channel::<Vec<u8>>(8);
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();

        let read_task = {
            let data_tx = data_tx.clone();
            let pong_tx = pong_tx.clone();
            tokio::spawn(async move {
                let mut reader = reader;
                loop {
                    match reader.recv().await {
                        Ok(WsFrame::Binary(d)) => {
                            if data_tx.send(d).is_err() {
                                break;
                            }
                        }
                        Ok(WsFrame::Ping(p)) => {
                            let _ = pong_tx.send(p).await;
                        }
                        Err(e) => {
                            log::debug!("vless relay recv error: {e}");
                            break;
                        }
                    }
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
                                if writer.send_pong(&p).await.is_err() {
                                    break;
                                }
                            }
                            None => break,
                        }
                    }
                    data = outbound_rx.recv() => {
                        match data {
                            Some(d) => {
                                if writer.send(&d).await.is_err() {
                                    break;
                                }
                            }
                            None => break,
                        }
                    }
                }
            }
            let _ = writer.close().await;
        });

        let _ = tokio::join!(read_task, write_task);
    });
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
                let reader = WsConnAsyncReader { inner: r, recv_buf: c.recv_buf };
                let writer = WsConnAsyncWriter { inner: w };
                (WsStreamAsyncReader::Plain(reader), WsStreamAsyncWriter::Plain(writer))
            }
            WsStreamAsync::Tls(c) => {
                let (r, w) = tokio::io::split(c.inner);
                let reader = WsConnAsyncReader { inner: r, recv_buf: c.recv_buf };
                let writer = WsConnAsyncWriter { inner: w };
                (WsStreamAsyncReader::Tls(reader), WsStreamAsyncWriter::Tls(writer))
            }
        }
    }
}

/// Build an async WebSocket connection over TCP (optional TLS).
///
/// Uses `tokio_boring` for async TLS and `WsConnAsync` for async WebSocket
/// framing. The entire handshake is fully async — no `spawn_blocking`.
pub(crate) async fn build_ws_async(
    tcp: tokio::net::TcpStream,
    tls_server: &str,
    insecure: bool,
    tls_fp: bool,
    fragment: Option<&FragmentConfig>,
    path: &str,
    headers: &HashMap<String, String>,
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
        tcp, host, tls_fp, insecure, fragment,
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
        ws: Option<WsStreamAsync>,
        uuid: [u8; 16],
        dest: Destination,
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
                DeferredTcpState::Active { data_rx, .. } =>
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
                    },
            }
        }
    }

    async fn write(&mut self, buf: &[u8]) -> io::Result<()> {
        let mut guard = self.state.lock().await;
        if let DeferredTcpState::Pending { ws, uuid, dest } = &mut *guard {
            let ws = ws.take().expect("ws already taken");
            let uuid = *uuid;
            let dest = dest.clone();
            let first = buf.to_vec();
            let (data_tx, data_rx) = mpsc::unbounded_channel();
            let (outbound_tx, outbound_rx) = mpsc::unbounded_channel();
            spawn_vless_relay(
                ws, uuid, dest, VlessCommand::Tcp, first, data_tx, outbound_rx,
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
        ws: Option<WsStreamAsync>,
        uuid: [u8; 16],
        dest: Destination,
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
        if let DeferredUdpState::Pending { ws, uuid, dest } = &mut *guard {
            let ws = ws.take().expect("ws already taken");
            let uuid = *uuid;
            let dest = dest.clone();
            let first = buf.to_vec();
            let (data_tx, data_rx) = mpsc::unbounded_channel();
            let (outbound_tx, outbound_rx) = mpsc::unbounded_channel();
            spawn_vless_relay(
                ws, uuid, dest, VlessCommand::Udp, first, data_tx, outbound_rx,
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
}
