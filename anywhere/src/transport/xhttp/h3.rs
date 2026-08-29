//! H3 client: HTTP/3 over QUIC using tokio-quiche.
//!
//! Creates a QUIC connection (UDP) and sends H3 requests.
//! Falls back to H2 if QUIC fails (handled by caller via FallbackState).

use std::collections::HashMap;
use std::io;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use std::future::poll_fn;

use tokio_quiche::http3::driver::{
    ClientH3Event, ClientRequestSender, H3Event, InboundFrame,
    InboundFrameStream, NewClientRequest, OutboundFrame, OutboundFrameSender,
};
use tokio_quiche::quic::QuicConnection;

use crate::connection::pool::{PoolLifecycle, PoolLimits};
use crate::transport::{DownlinkReader, TransportSession, UplinkWriter};

use super::config::XhttpConfig;
use super::padding::XPaddingMiddleware;
use super::placement::PlacementConfig;

// ---------------------------------------------------------------------------
// H3Session
// ---------------------------------------------------------------------------

/// H3 transport session using QUIC + HTTP/3.
pub struct H3Session {
    config: Arc<XhttpConfig>,
    session_id: String,
    /// QUIC connection handle (kept alive to maintain connection).
    /// `None` for pooled sessions (the pool entry holds the connection).
    _quic_conn: Option<QuicConnection>,
    /// Request sender for sending H3 requests (cloneable).
    request_sender: ClientRequestSender,
    /// Event receiver for H3 responses.
    event_receiver: tokio::sync::mpsc::UnboundedReceiver<ClientH3Event>,
    /// Response body reader (received from IncomingHeaders during uplink).
    response_recv: Option<InboundFrameStream>,
    padding: Option<XPaddingMiddleware>,
    placement: PlacementConfig,
    next_request_id: u64,
}

impl H3Session {
    /// Connect to an H3 server and create a session.
    pub async fn connect(config: Arc<XhttpConfig>) -> io::Result<Self> {
        let addr = super::resolve_addr(&config).await?;

        let udp_socket = tokio::net::UdpSocket::bind("0.0.0.0:0")
            .await
            .map_err(|e| io::Error::new(io::ErrorKind::AddrNotAvailable, e))?;
        udp_socket
            .connect(addr)
            .await
            .map_err(|e| io::Error::new(io::ErrorKind::ConnectionRefused, e))?;

        let (quic_conn, mut h3_controller) =
            tokio_quiche::quic::connect(udp_socket, Some(&config.host))
                .await
                .map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::ConnectionRefused,
                        e.to_string(),
                    )
                })?;

        let event_receiver = h3_controller.take_event_receiver();

        let padding = config.padding.clone().map(XPaddingMiddleware::new);
        let placement = PlacementConfig {
            session_id_placement: config.session_id_placement,
            session_id_key: config.session_id_key.clone(),
            seq_placement: config.seq_placement,
            seq_key: config.seq_key.clone(),
        };
        let session_id = uuid::Uuid::new_v4().to_string();

        log::debug!("xhttp: H3 connected to {} ({})", config.host, addr);

        Ok(Self {
            config,
            session_id,
            _quic_conn: Some(quic_conn),
            request_sender: h3_controller.request_sender(),
            event_receiver,
            response_recv: None,
            padding,
            placement,
            next_request_id: 0,
        })
    }

    /// Create a session on an existing (pooled) H3 connection.
    ///
    /// `request_sender` is a clone of the pooled connection's request sender.
    /// `event_receiver` is a per-request channel provided by the
    /// [`H3EventRouter`] dispatcher. The pool entry (not this session)
    /// holds the `QuicConnection` alive.
    pub(crate) fn from_pooled(
        config: Arc<XhttpConfig>, request_sender: ClientRequestSender,
        event_receiver: tokio::sync::mpsc::UnboundedReceiver<ClientH3Event>,
        request_id: u64,
    ) -> Self {
        let padding = config.padding.clone().map(XPaddingMiddleware::new);
        let placement = PlacementConfig {
            session_id_placement: config.session_id_placement,
            session_id_key: config.session_id_key.clone(),
            seq_placement: config.seq_placement,
            seq_key: config.seq_key.clone(),
        };
        Self {
            config,
            session_id: uuid::Uuid::new_v4().to_string(),
            _quic_conn: None,
            request_sender,
            event_receiver,
            response_recv: None,
            padding,
            placement,
            next_request_id: request_id,
        }
    }

    fn build_h3_headers(
        &self, method: &str, path: &str,
    ) -> Vec<quiche::h3::Header> {
        let mut headers = vec![
            quiche::h3::Header::new(b":method", method.as_bytes()),
            quiche::h3::Header::new(b":path", path.as_bytes()),
            quiche::h3::Header::new(b":authority", self.config.host.as_bytes()),
            quiche::h3::Header::new(b":scheme", b"https"),
        ];
        for (k, v) in &self.config.headers {
            headers.push(quiche::h3::Header::new(k.as_bytes(), v.as_bytes()));
        }
        if !self.config.no_grpc_header {
            headers.push(quiche::h3::Header::new(
                b"content-type",
                b"application/grpc",
            ));
        }
        // Note: no_sse_header controls the server-side SSE response header
        // (Content-Type: text/event-stream), not a client request header.
        headers
    }
}

#[async_trait]
impl TransportSession for H3Session {
    async fn uplink(&mut self) -> io::Result<Box<dyn UplinkWriter>> {
        let (path, extra_headers) = self.placement.build_request_meta(
            &self.config.path,
            &self.session_id,
            None,
        );

        // Apply padding before building headers so Query placement can modify the URL
        let mut pad_path = path;
        let mut pad_headers = Vec::new();
        if let Some(ref pad) = self.padding {
            pad.apply_to_request_mut(&mut pad_path, &mut pad_headers);
        }

        let mut headers = self.build_h3_headers("POST", &pad_path);
        for (k, v) in &extra_headers {
            headers.push(quiche::h3::Header::new(k.as_bytes(), v.as_bytes()));
        }
        for (k, v) in pad_headers {
            headers.push(quiche::h3::Header::new(k.as_bytes(), v.as_bytes()));
        }

        let (body_tx, body_rx) =
            tokio::sync::oneshot::channel::<OutboundFrameSender>();
        let request_id = self.next_request_id;
        self.next_request_id += 1;

        let request = NewClientRequest {
            request_id,
            headers,
            body_writer: Some(body_tx),
        };

        // Send request (sync, takes &self)
        self.request_sender.send(request).map_err(|_| {
            io::Error::new(
                io::ErrorKind::ConnectionReset,
                "h3 request send failed",
            )
        })?;

        // Wait for NewOutboundRequest event + body sender
        let mut got_body_sender = None;
        while let Some(event) = self.event_receiver.recv().await {
            match event {
                ClientH3Event::NewOutboundRequest {
                    request_id: rid, ..
                } if rid == request_id => match body_rx.await {
                    Ok(s) => {
                        got_body_sender = Some(s);
                        break;
                    },
                    Err(_) => {
                        return Err(io::Error::new(
                            io::ErrorKind::ConnectionReset,
                            "h3 body sender dropped",
                        ));
                    },
                },
                ClientH3Event::Core(H3Event::IncomingHeaders(hdrs)) => {
                    // Response arrived early (before uplink returned) - save it
                    self.response_recv = Some(hdrs.recv);
                },
                _ => {},
            }
        }

        let body_sender = got_body_sender.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::ConnectionReset,
                "h3 connection closed before stream created",
            )
        })?;

        Ok(Box::new(H3UplinkWriter {
            body_sender: Some(body_sender),
        }))
    }

    async fn downlink(&mut self) -> io::Result<Box<dyn DownlinkReader>> {
        // If response already received during uplink(), use it
        if let Some(recv) = self.response_recv.take() {
            return Ok(Box::new(H3DownlinkReader {
                recv,
                read_buf: Vec::new(),
            }));
        }

        while let Some(event) = self.event_receiver.recv().await {
            if let ClientH3Event::Core(H3Event::IncomingHeaders(hdrs)) = event {
                return Ok(Box::new(H3DownlinkReader {
                    recv: hdrs.recv,
                    read_buf: Vec::new(),
                }));
            }
        }

        Err(io::Error::new(
            io::ErrorKind::ConnectionReset,
            "h3 connection closed before response",
        ))
    }

    async fn close(&mut self) -> io::Result<()> {
        self.response_recv = None;
        Ok(())
    }

    fn kind(&self) -> &'static str {
        "xhttp-h3"
    }
}

// ---------------------------------------------------------------------------
// H3UplinkWriter
// ---------------------------------------------------------------------------

pub struct H3UplinkWriter {
    body_sender: Option<OutboundFrameSender>,
}

#[async_trait]
impl UplinkWriter for H3UplinkWriter {
    async fn write(&mut self, data: &[u8]) -> io::Result<()> {
        let sender = self.body_sender.as_mut().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::BrokenPipe,
                "h3 uplink already shut down",
            )
        })?;
        poll_fn(|cx| sender.poll_reserve(cx)).await.map_err(|_| {
            io::Error::new(io::ErrorKind::ConnectionReset, "h3 reserve failed")
        })?;
        sender
            .send_item(OutboundFrame::Body(Bytes::copy_from_slice(data), false))
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::ConnectionReset,
                    "h3 body send failed",
                )
            })
    }

    async fn shutdown(&mut self) -> io::Result<()> {
        if let Some(sender) = self.body_sender.as_mut() {
            if poll_fn(|cx| sender.poll_reserve(cx)).await.is_ok() {
                let _ = sender.send_item(OutboundFrame::Body(Bytes::new(), true));
            }
        }
        self.body_sender = None;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// H3DownlinkReader
// ---------------------------------------------------------------------------

pub struct H3DownlinkReader {
    recv: InboundFrameStream,
    read_buf: Vec<u8>,
}

#[async_trait]
impl DownlinkReader for H3DownlinkReader {
    async fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if !self.read_buf.is_empty() {
            let n = std::cmp::min(self.read_buf.len(), buf.len());
            buf[..n].copy_from_slice(&self.read_buf[..n]);
            self.read_buf.drain(..n);
            return Ok(n);
        }
        match self.recv.recv().await {
            Some(InboundFrame::Body(data, _fin)) => {
                let n = std::cmp::min(data.len(), buf.len());
                buf[..n].copy_from_slice(&data[..n]);
                if data.len() > n {
                    self.read_buf.extend_from_slice(&data[n..]);
                }
                Ok(n)
            },
            None => Ok(0),
            _ => Ok(0),
        }
    }
}

// ---------------------------------------------------------------------------
// H3ConnectionManager
// ---------------------------------------------------------------------------

use crate::connection::{ConnError, ConnectionManager};

/// Event router that dispatches H3 events from a shared connection to
/// per-request subscribers.
///
/// Each pooled H3 connection has one event receiver (from
/// `take_event_receiver()`). Multiple sessions multiplex on the same
/// connection; this router reads events and forwards them to the correct
/// session by `request_id` (for `NewOutboundRequest`) or `stream_id`
/// (for `IncomingHeaders`, resolved via the stream map).
struct H3EventRouter {
    /// Per-request event senders (request_id -> sender).
    subscribers: parking_lot::Mutex<
        HashMap<u64, tokio::sync::mpsc::UnboundedSender<ClientH3Event>>,
    >,
    /// stream_id -> request_id mapping (learned from NewOutboundRequest).
    stream_map: parking_lot::Mutex<HashMap<u64, u64>>,
    /// Monotonically increasing request ID counter.
    next_request_id: std::sync::atomic::AtomicU64,
}

impl H3EventRouter {
    fn new() -> Self {
        Self {
            subscribers: parking_lot::Mutex::new(HashMap::new()),
            stream_map: parking_lot::Mutex::new(HashMap::new()),
            next_request_id: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Allocate a unique request ID.
    fn alloc_request_id(&self) -> u64 {
        self.next_request_id.fetch_add(1, Ordering::Relaxed)
    }

    /// Subscribe to events for a new request. Returns the request ID and
    /// a receiver for events routed to this request.
    fn subscribe(
        &self,
    ) -> (u64, tokio::sync::mpsc::UnboundedReceiver<ClientH3Event>) {
        let request_id = self.alloc_request_id();
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        self.subscribers.lock().insert(request_id, tx);
        (request_id, rx)
    }

    /// Unsubscribe and clean up the stream map for this request.
    #[allow(dead_code)]
    fn unsubscribe(&self, request_id: u64) {
        self.subscribers.lock().remove(&request_id);
        self.stream_map.lock().retain(|_, rid| *rid != request_id);
    }

    /// Route an event to the appropriate subscriber. Called from the
    /// background event-loop task.
    fn route(&self, event: ClientH3Event) {
        match &event {
            ClientH3Event::NewOutboundRequest {
                stream_id,
                request_id,
            } => {
                self.stream_map.lock().insert(*stream_id, *request_id);
                if let Some(tx) = self.subscribers.lock().get(request_id) {
                    let _ = tx.send(event);
                }
            },
            ClientH3Event::Core(H3Event::IncomingHeaders(hdrs)) => {
                let request_id =
                    self.stream_map.lock().get(&hdrs.stream_id).copied();
                if let Some(rid) = request_id {
                    if let Some(tx) = self.subscribers.lock().get(&rid) {
                        let _ = tx.send(event);
                    }
                }
            },
            _ => {
                // Other events (ConnectionError, ResetStream, etc.) are not
                // needed by H3Session; sessions detect connection death via
                // their body streams closing.
            },
        }
    }
}

/// One pooled H3 connection with its event router and lifecycle counters.
struct H3PoolEntry {
    /// QUIC connection handle (keeps the connection alive).
    #[allow(dead_code)]
    quic_conn: QuicConnection,
    /// Cloneable request sender for creating new H3 streams.
    request_sender: ClientRequestSender,
    /// Shared event router for dispatching events to sessions.
    router: Arc<H3EventRouter>,
    /// Protocol-agnostic lifecycle state (counters + TTL).
    lifecycle: PoolLifecycle,
}

impl H3PoolEntry {
    fn is_reusable(&self, limits: &PoolLimits) -> bool {
        self.lifecycle.is_available(limits)
    }
}

/// H3 connection manager with pooling and xmux lifecycle limits.
///
/// Maintains a pool of QUIC+H3 connections. Each `acquire_uplink()` picks a
/// reusable connection (or creates a new one), subscribes to the shared
/// event router, and returns an `H3Session` that multiplexes on the pooled
/// connection. Honors `max_connections`, `max_concurrency`,
/// `max_reuses`, `max_requests`, and `max_reusable_secs`.
pub struct H3ConnectionManager {
    config: Arc<XhttpConfig>,
    addr: std::net::SocketAddr,
    connections: parking_lot::Mutex<Vec<H3PoolEntry>>,
    shutdown: parking_lot::Mutex<bool>,
    max_connections: usize,
    limits: PoolLimits,
}

impl H3ConnectionManager {
    pub async fn from_config(
        config: Arc<XhttpConfig>, xmux: &super::config::XmuxConfig,
    ) -> io::Result<Self> {
        let addr_str = format!("{}:{}", config.host, config.port);
        let addr = tokio::net::lookup_host(&addr_str)
            .await?
            .next()
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::AddrNotAvailable,
                    "DNS resolution failed",
                )
            })?;

        let limits = PoolLimits {
            max_concurrency: xmux
                .max_concurrency
                .as_ref()
                .map(|r| r.rand_usize())
                .unwrap_or(0),
            max_reuses: xmux
                .max_reuses
                .as_ref()
                .map(|r| r.rand_usize() as u32)
                .unwrap_or(u32::MAX),
            max_requests: xmux
                .max_requests
                .as_ref()
                .map(|r| r.rand_usize() as u32)
                .unwrap_or(u32::MAX),
            ttl: xmux
                .max_reusable_secs
                .as_ref()
                .map(|r| Duration::from_secs(r.rand_u64())),
        };
        let max_connections = xmux
            .max_connections
            .as_ref()
            .map(|r| r.rand_usize())
            .unwrap_or(0);

        Ok(Self {
            config,
            addr,
            connections: parking_lot::Mutex::new(Vec::new()),
            shutdown: parking_lot::Mutex::new(false),
            max_connections,
            limits,
        })
    }

    /// Create a new QUIC + H3 connection and start the event router task.
    async fn connect_new(&self) -> io::Result<H3PoolEntry> {
        let udp_socket = tokio::net::UdpSocket::bind("0.0.0.0:0")
            .await
            .map_err(|e| io::Error::new(io::ErrorKind::AddrNotAvailable, e))?;
        udp_socket
            .connect(self.addr)
            .await
            .map_err(|e| io::Error::new(io::ErrorKind::ConnectionRefused, e))?;

        let (quic_conn, mut h3_controller) =
            tokio_quiche::quic::connect(udp_socket, Some(&self.config.host))
                .await
                .map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::ConnectionRefused,
                        e.to_string(),
                    )
                })?;

        let request_sender = h3_controller.request_sender();
        let mut event_receiver = h3_controller.take_event_receiver();
        let router = Arc::new(H3EventRouter::new());

        // Spawn the background event-loop that reads from the shared
        // event_receiver and routes events to subscribers.
        let router_clone = Arc::clone(&router);
        tokio::spawn(async move {
            while let Some(event) = event_receiver.recv().await {
                router_clone.route(event);
            }
            // Event receiver closed -> connection dead; drop all subscribers.
            router_clone.subscribers.lock().clear();
            router_clone.stream_map.lock().clear();
        });

        Ok(H3PoolEntry {
            quic_conn,
            request_sender,
            router,
            lifecycle: PoolLifecycle::new(&self.limits),
        })
    }
}

#[async_trait]
impl ConnectionManager for H3ConnectionManager {
    async fn acquire_uplink(
        &self,
    ) -> Result<Box<dyn TransportSession>, ConnError> {
        if *self.shutdown.lock() {
            return Err(ConnError::Closed);
        }

        // Phase 1: Clean up dead/expired entries and find a reusable one.
        let found = {
            let mut pool = self.connections.lock();
            pool.retain(|e| {
                !e.lifecycle.is_expired() && e.lifecycle.has_budget()
            });

            let mut found: Option<(ClientRequestSender, Arc<H3EventRouter>)> =
                None;
            for entry in pool.iter_mut() {
                if entry.is_reusable(&self.limits) {
                    entry.lifecycle.acquire_slot();
                    found = Some((
                        entry.request_sender.clone(),
                        Arc::clone(&entry.router),
                    ));
                    break;
                }
            }
            found
        };

        if let Some((request_sender, router)) = found {
            let (request_id, event_rx) = router.subscribe();
            let session = H3Session::from_pooled(
                self.config.clone(),
                request_sender,
                event_rx,
                request_id,
            );
            return Ok(Box::new(session));
        }

        // Phase 2: No reusable connection. Check if we can add a new one.
        let can_add = {
            let pool = self.connections.lock();
            self.max_connections == 0 || pool.len() < self.max_connections
        };

        if can_add {
            let entry = self
                .connect_new()
                .await
                .map_err(|e| ConnError::CreateFailed(e.to_string()))?;
            let request_sender = entry.request_sender.clone();
            let router = Arc::clone(&entry.router);
            self.connections.lock().push(entry);

            let (_request_id, event_rx) = router.subscribe();
            let session = H3Session::from_pooled(
                self.config.clone(),
                request_sender,
                event_rx,
                _request_id,
            );
            return Ok(Box::new(session));
        }

        // Phase 3: At max_connections limit - create a temporary (non-pooled)
        // connection. This avoids blocking callers.
        let session = H3Session::connect(self.config.clone())
            .await
            .map_err(|e| ConnError::CreateFailed(e.to_string()))?;
        Ok(Box::new(session))
    }

    async fn acquire_downlink(
        &self,
    ) -> Result<Box<dyn TransportSession>, ConnError> {
        self.acquire_uplink().await
    }

    async fn release(&self, _session: Box<dyn TransportSession>) {
        // Decrement running count on the pool entry that owns this session.
        // Since we can't identify which entry from the session alone, we
        // decrement the entry with the highest running count (best effort).
        let pool = self.connections.lock();
        if let Some(entry) =
            pool.iter().max_by_key(|e| e.lifecycle.running_count())
        {
            entry.lifecycle.release_slot();
        }
    }
    fn is_healthy(&self) -> bool {
        true
    }
    async fn shutdown(&self) {
        *self.shutdown.lock() = true;
        self.connections.lock().clear();
    }
}
