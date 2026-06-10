use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::time::Duration;
use std::time::Instant;

use async_trait::async_trait;
use quiche::h3::NameValue;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tokio::sync::oneshot;
use tokio_quiche::http3::driver::ClientEventStream;
use tokio_quiche::http3::driver::ClientH3Event;
use tokio_quiche::http3::driver::ClientRequestSender;
use tokio_quiche::http3::driver::H3Event;
use tokio_quiche::http3::driver::InboundFrameStream;
use tokio_quiche::http3::driver::NewClientRequest;
use tokio_quiche::http3::driver::OutboundFrameSender;
use tokio_quiche::http3::settings::Http3Settings;
use tokio_quiche::quic::connect_with_config;
use tokio_quiche::settings::Hooks;
use tokio_quiche::settings::QuicSettings;

use crate::fingerprint::FingerprintHook;
use tokio_quiche::ClientH3Driver;
use tokio_quiche::ConnectionParams;
use tokio_quiche::socket::Socket;

use crate::config::OutboundConfig;
use crate::inbound::Destination;
use crate::outbound::OutboundClient;
use crate::outbound::common::bind_udp_bypass;
use crate::relay::H3Relay;
use crate::relay::StreamRelay;

type PendingMap = Arc<
    Mutex<
        HashMap<
            u64,
            oneshot::Sender<
                Result<(OutboundFrameSender, InboundFrameStream), String>,
            >,
        >,
    >,
>;

/// Maintains a QUIC connection to a remote proxy server, sends H3 CONNECT
/// requests, and returns [`H3Relay`] streams.
///
/// ## Architecture
/// 1. `from_config()` connects to the first QUIC outbound server and spawns a
///    background event-loop task.
/// 2. `dial()` sends an H3 CONNECT request and waits for a 200 response via a
///    oneshot channel.
/// 3. The background event loop receives H3 events and resolves pending
///    oneshots.
/// Internal mutable state for QuicOutboundClient.
struct QuicInner {
    request_sender: ClientRequestSender,
    pending: PendingMap,
}

pub struct QuicOutboundClient {
    inner: tokio::sync::Mutex<QuicInner>,
    /// Monotonically increasing request ID counter.
    next_req_id: AtomicU64,
    /// Authentication password sent in CONNECT headers.
    password: String,
    /// Server address for reconnection.
    server_addr: std::net::SocketAddr,
    /// Server hostname for reconnection.
    server_host: String,
    /// Whether to use Chrome TLS fingerprint on reconnect.
    fp: bool,
    /// Optional ECH config (base64) for reconnect.
    ech_config: Option<String>,
}

impl QuicOutboundClient {
    /// Creates a new [`QuicOutboundClient`] by connecting to the first QUIC
    /// outbound server in `configs`.
    pub async fn from_config(
        configs: Vec<&OutboundConfig>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let config = configs.first().ok_or("no quic outbound config")?;
        let server = config
            .server
            .as_ref()
            .ok_or("quic outbound missing server")?;
        let password = config.password.clone().unwrap_or_default();

        // Parse server address (supports hostname:port and ip:port).
        let server_addr: std::net::SocketAddr =
            server.parse().unwrap_or_else(|_| {
                std::net::ToSocketAddrs::to_socket_addrs(server)
                    .expect("invalid server address")
                    .next()
                    .expect("no address found")
            });
        let server_host = server.split(':').next().unwrap_or(server);

        // Bind a local UDP socket and connect to the remote server.
        let bind_addr = match server_addr {
            std::net::SocketAddr::V4(_) => "0.0.0.0:0",
            std::net::SocketAddr::V6(_) => "[::]:0",
        };
        let socket = bind_udp_bypass(bind_addr.parse().unwrap()).await?;
        socket.connect(server_addr).await?;

        // Configure QUIC settings.
        let mut quic_settings = QuicSettings::default();
        quic_settings.max_idle_timeout = Some(Duration::from_secs(30));
        quic_settings.verify_peer = false;

        // Create the H3 driver pair (driver + controller).
        let (h3_driver, mut controller) =
            ClientH3Driver::new(Http3Settings::default());

        // Convert the connected UDP socket into a tokio-quiche Socket.
        let quic_socket: Socket<_, _> = socket.try_into()?;

        // Connect and start the QUIC + H3 I/O loop in the background.
        let hooks = Hooks {
            connection_hook: FingerprintHook::into_arc_option(
                config.fp,
                config.ech_config.clone(),
            ),
        };
        let params = ConnectionParams::new_client(quic_settings, None, hooks);
        let _quic_conn = connect_with_config(
            quic_socket,
            Some(server_host),
            &params,
            h3_driver,
        )
        .await
        .map_err(|e| -> Box<dyn std::error::Error> { e })?;

        // Extract the request sender and event stream from the controller.
        let request_sender = controller.request_sender();
        let event_stream = controller.take_event_receiver();

        // Shared state for routing CONNECT responses back to dial() callers.
        let pending: PendingMap = Arc::new(Mutex::new(HashMap::new()));
        let pending_clone = Arc::clone(&pending);

        // Spawn the background H3 event loop.
        tokio::spawn(async move {
            Self::event_loop(event_stream, pending_clone).await;
        });

        Ok(Self {
            inner: tokio::sync::Mutex::new(QuicInner {
                request_sender,
                pending,
            }),
            next_req_id: AtomicU64::new(0),
            password,
            server_addr,
            server_host: server_host.to_string(),
            fp: config.fp,
            ech_config: config.ech_config.clone(),
        })
    }

    /// Background event loop that processes [`ClientH3Event`]s from the H3
    /// driver and resolves pending CONNECT oneshots.
    async fn event_loop(
        mut event_stream: ClientEventStream, pending: PendingMap,
    ) {
        let mut stream_map: HashMap<u64, u64> = HashMap::new(); // stream_id -> request_id

        while let Some(event) = event_stream.recv().await {
            match event {
                ClientH3Event::NewOutboundRequest {
                    stream_id,
                    request_id,
                } => {
                    stream_map.insert(stream_id, request_id);
                },

                ClientH3Event::Core(H3Event::IncomingHeaders(headers)) => {
                    let stream_id = headers.stream_id;
                    if let Some(req_id) = stream_map.remove(&stream_id) {
                        let status = headers
                            .headers
                            .iter()
                            .find(|h| h.name() == b":status")
                            .map(|h| {
                                String::from_utf8_lossy(h.value()).to_string()
                            });

                        let mut pending = pending.lock().await;
                        if let Some(sender) = pending.remove(&req_id) {
                            if status.as_deref() == Some("200") {
                                let _ =
                                    sender.send(Ok((headers.send, headers.recv)));
                            } else {
                                let _ = sender
                                    .send(Err(format!("rejected: {:?}", status)));
                            }
                        }
                    }
                },

                ClientH3Event::Core(H3Event::ConnectionError(e)) => {
                    fail_all_pending(&pending, format!("conn err: {e:?}")).await;
                    break;
                },

                ClientH3Event::Core(H3Event::ConnectionShutdown(e)) => {
                    fail_all_pending(&pending, format!("shutdown: {e:?}")).await;
                    break;
                },

                // Clean up stream_map entries for terminated streams.
                ClientH3Event::Core(H3Event::ResetStream { stream_id }) => {
                    stream_map.remove(&stream_id);
                },

                ClientH3Event::Core(H3Event::StreamClosed { stream_id }) => {
                    stream_map.remove(&stream_id);
                },

                _ => {},
            }
        }
    }

    /// Reconnects the QUIC connection to the remote server.
    ///
    /// Creates a fresh UDP socket, QUIC connection, H3 driver, and event-loop
    /// task, replacing the current `request_sender` and `pending` map.
    async fn reconnect(&self) -> Result<(), Box<dyn std::error::Error>> {
        let bind_addr = match self.server_addr {
            std::net::SocketAddr::V4(_) => "0.0.0.0:0",
            std::net::SocketAddr::V6(_) => "[::]:0",
        };
        let socket = bind_udp_bypass(bind_addr.parse().unwrap()).await?;
        socket.connect(self.server_addr).await?;

        let (h3_driver, mut controller) =
            ClientH3Driver::new(Http3Settings::default());
        let request_sender = controller.request_sender();
        let event_stream = controller.take_event_receiver();

        let pending: PendingMap = Arc::new(Mutex::new(HashMap::new()));
        let pending_for_spawn = Arc::clone(&pending);

        let mut quic_settings = QuicSettings::default();
        quic_settings.max_idle_timeout = Some(Duration::from_secs(30));
        quic_settings.verify_peer = false;

        let hooks = Hooks {
            connection_hook: FingerprintHook::into_arc_option(
                self.fp,
                self.ech_config.clone(),
            ),
        };
        let params = ConnectionParams::new_client(quic_settings, None, hooks);
        let quic_socket: Socket<_, _> = socket.try_into()?;
        let _quic_conn = connect_with_config(
            quic_socket,
            Some(&self.server_host),
            &params,
            h3_driver,
        )
        .await
        .map_err(|e| -> Box<dyn std::error::Error> { e })?;

        tokio::spawn(async move {
            Self::event_loop(event_stream, pending_for_spawn).await;
        });

        let mut inner = self.inner.lock().await;
        inner.request_sender = request_sender;
        inner.pending = pending;

        Ok(())
    }
}

/// Resolves all pending oneshots with the given error message.
async fn fail_all_pending(pending: &PendingMap, msg: String) {
    let mut map = pending.lock().await;
    for (_id, sender) in map.drain() {
        let _ = sender.send(Err(msg.clone()));
    }
}

#[async_trait]
impl OutboundClient for QuicOutboundClient {
    async fn dial(
        &self, dest: &Destination,
    ) -> Result<Box<dyn StreamRelay>, Box<dyn std::error::Error>> {
        let target = dest.to_string();
        // Loop to retry once after reconnection on channel failure.
        loop {
            let req_id = self.next_req_id.fetch_add(1, Ordering::SeqCst);

            let (tx, rx) = oneshot::channel();
            let (body_tx, body_rx) = oneshot::channel::<OutboundFrameSender>();

            // Brief locked section: insert into pending map and clone the
            // request sender, then drop the lock before any .await so that
            // concurrent dial() calls on the same QUIC connection are not
            // serialized.
            let request_sender = {
                let inner = self.inner.lock().await;
                inner.pending.lock().await.insert(req_id, tx);
                inner.request_sender.clone()
            }; // <-- Mutex lock dropped here

            let mut headers = vec![
                quiche::h3::Header::new(b":method", b"CONNECT"),
                quiche::h3::Header::new(b":authority", target.as_bytes()),
            ];
            if !self.password.is_empty() {
                headers.push(quiche::h3::Header::new(
                    b"anywhere-auth",
                    self.password.as_bytes(),
                ));
            }

            if request_sender
                .send(NewClientRequest {
                    request_id: req_id,
                    headers,
                    body_writer: Some(body_tx),
                })
                .is_err()
            {
                // Channel closed — the QUIC connection is dead (idle timeout,
                // server restart, etc.). Reconnect and retry once.
                log::warn!("QUIC outbound connection dead, reconnecting...");
                self.reconnect().await?;
                continue;
            }

            // Wait for the body_writer to confirm the request was dispatched.
            let _body_sender =
                body_rx.await.map_err(|_| "body_writer channel closed")?;

            // Wait for the CONNECT response (200 or error) with a 10-second
            // timeout.
            let (sender, receiver) =
                tokio::time::timeout(Duration::from_secs(10), rx)
                    .await
                    .map_err(|_| "dial timeout")?
                    .map_err(|_| "dial cancelled")?
                    .map_err(|_| "outbound connect rejected")?;

            log::info!("QUIC outbound CONNECT {target} established");

            return Ok(Box::new(H3Relay::new(sender, receiver)));
        }
    }

    async fn test_latency(&self, _host: &str, _port: u16) -> Option<u64> {
        use tokio_quiche::ConnectionParams;
        use tokio_quiche::http3::driver::ClientH3Driver;
        use tokio_quiche::http3::settings::Http3Settings;
        use tokio_quiche::quic::connect_with_config;
        use tokio_quiche::settings::Hooks;
        use tokio_quiche::settings::QuicSettings;
        use tokio_quiche::socket::Socket;

        use crate::fingerprint::FingerprintHook;

        let start = Instant::now();

        let bind_addr = match self.server_addr {
            std::net::SocketAddr::V4(_) => "0.0.0.0:0",
            std::net::SocketAddr::V6(_) => "[::]:0",
        };
        let socket = UdpSocket::bind(bind_addr).await.ok()?;
        socket.connect(self.server_addr).await.ok()?;

        let (h3_driver, _controller) =
            ClientH3Driver::new(Http3Settings::default());
        let quic_socket: Socket<_, _> = socket.try_into().ok()?;

        let mut quic_settings = QuicSettings::default();
        quic_settings.max_idle_timeout = Some(Duration::from_secs(5));
        quic_settings.verify_peer = false;

        let hooks = Hooks {
            connection_hook: FingerprintHook::into_arc_option(
                self.fp,
                self.ech_config.clone(),
            ),
        };
        let params = ConnectionParams::new_client(quic_settings, None, hooks);

        let result = tokio::time::timeout(
            Duration::from_secs(10),
            connect_with_config(
                quic_socket,
                Some(&self.server_host),
                &params,
                h3_driver,
            ),
        )
        .await;

        match result {
            Ok(Ok(_conn)) => {
                let elapsed = start.elapsed().as_millis() as u64;
                // Drop _conn to close immediately.
                Some(elapsed)
            },
            _ => None,
        }
    }
}
