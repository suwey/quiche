use async_trait::async_trait;
use bytes::Bytes;
use futures_util::sink::SinkExt;
use futures_util::stream::StreamExt;
use quiche::h3::NameValue;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio_quiche::ConnectionParams;
use tokio_quiche::ServerH3Driver;
use tokio_quiche::http3::driver::H3Event;
use tokio_quiche::http3::driver::IncomingH3Headers;
use tokio_quiche::http3::driver::OutboundFrame;
use tokio_quiche::http3::driver::ServerEventStream;
use tokio_quiche::http3::driver::ServerH3Event;
use tokio_quiche::http3::settings::Http3Settings;
use tokio_quiche::listen;
use tokio_quiche::metrics::DefaultMetrics;
use tokio_quiche::settings::CertificateKind;
use tokio_quiche::settings::Hooks;
use tokio_quiche::settings::QuicSettings;
use tokio_quiche::settings::TlsCertificatePaths;

use crate::config::InboundConfig;
use crate::inbound::Destination;
use crate::inbound::Inbound;
use crate::inbound::InboundConn;
use crate::relay::H3Relay;

/// Server-side QUIC/H3 CONNECT inbound.
///
/// Listens for QUIC connections on a UDP socket, accepts H3 CONNECT requests,
/// and yields [`InboundConn`] values (wrapping an [`H3Relay`]) via the
/// [`Inbound`] trait.
pub struct QuicInbound {
    conn_rx: mpsc::Receiver<InboundConn>,
}

impl QuicInbound {
    /// Creates a new [`QuicInbound`] from the first QUIC-type [`InboundConfig`]
    /// and the global [`UserConfig`](crate::config::UserConfig) passwords.
    ///
    /// Starts background tasks for QUIC connection acceptance and H3 event
    /// processing. Returns `None` when the config list is empty or missing
    /// required fields (`listen`, `cert`, `key`).
    pub fn from_config(
        config: &InboundConfig, passwords: Vec<String>,
    ) -> Option<Self> {
        let listen = config.listen.as_ref()?;
        let cert = config.cert.as_ref()?;
        let key = config.key.as_ref()?;

        let (conn_tx, conn_rx) = mpsc::channel(64);

        let listen_addr = listen.clone();
        let cert = cert.clone();
        let key = key.clone();

        tokio::spawn(async move {
            Self::run(listen_addr, cert, key, passwords, conn_tx).await;
        });

        Some(Self { conn_rx })
    }

    /// Background task: bind UDP socket, listen for QUIC connections, and spawn
    /// per-connection H3 event loops.
    async fn run(
        listen_addr: String, cert: String, key: String, passwords: Vec<String>,
        conn_tx: mpsc::Sender<InboundConn>,
    ) {
        let socket = match UdpSocket::bind(&listen_addr).await {
            Ok(s) => s,
            Err(e) => {
                log::error!(
                    "QuicInbound: failed to bind UDP socket on {listen_addr}: {e}"
                );
                return;
            },
        };
        log::info!("QuicInbound listening on {listen_addr}");

        let mut quic_settings = QuicSettings::default();
        quic_settings.max_idle_timeout = Some(std::time::Duration::from_secs(30));

        let mut listeners = match listen(
            [socket],
            ConnectionParams::new_server(
                quic_settings,
                TlsCertificatePaths {
                    cert: &cert,
                    private_key: &key,
                    kind: CertificateKind::X509,
                },
                Hooks::default(),
            ),
            DefaultMetrics,
        ) {
            Ok(l) => l,
            Err(e) => {
                log::error!("QuicInbound: listen failed: {e}");
                return;
            },
        };

        let accept_stream = &mut listeners[0];

        while let Some(conn_res) = accept_stream.next().await {
            match conn_res {
                Ok(conn) => {
                    let (driver, mut controller) =
                        ServerH3Driver::new(Http3Settings::default());
                    conn.start(driver);

                    let pws = passwords.clone();
                    let tx = conn_tx.clone();
                    tokio::spawn(async move {
                        Self::handle_connection(
                            controller.take_event_receiver(),
                            pws,
                            tx,
                        )
                        .await;
                    });
                },
                Err(e) => {
                    log::error!("QuicInbound: connection accept error: {e:?}");
                },
            }
        }
    }

    /// Per-connection H3 event loop. Processes incoming headers and forwards
    /// valid CONNECT requests as [`InboundConn`] values.
    async fn handle_connection(
        mut event_stream: ServerEventStream, passwords: Vec<String>,
        conn_tx: mpsc::Sender<InboundConn>,
    ) {
        loop {
            let event = match event_stream.recv().await {
                Some(e) => e,
                None => return,
            };

            match event {
                ServerH3Event::Headers {
                    incoming_headers, ..
                } => {
                    Self::handle_headers(incoming_headers, &passwords, &conn_tx)
                        .await;
                },
                ServerH3Event::Core(H3Event::ConnectionError(_)) |
                ServerH3Event::Core(H3Event::ConnectionShutdown(_)) => return,
                _ => {},
            }
        }
    }

    /// Inspect a single incoming H3 request. If it is a valid CONNECT with a
    /// matching auth token, send 200 and forward an [`InboundConn`] over the
    /// channel.
    async fn handle_headers(
        headers: IncomingH3Headers, passwords: &[String],
        conn_tx: &mpsc::Sender<InboundConn>,
    ) {
        let IncomingH3Headers {
            stream_id,
            headers: list,
            send: mut frame_sender,
            recv: frame_receiver,
            ..
        } = headers;

        let mut method = None;
        let mut authority = None;
        let mut auth_header = None;

        for h in &list {
            match h.name() {
                b":method" => {
                    method = Some(String::from_utf8_lossy(h.value()).to_string());
                },
                b":authority" => {
                    authority =
                        Some(String::from_utf8_lossy(h.value()).to_string());
                },
                b"anywhere-auth" => {
                    auth_header =
                        Some(String::from_utf8_lossy(h.value()).to_string());
                },
                _ => {},
            }
        }

        log::info!(
            "stream {stream_id} method={method:?} authority={authority:?} auth={auth_header:?}"
        );

        let is_connect = method.as_deref() == Some("CONNECT");
        let auth_ok = auth_header.is_some() &&
            passwords
                .iter()
                .any(|p| auth_header.as_deref() == Some(p.as_str()));

        if !is_connect || !auth_ok || authority.is_none() {
            log::warn!(
                "stream {stream_id} rejected: \
                 is_connect={is_connect} auth_ok={auth_ok} has_authority={}",
                authority.is_some()
            );

            // Send an error response so the client doesn't hang waiting,
            // and close the stream with FIN.
            let status = if !auth_ok { b"403" } else { b"400" };
            let err_headers = vec![quiche::h3::Header::new(b":status", status)];
            let _ = frame_sender
                .send(OutboundFrame::Headers(err_headers, None))
                .await;
            let _ = frame_sender
                .send(OutboundFrame::Body(Bytes::new(), true))
                .await;
            return;
        }

        let target = authority.unwrap();

        let destination: Destination = match target.parse() {
            Ok(d) => d,
            Err(e) => {
                log::warn!("stream {stream_id} bad authority {target:?}: {e}");
                let err_headers =
                    vec![quiche::h3::Header::new(b":status", b"400")];
                let _ = frame_sender
                    .send(OutboundFrame::Headers(err_headers, None))
                    .await;
                let _ = frame_sender
                    .send(OutboundFrame::Body(Bytes::new(), true))
                    .await;
                return;
            },
        };

        // Send 200 response before handing off the stream to the relay.
        let ok_headers = vec![quiche::h3::Header::new(b":status", b"200")];
        if frame_sender
            .send(OutboundFrame::Headers(ok_headers, None))
            .await
            .is_err()
        {
            log::error!("stream {stream_id} send_response 200 failed");
            return;
        }

        log::info!("stream {stream_id} accepted CONNECT to {destination}");

        let relay = H3Relay::new(frame_sender, frame_receiver);
        let inbound_conn = InboundConn::Tcp {
            destination,
            stream: Box::new(relay),
            source: "0.0.0.0:0".parse().unwrap(),
            type_: "quic".to_string(),
            sniff: false,
        };

        if conn_tx.send(inbound_conn).await.is_err() {
            log::error!(
                "stream {stream_id} failed to send InboundConn (receiver dropped)"
            );
        }
    }
}

#[async_trait]
impl Inbound for QuicInbound {
    async fn accept(&mut self) -> Option<InboundConn> {
        self.conn_rx.recv().await
    }
}
