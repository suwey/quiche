//! H3 client: HTTP/3 over QUIC using tokio-quiche.
//!
//! Creates a QUIC connection (UDP) and sends H3 requests.
//! Falls back to H2 if QUIC fails (handled by caller via FallbackState).

use std::io;
use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use std::future::poll_fn;

use tokio_quiche::http3::driver::{
    ClientH3Controller, ClientH3Event, ClientRequestSender, H3Event,
    InboundFrame, InboundFrameStream, NewClientRequest, OutboundFrame,
    OutboundFrameSender,
};
use tokio_quiche::quic::QuicConnection;

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
    _quic_conn: QuicConnection,
    /// H3 controller for sending requests.
    controller: ClientH3Controller,
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
        udp_socket.connect(addr)
            .await
            .map_err(|e| io::Error::new(io::ErrorKind::ConnectionRefused, e))?;

        let (quic_conn, mut h3_controller) = tokio_quiche::quic::connect(
            udp_socket,
            Some(&config.host),
        )
        .await
        .map_err(|e| io::Error::new(io::ErrorKind::ConnectionRefused, e.to_string()))?;

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
            _quic_conn: quic_conn,
            controller: h3_controller,
            event_receiver,
            response_recv: None,
            padding,
            placement,
            next_request_id: 0,
        })
    }

    fn build_h3_headers(&self, method: &str, path: &str) -> Vec<quiche::h3::Header> {
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
            headers.push(quiche::h3::Header::new(b"content-type", b"application/grpc"));
        }
        if !self.config.no_sse_header {
            headers.push(quiche::h3::Header::new(b"x-accel-buffering", b"no"));
        }
        headers
    }
}

#[async_trait]
impl TransportSession for H3Session {
    async fn uplink(&mut self) -> io::Result<Box<dyn UplinkWriter>> {
        let (path, extra_headers) = self.placement.build_request_meta(
            &self.config.path, &self.session_id, None,
        );

        let mut headers = self.build_h3_headers("POST", &path);
        for (k, v) in &extra_headers {
            headers.push(quiche::h3::Header::new(k.as_bytes(), v.as_bytes()));
        }
        if let Some(ref pad) = self.padding {
            let mut pad_headers = Vec::new();
            pad.apply_to_request(&path, &mut pad_headers);
            for (k, v) in pad_headers {
                headers.push(quiche::h3::Header::new(k.as_bytes(), v.as_bytes()));
            }
        }

        let (body_tx, body_rx) = tokio::sync::oneshot::channel::<OutboundFrameSender>();
        let request_id = self.next_request_id;
        self.next_request_id += 1;

        let request = NewClientRequest {
            request_id,
            headers,
            body_writer: Some(body_tx),
        };

        // Send request (sync, takes &self)
        let sender: ClientRequestSender = self.controller.request_sender();
        sender.send(request)
            .map_err(|_| io::Error::new(io::ErrorKind::ConnectionReset, "h3 request send failed"))?;

        // Wait for NewOutboundRequest event + body sender
        let mut got_body_sender = None;
        while let Some(event) = self.event_receiver.recv().await {
            match event {
                ClientH3Event::NewOutboundRequest { request_id: rid, .. } if rid == request_id => {
                    match body_rx.await {
                        Ok(s) => { got_body_sender = Some(s); break; }
                        Err(_) => return Err(io::Error::new(
                            io::ErrorKind::ConnectionReset, "h3 body sender dropped")),
                    }
                }
                ClientH3Event::Core(H3Event::IncomingHeaders(hdrs)) => {
                    // Response arrived early (before uplink returned) - save it
                    self.response_recv = Some(hdrs.recv);
                }
                _ => {}
            }
        }

        let body_sender = got_body_sender.ok_or_else(|| {
            io::Error::new(io::ErrorKind::ConnectionReset, "h3 connection closed before stream created")
        })?;

        Ok(Box::new(H3UplinkWriter {
            body_sender: Some(body_sender),
        }))
    }

    async fn downlink(&mut self) -> io::Result<Box<dyn DownlinkReader>> {
        // If response already received during uplink(), use it
        if let Some(recv) = self.response_recv.take() {
            return Ok(Box::new(H3DownlinkReader { recv, read_buf: Vec::new() }));
        }

        while let Some(event) = self.event_receiver.recv().await {
            if let ClientH3Event::Core(H3Event::IncomingHeaders(hdrs)) = event {
                return Ok(Box::new(H3DownlinkReader { recv: hdrs.recv, read_buf: Vec::new() }));
            }
        }

        Err(io::Error::new(io::ErrorKind::ConnectionReset, "h3 connection closed before response"))
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
            io::Error::new(io::ErrorKind::BrokenPipe, "h3 uplink already shut down")
        })?;
        poll_fn(|cx| sender.poll_reserve(cx)).await
            .map_err(|_| io::Error::new(io::ErrorKind::ConnectionReset, "h3 reserve failed"))?;
        sender.send_item(OutboundFrame::Body(Bytes::copy_from_slice(data), false))
            .map_err(|_| io::Error::new(io::ErrorKind::ConnectionReset, "h3 body send failed"))
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
            }
            None => Ok(0),
            _ => Ok(0),
        }
    }
}

// ---------------------------------------------------------------------------
// H3ConnectionManager
// ---------------------------------------------------------------------------

use crate::connection::{ConnError, ConnectionManager};

/// Simple H3 connection manager: one QUIC connection per session.
pub struct H3ConnectionManager {
    config: Arc<XhttpConfig>,
}

impl H3ConnectionManager {
    pub fn new(config: Arc<XhttpConfig>) -> Self {
        Self { config }
    }
}

#[async_trait]
impl ConnectionManager for H3ConnectionManager {
    async fn acquire_uplink(&self) -> Result<Box<dyn TransportSession>, ConnError> {
        let session = H3Session::connect(self.config.clone())
            .await
            .map_err(|e| ConnError::CreateFailed(e.to_string()))?;
        Ok(Box::new(session))
    }

    async fn acquire_downlink(&self) -> Result<Box<dyn TransportSession>, ConnError> {
        self.acquire_uplink().await
    }

    async fn release(&self, _session: Box<dyn TransportSession>) {}
    fn is_healthy(&self) -> bool { true }
    async fn shutdown(&self) {}
}
