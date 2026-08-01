//! XHTTP transport: stream-one mode over HTTP/2.
//!
//! Implements `TransportSession` for the XHTTP stream-one protocol:
//! a single POST request whose body carries uplink data and whose
//! response body carries downlink data (symmetric, like WebSocket).
//!
//! ## Architecture (§6.1)
//!
//! ```text
//! uplink()  -> StreamUplinkWriter  -> POST body (channel -> StreamBody)
//! downlink() -> StreamDownlinkReader -> response body (Incoming)
//! ```

pub mod config;
pub mod fallback;
pub mod h2;
pub mod padding;
pub mod placement;
pub mod download_queue;
pub mod upload_queue;
pub mod xmux;
pub mod h3;
use std::io;
use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use http_body::Frame;
use http_body_util::BodyExt;
use tokio::sync::mpsc;

use crate::transport::{DownlinkReader, TransportSession, UplinkWriter};

use config::{resolve_http_version, resolve_mode, XhttpConfig, XhttpMode};
use h2::{make_stream_body, H2SendRequest, ReqBody};
use padding::XPaddingMiddleware;
use upload_queue::UploadQueue;
use placement::PlacementConfig;

// ---------------------------------------------------------------------------
// XhttpSession
// ---------------------------------------------------------------------------

/// An XHTTP transport session.
///
/// For stream-one mode (M3): a single POST request with streaming body
/// (uplink) and streaming response body (downlink), sharing one H2 stream.
pub struct XhttpSession {
    config: Arc<XhttpConfig>,
    session_id: String,
    mode: XhttpMode,

    /// H2 send-request handle (cloned per stream; `None` after `close()`).
    send_req: Option<H2SendRequest>,

    /// Response future stored between `uplink()` and `downlink()`.
    response_rx: Option<tokio::sync::oneshot::Receiver<Result<hyper::Response<hyper::body::Incoming>, hyper::Error>>>,

    /// XPadding middleware (if configured).
    padding: Option<XPaddingMiddleware>,

    /// Session metadata placement config.
    placement: PlacementConfig,
}

impl XhttpSession {
    /// Create a session from a pre-built H2 `SendRequest` (for testing
    /// or when the connection is managed externally).
    pub fn from_send_request(config: Arc<XhttpConfig>, send_req: H2SendRequest) -> Self {
        let padding = config.padding.clone().map(XPaddingMiddleware::new);
        let placement = PlacementConfig {
            session_id_placement: config.session_id_placement,
            session_id_key: config.session_id_key.clone(),
            seq_placement: config.seq_placement,
            seq_key: config.seq_key.clone(),
        };
        let session_id = uuid::Uuid::new_v4().to_string();
        Self {
            mode: resolve_mode(&config),
            config,
            session_id,
            send_req: Some(send_req),
            response_rx: None,
            padding,
            placement,
        }
    }

    /// Connect to the server and create a session (production path).
    pub async fn connect(config: Arc<XhttpConfig>) -> io::Result<Self> {
        let addr = resolve_addr(&config).await?;
        let http_version = resolve_http_version(&config);
        let send_req = h2::connect(addr, &config.host, config.insecure, http_version).await?;
        Ok(Self::from_send_request(config, send_req))
    }

    /// Build an HTTP request with the given method, optional seq, and body.
    fn build_request(
        &self,
        method: &str,
        seq: Option<u64>,
        body: ReqBody,
    ) -> io::Result<http::Request<ReqBody>> {
        let (path, extra_headers) = self.placement.build_request_meta(
            &self.config.path,
            &self.session_id,
            seq,
        );

        let mut builder = http::Request::builder()
            .method(method)
            .uri(&path)
            .header("Host", &self.config.host);

        for (k, v) in &self.config.headers {
            builder = builder.header(k, v);
        }
        for (k, v) in &extra_headers {
            builder = builder.header(k, v);
        }
        // Decoy headers (disabled by no_grpc_header / no_sse_header)
        if !self.config.no_grpc_header {
            builder = builder.header("Content-Type", "application/grpc");
        }
        if !self.config.no_sse_header {
            builder = builder.header("X-Accel-Buffering", "no");
        }

        if let Some(pad) = &self.padding {
            let mut pad_headers = Vec::new();
            pad.apply_to_request(&path, &mut pad_headers);
            for (k, v) in pad_headers {
                builder = builder.header(k, v);
            }
        }

        builder
            .body(body)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))
    }
}

#[async_trait]
impl TransportSession for XhttpSession {
    async fn uplink(&mut self) -> io::Result<Box<dyn UplinkWriter>> {
        match self.mode {
            XhttpMode::StreamOne | XhttpMode::StreamUp => {
                let (body_tx, body) = make_stream_body(64);
                let request = self.build_request("POST", None, body)?;

                let send_req = self.send_req.as_mut().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::NotConnected, "session closed")
                })?;
                let response_future = send_req.send_request(request);

                if self.mode == XhttpMode::StreamOne {
                    // Stream-one: store response for downlink()
                    let (resp_tx, resp_rx) = tokio::sync::oneshot::channel();
                    self.response_rx = Some(resp_rx);
                    tokio::spawn(async move {
                        let result = response_future.await;
                        let _ = resp_tx.send(result);
                    });
                } else {
                    // Stream-up: drain response (not used for downlink)
                    tokio::spawn(async move {
                        if let Ok(resp) = response_future.await {
                            let _ = http_body_util::BodyExt::collect(resp.into_body()).await;
                        }
                    });
                }

                Ok(Box::new(StreamUplinkWriter {
                    body_tx: Some(body_tx),
                }))
            }
            XhttpMode::PacketUp => {
                // Packet-up: return a PacketUplinkWriter that chunks data
                // into separate POSTs with seq
                let send_req_clone = self.send_req.as_ref()
                    .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "session closed"))?
                    .clone();

                Ok(Box::new(PacketUplinkWriter {
                    send_req: send_req_clone,
                    config: self.config.clone(),
                    session_id: self.session_id.clone(),
                    placement: self.placement.clone(),
                    padding: self.padding.clone(),
                    upload_queue: {
                        let cs = self.config.uplink.chunk_size
                            .as_ref()
                            .map(|r| r.rand_usize())
                            .unwrap_or(16 * 1024);
                        UploadQueue::new(cs)
                    },
                }))
            }
            XhttpMode::Auto => {
                Err(io::Error::new(io::ErrorKind::Unsupported, "Auto mode should be resolved"))
            }
        }
    }

    async fn downlink(&mut self) -> io::Result<Box<dyn DownlinkReader>> {
        match self.mode {
            XhttpMode::StreamOne => {
                // Stream-one: use the response from uplink()
                let response_rx = self.response_rx.take().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "uplink() must be called first")
                })?;

                let response = response_rx
                    .await
                    .map_err(|_| io::Error::new(io::ErrorKind::ConnectionReset, "response task dropped"))?
                    .map_err(|e| io::Error::new(io::ErrorKind::ConnectionReset, e))?;

                if let Some(pad) = &self.padding {
                    if !pad.validate_response(response.headers()) {
                        log::warn!("xhttp: response XPadding validation failed");
                    }
                }

                Ok(Box::new(StreamDownlinkReader {
                    body: response.into_body(),
                    read_buf: Vec::new(),
                }))
            }
            XhttpMode::StreamUp | XhttpMode::PacketUp => {
                // Stream-up / packet-up: send a separate GET request
                let (_empty_tx, empty_body) = make_stream_body(1);
                // _empty_tx dropped -> empty body = immediate end-of-body
                let request = self.build_request("GET", None, empty_body)?;

                let send_req = self.send_req.as_mut().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::NotConnected, "session closed")
                })?;

                let response = send_req.send_request(request)
                    .await
                    .map_err(|e| io::Error::new(io::ErrorKind::ConnectionReset, e))?;

                if let Some(pad) = &self.padding {
                    if !pad.validate_response(response.headers()) {
                        log::warn!("xhttp: response XPadding validation failed");
                    }
                }

                Ok(Box::new(StreamDownlinkReader {
                    body: response.into_body(),
                    read_buf: Vec::new(),
                }))
            }
            XhttpMode::Auto => {
                Err(io::Error::new(io::ErrorKind::Unsupported, "Auto mode should be resolved"))
            }
        }
    }

    async fn close(&mut self) -> io::Result<()> {
        self.send_req.take();
        self.response_rx = None;
        Ok(())
    }

    fn kind(&self) -> &'static str {
        "xhttp"
    }
}

// ---------------------------------------------------------------------------
// StreamUplinkWriter
// ---------------------------------------------------------------------------

/// Writes uplink data to the POST request body via a channel.
pub struct StreamUplinkWriter {
    body_tx: Option<mpsc::Sender<Result<Frame<Bytes>, io::Error>>>,
}

#[async_trait]
impl UplinkWriter for StreamUplinkWriter {
    async fn write(&mut self, data: &[u8]) -> io::Result<()> {
        let tx = self.body_tx.as_ref().ok_or_else(|| {
            io::Error::new(io::ErrorKind::BrokenPipe, "uplink already shut down")
        })?;
        tx.send(Ok(Frame::data(Bytes::copy_from_slice(data))))
            .await
            .map_err(|_| {
                io::Error::new(io::ErrorKind::ConnectionReset, "body channel closed")
            })
    }

    async fn shutdown(&mut self) -> io::Result<()> {
        // Drop the sender to signal end-of-body to the H2 layer.
        self.body_tx.take();
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// StreamDownlinkReader
// ---------------------------------------------------------------------------

/// Reads downlink data from the HTTP response body.
pub struct StreamDownlinkReader {
    body: hyper::body::Incoming,
    read_buf: Vec<u8>,
}

#[async_trait]
impl DownlinkReader for StreamDownlinkReader {
    async fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // Drain the read buffer first
        if !self.read_buf.is_empty() {
            let n = std::cmp::min(self.read_buf.len(), buf.len());
            buf[..n].copy_from_slice(&self.read_buf[..n]);
            self.read_buf.drain(..n);
            return Ok(n);
        }

        // Read the next data frame from the response body
        loop {
            match self.body.frame().await {
                None => return Ok(0), // EOF
                Some(Ok(frame)) => {
                    if let Some(data) = frame.data_ref() {
                        let n = std::cmp::min(data.len(), buf.len());
                        buf[..n].copy_from_slice(&data[..n]);
                        if data.len() > n {
                            self.read_buf.extend_from_slice(&data[n..]);
                        }
                        return Ok(n);
                    }
                    // Skip trailer frames
                }
                Some(Err(e)) => {
                    return Err(io::Error::new(io::ErrorKind::ConnectionReset, e));
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// PacketUplinkWriter (packet-up mode)
// ---------------------------------------------------------------------------

/// Uplink writer for packet-up mode: chunks data into separate POSTs.
///
/// Each chunk is sent as a separate HTTP POST with `?seq=N` in the URL.
/// The server reassembles chunks by seq order.
pub struct PacketUplinkWriter {
    send_req: H2SendRequest,
    config: Arc<XhttpConfig>,
    session_id: String,
    placement: PlacementConfig,
    padding: Option<XPaddingMiddleware>,
    upload_queue: UploadQueue,
}

impl PacketUplinkWriter {
    /// Send a single chunk as a POST with `?seq=<seq>`.
    async fn send_packet(&mut self, seq: u64, data: Vec<u8>) -> io::Result<()> {
        let (body_tx, body) = make_stream_body(1);

        // Build POST request with seq in URL
        let (path, extra_headers) = self.placement.build_request_meta(
            &self.config.path, &self.session_id, Some(seq),
        );

        let method_str = match self.config.uplink.method {
            config::HttpMethod::Post => "POST",
            config::HttpMethod::Get => "GET",
        };
        let mut builder = http::Request::builder()
            .method(method_str)
            .uri(&path)
            .header("Host", &self.config.host);

        for (k, v) in &self.config.headers {
            builder = builder.header(k, v);
        }
        for (k, v) in &extra_headers {
            builder = builder.header(k, v);
        }
        // Decoy headers
        if !self.config.no_grpc_header {
            builder = builder.header("Content-Type", "application/grpc");
        }
        if !self.config.no_sse_header {
            builder = builder.header("X-Accel-Buffering", "no");
        }
        if let Some(pad) = &self.padding {
            let mut pad_headers = Vec::new();
            pad.apply_to_request(&path, &mut pad_headers);
            for (k, v) in pad_headers {
                builder = builder.header(k, v);
            }
        }

        let request = builder
            .body(body)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;

        // Send data and close body immediately (short POST)
        let _ = body_tx.send(Ok(Frame::data(Bytes::from(data)))).await;
        drop(body_tx);

        let response_future = self.send_req.send_request(request);

        // Drain response (not used for uplink)
        tokio::spawn(async move {
            if let Ok(resp) = response_future.await {
                let _ = http_body_util::BodyExt::collect(resp.into_body()).await;
            }
        });

        Ok(())
    }
}

#[async_trait]
impl UplinkWriter for PacketUplinkWriter {
    async fn write(&mut self, data: &[u8]) -> io::Result<()> {
        let chunks = self.upload_queue.push(data);
        for (seq, chunk) in chunks {
            self.send_packet(seq, chunk).await?;
        }
        Ok(())
    }

    async fn shutdown(&mut self) -> io::Result<()> {
        if let Some((seq, chunk)) = self.upload_queue.flush() {
            self.send_packet(seq, chunk).await?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async fn resolve_addr(config: &XhttpConfig) -> io::Result<std::net::SocketAddr> {
    let addr_str = format!("{}:{}", config.host, config.port);
    tokio::net::lookup_host(&addr_str)
        .await?
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::AddrNotAvailable, "DNS resolution failed"))
}

// ---------------------------------------------------------------------------
// Integration tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::body::Incoming;
    use hyper::server::conn::http2;
    use hyper::service::service_fn;
    use hyper::Request;
    use hyper_util::rt::{TokioExecutor, TokioIo};
    use http_body_util::{BodyExt, Full};

    /// Start a plain-H2 echo server on localhost.
    ///
    /// Reads the full request body, then echoes it back as the response body.
    async fn start_echo_server() -> (
        std::net::SocketAddr,
        tokio::task::JoinHandle<()>,
    ) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let handle = tokio::spawn(async move {
            loop {
                let Ok((tcp, _)) = listener.accept().await else { break };
                let io = TokioIo::new(tcp);
                let exec = TokioExecutor::new();
                let _ = http2::Builder::new(exec)
                    .serve_connection(
                        io,
                        service_fn(|req: Request<Incoming>| async move {
                            let bytes = req.into_body().collect().await.unwrap().to_bytes();
                            Ok::<_, std::convert::Infallible>(
                                hyper::Response::builder()
                                    .status(200)
                                    .body(Full::new(bytes))
                                    .unwrap(),
                            )
                        }),
                    )
                    .await;
            }
        });

        (addr, handle)
    }

    /// Connect a plain H2 client (no TLS) for testing.
    async fn connect_plain_h2(addr: std::net::SocketAddr) -> H2SendRequest {
        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        let io = TokioIo::new(tcp);
        let exec = TokioExecutor::new();
        let (send_req, conn) = hyper::client::conn::http2::handshake(exec, io).await.unwrap();
        tokio::spawn(async move {
            let _ = conn.await;
        });
        send_req
    }

    #[tokio::test]
    async fn stream_one_echo_roundtrip() {
        let (addr, _server) = start_echo_server().await;
        let send_req = connect_plain_h2(addr).await;

        let config = Arc::new(XhttpConfig {
            host: "localhost".to_string(),
            path: "/xhttp".to_string(),
            ..Default::default()
        });
        let mut session = XhttpSession::from_send_request(config, send_req);

        // Write data through uplink
        let mut writer = session.uplink().await.unwrap();
        writer.write(b"Hello, XHTTP!").await.unwrap();
        writer.shutdown().await.unwrap();

        // Read data from downlink
        let mut reader = session.downlink().await.unwrap();
        let mut buf = vec![0u8; 1024];
        let n = reader.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"Hello, XHTTP!");

        // EOF
        let n2 = reader.read(&mut buf).await.unwrap();
        assert_eq!(n2, 0);
    }

    #[tokio::test]
    async fn stream_one_large_data() {
        let (addr, _server) = start_echo_server().await;
        let send_req = connect_plain_h2(addr).await;

        let config = Arc::new(XhttpConfig {
            host: "localhost".to_string(),
            path: "/xhttp".to_string(),
            ..Default::default()
        });
        let mut session = XhttpSession::from_send_request(config, send_req);

        // Write 64KB of data
        let data: Vec<u8> = (0..65536).map(|i| (i % 256) as u8).collect();
        let mut writer = session.uplink().await.unwrap();
        // Write in chunks
        for chunk in data.chunks(4096) {
            writer.write(chunk).await.unwrap();
        }
        writer.shutdown().await.unwrap();

        // Read all data back
        let mut reader = session.downlink().await.unwrap();
        let mut received = Vec::new();
        let mut buf = vec![0u8; 8192];
        loop {
            let n = reader.read(&mut buf).await.unwrap();
            if n == 0 {
                break;
            }
            received.extend_from_slice(&buf[..n]);
        }
        assert_eq!(received, data);
    }

    #[tokio::test]
    async fn stream_one_multiple_writes() {
        let (addr, _server) = start_echo_server().await;
        let send_req = connect_plain_h2(addr).await;

        let config = Arc::new(XhttpConfig {
            host: "localhost".to_string(),
            path: "/xhttp".to_string(),
            ..Default::default()
        });
        let mut session = XhttpSession::from_send_request(config, send_req);

        let mut writer = session.uplink().await.unwrap();
        writer.write(b"chunk1|").await.unwrap();
        writer.write(b"chunk2|").await.unwrap();
        writer.write(b"chunk3").await.unwrap();
        writer.shutdown().await.unwrap();

        let mut reader = session.downlink().await.unwrap();
        let mut received = Vec::new();
        let mut buf = vec![0u8; 1024];
        loop {
            let n = reader.read(&mut buf).await.unwrap();
            if n == 0 {
                break;
            }
            received.extend_from_slice(&buf[..n]);
        }
        assert_eq!(received, b"chunk1|chunk2|chunk3");
    }

    #[tokio::test]
    async fn session_kind() {
        let (addr, _server) = start_echo_server().await;
        let send_req = connect_plain_h2(addr).await;
        let config = Arc::new(XhttpConfig {
            host: "localhost".to_string(),
            ..Default::default()
        });
        let session = XhttpSession::from_send_request(config, send_req);
        assert_eq!(session.kind(), "xhttp");
    }

    #[tokio::test]
    async fn session_close() {
        let (addr, _server) = start_echo_server().await;
        let send_req = connect_plain_h2(addr).await;
        let config = Arc::new(XhttpConfig {
            host: "localhost".to_string(),
            ..Default::default()
        });
        let mut session = XhttpSession::from_send_request(config, send_req);
        session.close().await.unwrap();
        // uplink after close should fail
        assert!(session.uplink().await.is_err());
    }

    // -----------------------------------------------------------------------
    // Stream-up tests (M6)
    // -----------------------------------------------------------------------

    /// Server that stores POST body and returns it as GET response.
    /// POST and GET are associated by arriving on the same H2 connection.
    async fn start_stream_up_server() -> std::net::SocketAddr {
        use std::time::Duration;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let stored: Arc<tokio::sync::Mutex<Option<Vec<u8>>>> =
            Arc::new(tokio::sync::Mutex::new(None));
        let notify = Arc::new(tokio::sync::Notify::new());

        tokio::spawn(async move {
            loop {
                let Ok((tcp, _)) = listener.accept().await else { break };
                let io = TokioIo::new(tcp);
                let exec = TokioExecutor::new();
                let stored = stored.clone();
                let notify = notify.clone();
                let _ = http2::Builder::new(exec)
                    .serve_connection(
                        io,
                        service_fn(move |req: Request<Incoming>| {
                            let stored = stored.clone();
                            let notify = notify.clone();
                            async move {
                                if req.method() == "POST" {
                                    let bytes = req.into_body().collect().await.unwrap().to_bytes();
                                    *stored.lock().await = Some(bytes.to_vec());
                                    notify.notify_one();
                                    Ok::<_, std::convert::Infallible>(
                                        hyper::Response::builder().status(200).body(Full::new(Bytes::new())).unwrap(),
                                    )
                                } else {
                                    // GET: wait for POST to complete
                                    let _ = tokio::time::timeout(
                                        Duration::from_secs(5),
                                        notify.notified(),
                                    ).await;
                                    let data = stored.lock().await.clone().unwrap_or_default();
                                    Ok::<_, std::convert::Infallible>(
                                        hyper::Response::builder().status(200)
                                            .body(Full::new(Bytes::from(data))).unwrap(),
                                    )
                                }
                            }
                        }),
                    )
                    .await;
            }
        });
        addr
    }

    #[tokio::test]
    async fn stream_up_separate_post_get() {
        let addr = start_stream_up_server().await;
        let send_req = connect_plain_h2(addr).await;
        let config = Arc::new(XhttpConfig {
            host: "localhost".to_string(),
            path: "/xhttp".to_string(),
            mode: XhttpMode::StreamUp,
            ..Default::default()
        });
        let mut session = XhttpSession::from_send_request(config, send_req);

        // Uplink: write data via POST
        let mut writer = session.uplink().await.unwrap();
        writer.write(b"stream-up test data").await.unwrap();
        writer.shutdown().await.unwrap();

        // Downlink: read data via GET
        let mut reader = session.downlink().await.unwrap();
        let mut buf = vec![0u8; 1024];
        let n = reader.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"stream-up test data");
    }

    // -----------------------------------------------------------------------
    // Packet-up tests (M6)
    // -----------------------------------------------------------------------

    /// Server that collects POST chunks by seq and returns them as GET response.
    async fn start_packet_up_server() -> std::net::SocketAddr {
        use std::collections::BTreeMap;
        use std::time::Duration;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let chunks: Arc<tokio::sync::Mutex<BTreeMap<u64, Vec<u8>>>> =
            Arc::new(tokio::sync::Mutex::new(BTreeMap::new()));
        let post_count = Arc::new(std::sync::atomic::AtomicU32::new(0));

        tokio::spawn(async move {
            loop {
                let Ok((tcp, _)) = listener.accept().await else { break };
                let io = TokioIo::new(tcp);
                let exec = TokioExecutor::new();
                let chunks = chunks.clone();
                let post_count = post_count.clone();
                let _ = http2::Builder::new(exec)
                    .serve_connection(
                        io,
                        service_fn(move |req: Request<Incoming>| {
                            let chunks = chunks.clone();
                            let post_count = post_count.clone();
                            async move {
                                if req.method() == "POST" {
                                    // Extract seq from query before consuming body
                                    let seq = req.uri().query()
                                        .and_then(|q| q.split('=').nth(1))
                                        .and_then(|s| s.parse::<u64>().ok())
                                        .unwrap_or(0);
                                    let bytes = req.into_body().collect().await.unwrap().to_bytes();
                                    chunks.lock().await.insert(seq, bytes.to_vec());
                                    post_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                    Ok::<_, std::convert::Infallible>(
                                        hyper::Response::builder().status(200).body(Full::new(Bytes::new())).unwrap(),
                                    )
                                } else {
                                    // GET: wait for POSTs to arrive
                                    tokio::time::sleep(Duration::from_millis(500)).await;
                                    let map = chunks.lock().await;
                                    let mut data = Vec::new();
                                    for (_, chunk) in map.iter() {
                                        data.extend_from_slice(chunk);
                                    }
                                    Ok::<_, std::convert::Infallible>(
                                        hyper::Response::builder().status(200)
                                            .body(Full::new(Bytes::from(data))).unwrap(),
                                    )
                                }
                            }
                        }),
                    )
                    .await;
            }
        });
        addr
    }

    #[tokio::test]
    async fn packet_up_multiple_posts() {
        let addr = start_packet_up_server().await;
        let send_req = connect_plain_h2(addr).await;
        let config = Arc::new(XhttpConfig {
            host: "localhost".to_string(),
            path: "/xhttp".to_string(),
            mode: XhttpMode::PacketUp,
            ..Default::default()
        });
        let mut session = XhttpSession::from_send_request(config, send_req);

        // Write 32KB of data - should be split into 2 chunks (16KB default)
        let data: Vec<u8> = (0..32768).map(|i| (i % 256) as u8).collect();
        let mut writer = session.uplink().await.unwrap();
        writer.write(&data).await.unwrap();
        writer.shutdown().await.unwrap();

        // Downlink: read reassembled data via GET
        let mut reader = session.downlink().await.unwrap();
        let mut received = Vec::new();
        let mut buf = vec![0u8; 8192];
        loop {
            let n = reader.read(&mut buf).await.unwrap();
            if n == 0 { break; }
            received.extend_from_slice(&buf[..n]);
        }
        assert_eq!(received.len(), data.len());
        assert_eq!(received, data);
    }
}
