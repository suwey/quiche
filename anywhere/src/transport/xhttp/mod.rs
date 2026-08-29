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
pub mod h3;
pub mod padding;
pub mod placement;
pub mod xmux;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use http_body::Frame;
use http_body_util::BodyExt;
use tokio::sync::mpsc;

use crate::connection::reconnect::ReconnectPolicy;
use crate::obfuscation::{ObfContext, ObfuscationChain};
use crate::transport::{DownlinkReader, TransportSession, UplinkWriter};

use crate::transport::seq::SeqChunker;
use base64::Engine;
use config::{
    HttpVersionPref, UplinkDataPlacement, XhttpConfig, XhttpDirectionConfig,
    XhttpMode, resolve_http_version, resolve_mode,
};
use h2::{H2SendRequest, HttpSendRequest, ReqBody, make_stream_body};
use h3::H3Session;
use padding::XPaddingMiddleware;
use placement::PlacementConfig;

// ---------------------------------------------------------------------------
// Obfuscation chain builder
// ---------------------------------------------------------------------------

/// Build an [`ObfuscationChain`] from the XHTTP config.
///
/// Returns `None` when no obfuscation is configured (chain would be empty).
/// Concrete layers are registered here as they are implemented; the chain
/// architecture allows adding new [`ObfuscationLayer`] implementations
/// without further transport-layer changes.
fn build_obfuscation_chain(config: &XhttpConfig) -> Option<ObfuscationChain> {
    let obf_config = config.obfuscation.as_ref()?;
    let chain = ObfuscationChain::new();

    for layer_name in &obf_config.layers {
        // Register concrete layers here as they are implemented.
        // Unrecognized layer names are logged and skipped.
        log::warn!("xhttp: unknown obfuscation layer '{layer_name}', skipping");
    }

    if chain.is_empty() { None } else { Some(chain) }
}

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
    /// `None` when in H3 mode (uses `h3_session` instead).
    send_req: Option<HttpSendRequest>,

    /// Optional separate downlink send-request for asymmetric mode
    /// (when `downlink_target` is configured). `None` in symmetric mode.
    downlink_send_req: Option<HttpSendRequest>,

    /// H3 session handle (when using HTTP/3). `None` for H2/H1 mode.
    /// When set, all TransportSession methods delegate to this H3 session.
    h3_session: Option<H3Session>,

    /// Response future stored between `uplink()` and `downlink()`.
    response_rx: Option<
        tokio::sync::oneshot::Receiver<
            Result<hyper::Response<hyper::body::Incoming>, hyper::Error>,
        >,
    >,

    /// XPadding middleware (if configured).
    padding: Option<XPaddingMiddleware>,

    /// Session metadata placement config.
    placement: PlacementConfig,
}

impl XhttpSession {
    /// Create a session from a pre-built H2 `SendRequest` (for testing
    /// or when the connection is managed externally).
    pub fn from_send_request(
        config: Arc<XhttpConfig>, send_req: HttpSendRequest,
    ) -> Self {
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
            downlink_send_req: None,
            h3_session: None,
            response_rx: None,
            padding,
            placement,
        }
    }

    /// Connect to the server and create a session (production path).
    ///
    /// If `uplink_target` or `downlink_target` is configured, uses asymmetric
    /// mode: separate connections for uplink and downlink.
    ///
    /// When `http_version` is `Http3`, tries H3 (QUIC) first. If H3 fails,
    /// falls back to H2 automatically.
    pub async fn connect(config: Arc<XhttpConfig>) -> io::Result<Self> {
        if config.uplink_target.is_some() || config.downlink_target.is_some() {
            return Self::connect_asymmetric(config).await;
        }

        // Symmetric mode: single connection for both directions
        let http_version = resolve_http_version(&config);

        match http_version {
            HttpVersionPref::Http3 => {
                // Try H3 first, fall back to H2 on failure
                match h3::H3Session::connect(config.clone()).await {
                    Ok(h3_session) => {
                        log::debug!("xhttp: connected via H3 to {}", config.host);
                        let padding =
                            config.padding.clone().map(XPaddingMiddleware::new);
                        let placement = PlacementConfig {
                            session_id_placement: config.session_id_placement,
                            session_id_key: config.session_id_key.clone(),
                            seq_placement: config.seq_placement,
                            seq_key: config.seq_key.clone(),
                        };
                        let session_id = uuid::Uuid::new_v4().to_string();
                        let mode = resolve_mode(&config);
                        Ok(Self {
                            config,
                            session_id,
                            mode,
                            send_req: None,
                            downlink_send_req: None,
                            h3_session: Some(h3_session),
                            response_rx: None,
                            padding,
                            placement,
                        })
                    },
                    Err(e) => {
                        log::warn!(
                            "xhttp: H3 connect failed, falling back to H2: {}",
                            e
                        );
                        let addr = resolve_addr(&config).await?;
                        let send_req = h2::connect(
                            addr,
                            &config.host,
                            config.insecure,
                            HttpVersionPref::Http2,
                        )
                        .await?;
                        Ok(Self::from_send_request(config, send_req))
                    },
                }
            },
            _ => {
                // H2 / H1 path (original)
                let addr = resolve_addr(&config).await?;
                let send_req = h2::connect(
                    addr,
                    &config.host,
                    config.insecure,
                    http_version,
                )
                .await?;
                Ok(Self::from_send_request(config, send_req))
            },
        }
    }

    /// Connect using asymmetric (separate uplink/downlink) connections.
    ///
    /// - Uplink: uses `uplink_target` overrides merged into base config.
    /// - Downlink: if `downlink_target` is set, creates a separate connection.
    async fn connect_asymmetric(config: Arc<XhttpConfig>) -> io::Result<Self> {
        // Build uplink config by merging base with uplink_target overrides
        let uplink_config =
            merge_direction_config(&config, config.uplink_target.as_ref());
        let uplink_addr = resolve_addr(&uplink_config).await?;
        let uplink_http_version = resolve_http_version(&uplink_config);
        let uplink_send_req = h2::connect(
            uplink_addr,
            &uplink_config.host,
            uplink_config.insecure,
            uplink_http_version,
        )
        .await?;

        // Build downlink config (if downlink_target is set)
        let downlink_send_req = if config.downlink_target.is_some() {
            let downlink_config =
                merge_direction_config(&config, config.downlink_target.as_ref());
            let downlink_addr = resolve_addr(&downlink_config).await?;
            let downlink_http_version = resolve_http_version(&downlink_config);
            let dl_send_req = h2::connect(
                downlink_addr,
                &downlink_config.host,
                downlink_config.insecure,
                downlink_http_version,
            )
            .await?;
            Some(dl_send_req)
        } else {
            None
        };

        // Build session with uplink connection as primary
        let mut session = Self::from_send_request(config, uplink_send_req);
        session.downlink_send_req = downlink_send_req;
        Ok(session)
    }

    /// Build an HTTP request with the given method, optional seq, and body.
    fn build_request(
        &self, method: &str, seq: Option<u64>, body: ReqBody,
    ) -> io::Result<http::Request<ReqBody>> {
        let (path, extra_headers) = self.placement.build_request_meta(
            &self.config.path,
            &self.session_id,
            seq,
        );

        // Apply padding before setting URI so Query placement can modify the URL
        let mut pad_path = path;
        let mut pad_headers = Vec::new();
        if let Some(pad) = &self.padding {
            pad.apply_to_request_mut(&mut pad_path, &mut pad_headers);
        }

        let mut builder = http::Request::builder()
            .method(method)
            .uri(&pad_path)
            .header("Host", &self.config.host);

        for (k, v) in &self.config.headers {
            builder = builder.header(k, v);
        }
        for (k, v) in &extra_headers {
            builder = builder.header(k, v);
        }
        // Decoy headers (disabled by no_grpc_header)
        if !self.config.no_grpc_header {
            builder = builder.header("Content-Type", "application/grpc");
        }
        // HTTP/1.1 requires Transfer-Encoding: chunked for streaming
        // request bodies. hyper's H1 client does not auto-add it for
        // custom Body types, causing the server to wait for body EOF.
        // H2 will strip this header (per RFC 7540 §8.1.2.2).
        builder = builder.header("Transfer-Encoding", "chunked");
        // Note: no_sse_header controls the server-side SSE response header
        // (Content-Type: text/event-stream), not a client request header.
        // X-Accel-Buffering is a server response header, not a request header.

        for (k, v) in pad_headers {
            builder = builder.header(k, v);
        }

        builder
            .body(body)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))
    }
}

#[async_trait]
impl TransportSession for XhttpSession {
    async fn uplink(&mut self) -> io::Result<Box<dyn UplinkWriter>> {
        // Delegate to H3 session if in H3 mode
        if let Some(ref mut h3) = self.h3_session {
            return h3.uplink().await;
        }
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
                            let _ = http_body_util::BodyExt::collect(
                                resp.into_body(),
                            )
                            .await;
                        }
                    });
                }

                Ok(Box::new(StreamUplinkWriter {
                    body_tx: Some(body_tx),
                    obf_chain: build_obfuscation_chain(&self.config),
                    is_first_write: true,
                }))
            },
            XhttpMode::PacketUp => {
                // Packet-up: return a PacketUplinkWriter that chunks data
                // into separate POSTs with seq
                let send_req_clone = match self.send_req.as_ref() {
                    Some(HttpSendRequest::H2(sr)) => sr.clone(),
                    _ => {
                        return Err(io::Error::new(
                            io::ErrorKind::Unsupported,
                            "packet-up requires HTTP/2",
                        ));
                    },
                };

                // Resolve chunk_size from uplink.chunk_size (default 16KB)
                let cs = self
                    .config
                    .uplink
                    .chunk_size
                    .as_ref()
                    .map(|r| r.rand_usize())
                    .unwrap_or(16 * 1024);

                // Resolve throttle config: max_buffered_posts (default 30)
                let max_buffered_posts =
                    self.config.throttle.max_buffered_posts.unwrap_or(30)
                        as usize;
                let max_buffered = max_buffered_posts * cs;

                // Resolve min_posts_interval_ms (default 30ms)
                let min_post_interval = self
                    .config
                    .throttle
                    .min_posts_interval_ms
                    .as_ref()
                    .map(|r| std::time::Duration::from_millis(r.rand_u64()))
                    .or(Some(std::time::Duration::from_millis(30)));

                Ok(Box::new(PacketUplinkWriter {
                    send_req: send_req_clone,
                    config: self.config.clone(),
                    session_id: self.session_id.clone(),
                    placement: self.placement.clone(),
                    padding: self.padding.clone(),
                    upload_queue: SeqChunker::new(cs, max_buffered),
                    last_post_time: None,
                    min_post_interval,
                    obf_chain: build_obfuscation_chain(&self.config),
                }))
            },
            XhttpMode::Auto => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Auto mode should be resolved",
            )),
        }
    }

    async fn downlink(&mut self) -> io::Result<Box<dyn DownlinkReader>> {
        // Delegate to H3 session if in H3 mode
        if let Some(ref mut h3) = self.h3_session {
            return h3.downlink().await;
        }
        match self.mode {
            XhttpMode::StreamOne => {
                // Stream-one: return a lazy reader that awaits the response
                // on first read(). This avoids blocking downlink() while the
                // request body is still being sent - critical for HTTP/1.1
                // where the server won't respond until it receives body data.
                let response_rx = self.response_rx.take().ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "uplink() must be called first",
                    )
                })?;
                Ok(Box::new(StreamDownlinkReader {
                    response_rx: Some(response_rx),
                    response_fut: None,
                    body: None,
                    read_buf: Vec::new(),
                    padding: self.padding.clone(),
                    obf_chain: build_obfuscation_chain(&self.config),
                    reconnect: None,
                }))
            },
            XhttpMode::StreamUp | XhttpMode::PacketUp => {
                // Stream-up / packet-up: send a separate GET request
                // In asymmetric mode, use the dedicated downlink connection if available
                let (_empty_tx, empty_body) = make_stream_body(1);
                // _empty_tx dropped -> empty body = immediate end-of-body
                let request = self.build_request("GET", None, empty_body)?;

                let send_req =
                    if let Some(ref mut dl_req) = self.downlink_send_req {
                        dl_req
                    } else {
                        self.send_req.as_mut().ok_or_else(|| {
                            io::Error::new(
                                io::ErrorKind::NotConnected,
                                "session closed",
                            )
                        })?
                    };

                let response =
                    send_req.send_request(request).await.map_err(|e| {
                        io::Error::new(io::ErrorKind::ConnectionReset, e)
                    })?;

                if let Some(pad) = &self.padding {
                    if !pad.validate_response(response.headers()) {
                        log::warn!("xhttp: response XPadding validation failed");
                    }
                }

                // Extract a cloneable H2 send-request for downlink reconnection.
                // H1 connections cannot be cloned; reconnect is H2-only.
                let reconnect = match send_req {
                    HttpSendRequest::H2(h2_sr) => {
                        let max_age = self
                            .config
                            .throttle
                            .stream_up_server_secs
                            .as_ref()
                            .map(|r| {
                                std::time::Duration::from_secs(r.rand_u64())
                            });
                        Some(DownlinkReconnect {
                            send_req: h2_sr.clone(),
                            config: self.config.clone(),
                            session_id: self.session_id.clone(),
                            placement: self.placement.clone(),
                            padding: self.padding.clone(),
                            policy: ReconnectPolicy::new(max_age),
                        })
                    },
                    HttpSendRequest::H1(_) => None,
                };

                Ok(Box::new(StreamDownlinkReader {
                    response_rx: None,
                    response_fut: None,
                    body: Some(response.into_body()),
                    read_buf: Vec::new(),
                    padding: None,
                    obf_chain: build_obfuscation_chain(&self.config),
                    reconnect,
                }))
            },
            XhttpMode::Auto => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Auto mode should be resolved",
            )),
        }
    }

    async fn close(&mut self) -> io::Result<()> {
        // Close H3 session if present
        if let Some(mut h3) = self.h3_session.take() {
            h3.close().await?;
        }
        self.send_req.take();
        self.downlink_send_req.take();
        self.response_rx = None;
        Ok(())
    }

    fn kind(&self) -> &'static str {
        if self.h3_session.is_some() {
            "xhttp-h3"
        } else {
            "xhttp"
        }
    }
}

// ---------------------------------------------------------------------------
// StreamUplinkWriter
// ---------------------------------------------------------------------------

/// Writes uplink data to the POST request body via a channel.
pub struct StreamUplinkWriter {
    body_tx: Option<mpsc::Sender<Result<Frame<Bytes>, io::Error>>>,
    /// Optional obfuscation chain for pre_send processing.
    obf_chain: Option<ObfuscationChain>,
    /// Whether the next write is the first write (for ObfContext.is_first).
    is_first_write: bool,
}

#[async_trait]
impl UplinkWriter for StreamUplinkWriter {
    async fn write(&mut self, data: &[u8]) -> io::Result<()> {
        let tx = self.body_tx.as_ref().ok_or_else(|| {
            io::Error::new(io::ErrorKind::BrokenPipe, "uplink already shut down")
        })?;

        // Apply obfuscation chain if present
        let payload = if let Some(ref mut chain) = self.obf_chain {
            let ctx = ObfContext {
                request_url: None,
                is_first: self.is_first_write,
                seq: None,
                response_headers: None,
            };
            self.is_first_write = false;
            chain.pre_send(data, &ctx).await?
        } else {
            data.to_vec()
        };

        tx.send(Ok(Frame::data(Bytes::from(payload))))
            .await
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::ConnectionReset,
                    "body channel closed",
                )
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
    response_rx: Option<
        tokio::sync::oneshot::Receiver<
            Result<hyper::Response<hyper::body::Incoming>, hyper::Error>,
        >,
    >,
    /// Cached response future for cancel-safe lazy init.
    response_fut: Option<
        Pin<Box<dyn Future<Output = io::Result<hyper::body::Incoming>> + Send>>,
    >,
    body: Option<hyper::body::Incoming>,
    read_buf: Vec<u8>,
    padding: Option<XPaddingMiddleware>,
    /// Optional obfuscation chain for post_recv processing.
    obf_chain: Option<ObfuscationChain>,
    /// Reconnection info for stream-up / packet-up downlink.
    /// When present, the reader re-issues the GET on EOF or timeout.
    reconnect: Option<DownlinkReconnect>,
}

/// State needed to re-issue the downlink GET in stream-up / packet-up mode.
struct DownlinkReconnect {
    send_req: H2SendRequest,
    config: Arc<XhttpConfig>,
    session_id: String,
    placement: PlacementConfig,
    padding: Option<XPaddingMiddleware>,
    /// Reconnection timing policy (from stream_up_server_secs).
    policy: ReconnectPolicy,
}

impl StreamDownlinkReader {
    /// Re-issue the downlink GET and replace the current body.
    async fn reissue_get(&mut self) -> io::Result<()> {
        let reconnect = self.reconnect.as_mut().ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotConnected, "no reconnect info")
        })?;

        // Build the same GET request as the original downlink.
        let (path, extra_headers) = reconnect.placement.build_request_meta(
            &reconnect.config.path,
            &reconnect.session_id,
            None,
        );

        // Apply padding to the request path.
        let mut pad_path = path;
        let mut pad_headers = Vec::new();
        if let Some(pad) = &reconnect.padding {
            pad.apply_to_request_mut(&mut pad_path, &mut pad_headers);
        }

        let mut builder = http::Request::builder()
            .method("GET")
            .uri(&pad_path)
            .header("Host", &reconnect.config.host);

        for (k, v) in &reconnect.config.headers {
            builder = builder.header(k, v);
        }
        for (k, v) in &extra_headers {
            builder = builder.header(k, v);
        }
        if !reconnect.config.no_grpc_header {
            builder = builder.header("Content-Type", "application/grpc");
        }
        for (k, v) in pad_headers {
            builder = builder.header(k, v);
        }

        let (_empty_tx, empty_body) = make_stream_body(1);
        let request = builder
            .body(empty_body)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;

        let response = reconnect
            .send_req
            .send_request(request)
            .await
            .map_err(|e| io::Error::new(io::ErrorKind::ConnectionReset, e))?;

        if let Some(pad) = &reconnect.padding {
            if !pad.validate_response(response.headers()) {
                log::warn!(
                    "xhttp: response XPadding validation failed on reconnect"
                );
            }
        }

        log::debug!(
            "xhttp: downlink GET re-issued for session {}",
            reconnect.session_id
        );
        reconnect.policy.reset();
        self.body = Some(response.into_body());
        Ok(())
    }
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

        // Lazy init: await response on first read (cancel-safe via cached future)
        if self.body.is_none() && self.response_fut.is_none() {
            let response_rx = self.response_rx.take().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::ConnectionReset,
                    "no response available",
                )
            })?;
            let padding = self.padding.clone();
            self.response_fut = Some(Box::pin(async move {
                let response = response_rx
                    .await
                    .map_err(|_| {
                        io::Error::new(
                            io::ErrorKind::ConnectionReset,
                            "response task dropped",
                        )
                    })?
                    .map_err(|e| {
                        io::Error::new(io::ErrorKind::ConnectionReset, e)
                    })?;
                log::debug!("xhttp: response status={}", response.status());
                if let Some(pad) = &padding {
                    if !pad.validate_response(response.headers()) {
                        log::warn!("xhttp: response XPadding validation failed");
                    }
                }
                Ok(response.into_body())
            }));
        }

        if let Some(fut) = self.response_fut.as_mut() {
            let body = fut.as_mut().await?;
            self.body = Some(body);
            self.response_fut = None;
        }

        loop {
            // Take the body out temporarily to avoid borrow conflicts
            // with reissue_get() (which needs &mut self).
            let mut body = match self.body.take() {
                Some(b) => b,
                None => {
                    return Err(io::Error::new(
                        io::ErrorKind::ConnectionReset,
                        "no body",
                    ));
                },
            };

            // Check stream_up_server_secs: force reconnect if the current
            // GET has been open longer than the configured server duration.
            if let Some(reconnect) = &self.reconnect {
                if reconnect.policy.should_reconnect() {
                    log::debug!(
                        "xhttp: downlink GET exceeded stream_up_server_secs, reconnecting"
                    );
                    self.body = Some(body);
                    self.reissue_get().await?;
                    continue;
                }
            }

            match body.frame().await {
                None => {
                    // EOF - if we have reconnect info (stream-up / packet-up),
                    // re-issue the GET and continue reading.
                    self.body = Some(body);
                    if self.reconnect.is_some() {
                        self.reissue_get().await?;
                        continue;
                    }
                    return Ok(0); // true EOF for stream-one
                },
                Some(Ok(frame)) => {
                    self.body = Some(body);
                    if let Some(data) = frame.data_ref() {
                        // Apply post_recv obfuscation chain if present
                        let processed =
                            if let Some(ref mut chain) = self.obf_chain {
                                let ctx = ObfContext {
                                    request_url: None,
                                    is_first: false,
                                    seq: None,
                                    response_headers: None,
                                };
                                chain.post_recv(data, &ctx).await?
                            } else {
                                data.to_vec()
                            };

                        let n = std::cmp::min(processed.len(), buf.len());
                        buf[..n].copy_from_slice(&processed[..n]);
                        if processed.len() > n {
                            self.read_buf.extend_from_slice(&processed[n..]);
                        }
                        return Ok(n);
                    }
                    // Skip trailer frames
                },
                Some(Err(e)) => {
                    self.body = Some(body);
                    return Err(io::Error::new(
                        io::ErrorKind::ConnectionReset,
                        e,
                    ));
                },
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
    upload_queue: SeqChunker,
    /// Last time a POST was sent, for throttling.
    last_post_time: Option<tokio::time::Instant>,
    /// Minimum interval between POSTs (from ThrottleConfig.min_posts_interval_ms).
    min_post_interval: Option<std::time::Duration>,
    /// Optional obfuscation chain for pre_send processing.
    obf_chain: Option<ObfuscationChain>,
}

impl PacketUplinkWriter {
    /// Send a single chunk as a POST with `?seq=<seq>`.
    ///
    /// If `min_post_interval` is set and the elapsed time since the last
    /// POST is less than the interval, this method sleeps for the
    /// remaining duration before sending.
    async fn send_packet(&mut self, seq: u64, data: Vec<u8>) -> io::Result<()> {
        // Throttle: enforce minimum interval between POSTs
        if let Some(interval) = self.min_post_interval {
            if let Some(last) = self.last_post_time {
                let elapsed = last.elapsed();
                if elapsed < interval {
                    tokio::time::sleep(interval - elapsed).await;
                }
            }
        }

        // Apply obfuscation chain if present
        let data = if let Some(ref mut chain) = self.obf_chain {
            let ctx = ObfContext {
                request_url: None,
                is_first: seq == 0,
                seq: Some(seq),
                response_headers: None,
            };
            chain.pre_send(&data, &ctx).await?
        } else {
            data
        };

        // Build POST request with seq in URL
        let (path, extra_headers) = self.placement.build_request_meta(
            &self.config.path,
            &self.session_id,
            Some(seq),
        );

        let method_str = match self.config.uplink.method {
            config::HttpMethod::Post => "POST",
            config::HttpMethod::Get => "GET",
        };

        // Apply padding before setting URI so Query placement can modify the URL
        let mut pad_path = path;
        let mut pad_headers = Vec::new();
        if let Some(pad) = &self.padding {
            pad.apply_to_request_mut(&mut pad_path, &mut pad_headers);
        }

        let mut builder = http::Request::builder()
            .method(method_str)
            .uri(&pad_path)
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
        // Note: no_sse_header controls the server-side SSE response header
        // (Content-Type: text/event-stream), not a client request header.
        for (k, v) in pad_headers {
            builder = builder.header(k, v);
        }

        // Data placement: decide where to put the uplink data based on config.
        // Auto/Body -> POST body; Header -> base64 in X-Data header;
        // Cookie -> base64+urlencoded in Cookie header.
        let body: ReqBody = match self.config.uplink.data_placement {
            UplinkDataPlacement::Auto | UplinkDataPlacement::Body => {
                let (body_tx, body) = make_stream_body(1);
                let _ = body_tx.send(Ok(Frame::data(Bytes::from(data)))).await;
                drop(body_tx);
                body
            },
            UplinkDataPlacement::Header => {
                let key = if self.config.uplink.data_key.is_empty() {
                    "X-Data"
                } else {
                    &self.config.uplink.data_key
                };
                let encoded =
                    base64::engine::general_purpose::STANDARD.encode(&data);
                const MAX_HEADER_CHUNK: usize = 8 * 1024;
                if encoded.len() <= MAX_HEADER_CHUNK {
                    builder = builder.header(key, &encoded);
                } else {
                    for (i, chunk) in
                        encoded.as_bytes().chunks(MAX_HEADER_CHUNK).enumerate()
                    {
                        let header_name = format!("{}-{}", key, i);
                        let val = std::str::from_utf8(chunk).unwrap_or("");
                        builder = builder.header(header_name, val);
                    }
                }
                let (_, body) = make_stream_body(1);
                body
            },
            UplinkDataPlacement::Cookie => {
                let key = if self.config.uplink.data_key.is_empty() {
                    "data"
                } else {
                    &self.config.uplink.data_key
                };
                let encoded =
                    base64::engine::general_purpose::STANDARD.encode(&data);
                let cookie_value = urlencoding::encode(&encoded);
                builder =
                    builder.header("Cookie", format!("{}={}", key, cookie_value));
                let (_, body) = make_stream_body(1);
                body
            },
        };

        let request = builder
            .body(body)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;

        let response_future = self.send_req.send_request(request);

        // Drain response (not used for uplink)
        tokio::spawn(async move {
            if let Ok(resp) = response_future.await {
                let _ = http_body_util::BodyExt::collect(resp.into_body()).await;
            }
        });

        // Record the time of this POST for throttling
        self.last_post_time = Some(tokio::time::Instant::now());

        Ok(())
    }
}

#[async_trait]
impl UplinkWriter for PacketUplinkWriter {
    async fn write(&mut self, data: &[u8]) -> io::Result<()> {
        let chunks = self.upload_queue.push(data)?;
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
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                "DNS resolution failed",
            )
        })
}

/// Merge per-direction overrides from `XhttpDirectionConfig` into a base `XhttpConfig`.
///
/// Only fields that are `Some` in the direction config are overridden;
/// all others are inherited from the base config. This allows asymmetric
/// mode to use different servers/ports/paths for uplink and downlink
/// while sharing the rest of the configuration (TLS, padding, throttling, etc.).
fn merge_direction_config(
    base: &XhttpConfig, direction: Option<&XhttpDirectionConfig>,
) -> Arc<XhttpConfig> {
    let mut merged = base.clone();
    if let Some(dir) = direction {
        if let Some(ref server) = dir.server {
            merged.host = server.clone();
        }
        if let Some(port) = dir.port {
            merged.port = port;
        }
        if let Some(ref path) = dir.path {
            merged.path = path.clone();
        }
        if let Some(ref tls_server) = dir.tls_server {
            merged.host = tls_server.clone();
        }
        if let Some(ref headers) = dir.headers {
            merged.headers = headers.clone();
        }
        if let Some(hv) = dir.http_version {
            merged.http_version = hv;
        }
    }
    Arc::new(merged)
}

// ---------------------------------------------------------------------------
// Integration tests
// ---------------------------------------------------------------------------
