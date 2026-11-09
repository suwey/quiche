// SPDX-License-Identifier: BSD-2-Clause
// Copyright © The anywhere project contributors.

//! Mless outbound — VLESS over multiplexed WebSocket (Hermes protocol).

use std::sync::Arc;
use std::sync::Weak;
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use std::time::Instant;

use async_trait::async_trait;
use tokio::sync::Notify;
use tokio::sync::mpsc;

use crate::config::OutboundConfig;
use crate::connection::ConnectionManager;
use crate::crypto::CryptoFactory;
use crate::inbound::Destination;
use crate::outbound::OutboundClient;
use crate::outbound::common::resolve_sni;
use crate::outbound::direct::DirectOutboundClient;
use crate::outbound::vless::parse_uuid;
use crate::relay::PacketRelay;
use crate::relay::StreamRelay;

use self::frame::FLAG_FIRST;
use self::multiplexer::MlessMessage;
use self::multiplexer::MlessMultiplexer;
use self::multiplexer::MuxPoolWiring;
use self::multiplexer::PoolRetireGate;
use self::multiplexer::MlessStreamHandle;
use self::vless::build_vless_header;

pub mod crypto;
pub mod frame;
pub mod multiplexer;
pub mod vless;

/// Mless outbound client.
///
/// M4: Uses pluggable `ConnectionManager` + `CryptoFactory` instead of
/// raw connection parameters. Supports both WS and XHTTP transports.
///
/// When `pool_size > 1`, multiple `MlessMultiplexer` instances are created,
/// each with its own WebSocket connection and independent crypto counters.
/// Streams are distributed round-robin across the pool, multiplying TCP
/// throughput and eliminating the single-connection bottleneck.
pub struct MlessOutboundClient {
    /// Pool of multiplexers. Each entry is `(multiplexer, consecutive_fails)`.
    /// A pool of size 1 is equivalent to the old single-multiplexer behavior.
    pool: tokio::sync::Mutex<Vec<MuxSlot>>,
    /// Round-robin index for stream distribution.
    next: AtomicUsize,
    /// Pool size (cached for reconnection logic).
    pool_size: usize,
    /// Pool-side wiring shared by every slot: stream capacity, retire gate,
    /// and the pool-wide death signal.
    wiring: MuxPoolWiring,
    uuid: [u8; 16],
    uuid_str: String,
    /// Pluggable crypto factory (shared; each slot creates its own instance).
    crypto_factory: Arc<dyn CryptoFactory>,
    /// Direct outbound used for UDP ports that mless can't tunnel (e.g. NTP).
    direct_fallback: DirectOutboundClient,
}

/// One slot in the mless connection pool.
struct MuxSlot {
    mux: Arc<MlessMultiplexer>,
    consecutive_fails: AtomicU32,
    /// Per-slot connection manager: each slot reconnects independently, so a
    /// dead slot's handshake doesn't block the others.
    conn_mgr: Arc<dyn ConnectionManager>,
}

/// Longest a dial waits inside `open_stream` for the pool to yield a live
/// slot — covering both "a reconnect is in flight" and "pool at stream
/// capacity". Bounds the 2026-11-07 failure mode where leaked
/// `reconnecting` claims kept every dial spinning on the 200 ms poll with
/// no timeout, no log and no recovery until the process was restarted.
const OPEN_STREAM_MAX_WAIT: std::time::Duration =
    std::time::Duration::from_secs(30);

/// A `reconnecting` claim legitimately spans at most one 30 s backoff plus
/// one bounded connect (`TCP_CONNECT_TIMEOUT` = 5 s plus the TLS/WS
/// upgrade), so a claim older than this means the flag leaked anyway — the
/// keepalive force-releases it before the pool wedges permanently.
const RECONNECT_STUCK_AFTER: std::time::Duration =
    std::time::Duration::from_secs(120);

/// Owes the release of one `reconnecting` claim.
///
/// `claim_dead_slot` flips the slot's `reconnecting` flag with `swap(true)`,
/// and the flag used to be cleared only when `reconnect_slot` finished. But
/// `reconnect_slot` is awaited inline inside arbitrary caller tasks —
/// urltest probes wrap `dial` in a 5 s timeout, relay tasks are dropped on
/// client disconnect — so any cancellation between claim and completion
/// leaked `reconnecting == true` forever. The slot became unclaimable, and
/// once every slot had been wedged that way, dials hung with no error and
/// no log: the 2026-11-07 outage (five probe timeouts wedged all five
/// slots between 16:11 and 16:21; proxy dead until the 00:16 restart) is
/// exactly this chain. Dropping the guard — on completion, on failure, or
/// on cancellation — always releases the flag.
struct ReconnectGuard {
    mux: Arc<MlessMultiplexer>,
}

impl Drop for ReconnectGuard {
    fn drop(&mut self) {
        self.mux.reconnecting.store(false, Ordering::Release);
        *self.mux.reconnecting_since.lock() = None;
    }
}

impl MlessOutboundClient {
    pub async fn from_config(
        configs: Vec<&OutboundConfig>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let cfg = configs
            .into_iter()
            .next()
            .ok_or("mless: no config provided")?;
        let server =
            cfg.server.as_deref().ok_or("mless: missing server field")?;

        let tls_server = resolve_sni(cfg).map_err(|e| format!("mless: {e}"))?;
        let addr = crate::outbound::common::resolve_addr(server)
            .map_err(|e| format!("mless: {e}"))?;
        let uuid_str = cfg
            .password
            .as_deref()
            .ok_or("mless: missing password (uuid)")?;
        let uuid = parse_uuid(uuid_str)?;
        let uuid_str = uuid_str.to_string();

        // Determine pool size from [outbounds.xmux].pool_size (default: 5).
        let pool_size = cfg
            .xmux
            .as_ref()
            .and_then(|x| x.pool_size)
            .unwrap_or(5)
            .max(1);
        let max_streams = cfg
            .xmux
            .as_ref()
            .and_then(|x| x.max_concurrency.as_ref())
            .map(|range| range.rand_usize())
            .unwrap_or(0);

        // Build connection manager(s) from the nested [transport] config.
        //
        // Hermes 老版本把隧道按 DO 分片，WS 路径带 `_hslot=<slot>` 标记；
        // 现在隧道数据面已移出 DO（仅 sub/admin 的 KV 路径进 DO），
        // 服务端不再读取该参数，客户端也不再附加。
        // XHTTP 共用一个 manager（xmux 自带连接池）。
        let transport = cfg
            .transport
            .as_ref()
            .ok_or("mless: missing [transport] config")?;
        use crate::connection::SingleConnectionManager;
        use crate::transport::TransportContext;
        use crate::transport::ws::WsTransportFactory;
        let ws_ctx: Option<TransportContext> = match transport.type_.as_str() {
            "ws" => {
                let ws = transport
                    .ws
                    .as_ref()
                    .ok_or("mless: missing [transport.ws] config")?;
                let path = ws.path.clone().unwrap_or_else(|| "/".to_string());
                let mut headers = ws.headers.clone().unwrap_or_default();
                headers
                    .entry("Host".to_string())
                    .or_insert_with(|| tls_server.clone());
                Some(TransportContext {
                    server: addr.ip().to_string(),
                    port: addr.port(),
                    tls_server: tls_server.clone(),
                    insecure: cfg.insecure,
                    tls_fp: cfg.fp,
                    path,
                    headers,
                    fragment: if cfg.tls_fragment {
                        Some(cfg.tls_fragment_config.clone().unwrap_or_default())
                    } else {
                        None
                    },
                })
            },
            _ => None,
        };
        let shared_conn_mgr: Option<Arc<dyn ConnectionManager>> =
            match transport.type_.as_str() {
                "ws" => None,
                "xhttp" => {
                    use crate::transport::xhttp::config::XmuxConfig;
                    use crate::transport::xhttp::{
                        config::HttpVersionPref, xmux::XmuxConnectionManager,
                    };
                    let xc = transport
                        .xhttp
                        .as_ref()
                        .ok_or("mless: missing [transport.xhttp] config")?;
                    let mut xhttp_config = xc.clone();
                    if xhttp_config.host.is_empty() {
                        xhttp_config.host = tls_server.clone();
                    }
                    if xhttp_config.port == 0 {
                        xhttp_config.port = addr.port();
                    }
                    xhttp_config.insecure = cfg.insecure;
                    // mless requires a bidirectional streaming transport (uplink POST
                    // body + downlink response body). Force stream-one regardless of
                    // the user's mode setting, since packet-up/stream-up would break
                    // the mless frame io_loop.
                    xhttp_config.mode =
                        crate::transport::xhttp::config::XhttpMode::StreamOne;
                    // Hermes router intercepts UUID-like paths as logout
                    // (router.ts: uuidRegex.test(访问路径) -> 302 redirect).
                    // session_id is a UUID, so placing it in the path triggers
                    // a 302. Force query placement to keep the path clean.
                    xhttp_config.session_id_placement =
                        crate::transport::xhttp::config::SessionPlacement::Query;
                    let xhttp_config = Arc::new(xhttp_config);
                    let default_xmux = XmuxConfig::default();
                    let xmux_cfg = cfg.xmux.as_ref().unwrap_or(&default_xmux);
                    Some(
                        if xhttp_config.http_version == HttpVersionPref::Http3 {
                            use crate::transport::xhttp::h3::H3ConnectionManager;
                            Arc::new(
                                H3ConnectionManager::from_config(
                                    xhttp_config,
                                    xmux_cfg,
                                )
                                .await?,
                            )
                        } else {
                            Arc::new(
                                XmuxConnectionManager::from_config(
                                    xhttp_config,
                                    xmux_cfg,
                                )
                                .await?,
                            )
                        },
                    )
                },
                other => {
                    return Err(format!(
                        "mless: unsupported transport type '{other}'"
                    )
                    .into());
                },
            };

        let build_conn_mgr = || -> Arc<dyn ConnectionManager> {
            match &ws_ctx {
                Some(ctx) => Arc::new(SingleConnectionManager::new(
                    Box::new(WsTransportFactory),
                    ctx.clone(),
                )),
                None => shared_conn_mgr
                    .clone()
                    .expect("xhttp branch built a shared conn mgr"),
            }
        };

        // Build crypto factory
        let crypto_factory: Arc<dyn CryptoFactory> =
            Arc::new(self::crypto::AheadXorFactory);

        // One pool-wide wake-up channel: any tunnel death (transport EOF,
        // involuntary retirement) notifies the keepalive task immediately.
        let wiring = MuxPoolWiring {
            max_streams,
            capacity_notify: Arc::new(Notify::new()),
            pool_gate: PoolRetireGate::new(),
            disconnect_signal: Arc::new(Notify::new()),
        };

        // Connect all multiplexer instances in the pool concurrently.
        // Each slot does its own TCP+TLS+WS (or XHTTP stream) handshake with
        // its own independent crypto state, so there is no ordering
        // dependency between them: serializing them costs one full round trip
        // per slot (~2s each in the field) before any traffic is proxied.
        // `try_join_all` preserves slot order — the round-robin index `next`
        // indexes into this Vec — and propagates the first error, so any slot
        // failing still fails construction as before.
        let muxes = futures_util::future::try_join_all(
            (0..pool_size).map(|i| {
                let conn_mgr = build_conn_mgr();
                let crypto_factory = crypto_factory.clone();
                let wiring = wiring.clone();
                let uuid_str = uuid_str.clone();
                let slot = i + 1;
                async move {
                    let mux = MlessMultiplexer::connect_pluggable(
                        conn_mgr,
                        crypto_factory,
                        &uuid_str,
                        wiring,
                        slot,
                    )
                    .await
                    // `Box<dyn Error>` is not `Send`, and that would make this
                    // future non-Send — which only bites on Android, where the
                    // engine is spawned on a multi-thread runtime.
                    .map_err(|e| e.to_string())?;
                    // Completion lines may interleave now that the slots
                    // connect in parallel; the slot number is what matters.
                    if pool_size > 1 {
                        log::info!(
                            "mless: [slot {slot}] pool connected ({slot}/{pool_size})",
                        );
                    }
                    Ok::<_, String>(mux)
                }
            }),
        )
        .await?;

        let slots: Vec<MuxSlot> = muxes
            .into_iter()
            .map(|mux| MuxSlot {
                mux,
                consecutive_fails: AtomicU32::new(0),
                conn_mgr: build_conn_mgr(),
            })
            .collect();

        Ok(Self {
            wiring,
            pool: tokio::sync::Mutex::new(slots),
            next: AtomicUsize::new(0),
            pool_size,
            uuid,
            uuid_str,
            crypto_factory,
            direct_fallback: DirectOutboundClient::default(),
        })
    }

    async fn try_register_stream(
        &self,
    ) -> Option<(Arc<MlessMultiplexer>, u64, mpsc::UnboundedReceiver<Vec<u8>>)>
    {
        let start = self.next.fetch_add(1, Ordering::Relaxed) % self.pool_size;
        let pool = self.pool.lock().await;
        for offset in 0..pool.len() {
            let slot = &pool[(start + offset) % pool.len()];
            if slot.mux.dead.load(Ordering::Relaxed) {
                continue;
            }
            if let Some((stream_id, rx)) = slot.mux.try_register_stream() {
                return Some((slot.mux.clone(), stream_id, rx));
            }
        }
        None
    }

    async fn claim_dead_slot(&self) -> (Option<(usize, ReconnectGuard)>, bool) {
        let pool = self.pool.lock().await;
        let mut has_reconnecting = false;
        for (idx, slot) in pool.iter().enumerate() {
            if !slot.mux.dead.load(Ordering::Relaxed) {
                continue;
            }
            if slot.mux.reconnecting.load(Ordering::Acquire) {
                has_reconnecting = true;
                continue;
            }
            if !slot.mux.reconnecting.swap(true, Ordering::Acquire) {
                *slot.mux.reconnecting_since.lock() = Some(Instant::now());
                let guard = ReconnectGuard {
                    mux: Arc::clone(&slot.mux),
                };
                return (Some((idx, guard)), has_reconnecting);
            }
            has_reconnecting = true;
        }
        (None, has_reconnecting)
    }

    async fn reconnect_slot(&self, idx: usize) -> Option<Arc<MlessMultiplexer>> {
        let (fails, conn_mgr, claimed_mux) = {
            let pool = self.pool.lock().await;
            let slot = &pool[idx];
            (
                slot.consecutive_fails.fetch_add(1, Ordering::Relaxed),
                slot.conn_mgr.clone(),
                Arc::clone(&slot.mux),
            )
        };
        let delay_secs = (2u64).pow(fails.min(5)).min(30);
        let slot = idx + 1;
        log::info!(
            "{}: [slot {slot}] pool reconnecting... (attempt {}, backoff {}s)",
            self.log_tag(),
            fails + 1,
            delay_secs,
        );
        tokio::time::sleep(std::time::Duration::from_secs(delay_secs)).await;

        let result = MlessMultiplexer::connect_pluggable(
            conn_mgr,
            self.crypto_factory.clone(),
            &self.uuid_str,
            self.wiring.clone(),
            slot,
        )
        .await;

        // Extract the result before locking the pool to avoid holding
        // a non-Send `Box<dyn StdError>` across an await boundary.
        let new_mux = result.ok();

        let mut pool = self.pool.lock().await;
        // Install only if the slot still holds the mux this reconnect was
        // claimed against: a stale claim (force-released by the keepalive
        // stuck-claim watchdog, then re-claimed) must not clobber a newer
        // tunnel with an older one.
        if !Arc::ptr_eq(&pool[idx].mux, &claimed_mux) {
            log::debug!(
                "{}: [slot {slot}] reconnect attempt stale, slot already revived",
                self.log_tag(),
            );
            return None;
        }
        match new_mux {
            Some(new_mux) => {
                pool[idx].consecutive_fails.store(0, Ordering::Relaxed);
                pool[idx].mux = new_mux.clone();
                drop(pool);
                log::info!(
                    "{}: [slot {slot}] pool reconnected",
                    self.log_tag()
                );
                Some(new_mux)
            },
            None => {
                log::warn!(
                    "{}: [slot {slot}] pool reconnect failed",
                    self.log_tag()
                );
                None
            },
        }
    }

    /// Spawns the pool keepalive task: wakes on any tunnel-death signal and
    /// additionally sweeps every 10 s as a backstop.
    ///
    /// Without it a dead slot is only reconnected when `open_stream` finds no
    /// live slot left, and because `max_streams` defaults to unlimited a
    /// single surviving connection always has capacity — so a pool that lost
    /// 4 of 5 connections kept serving everything off the last one, head-of-
    /// line blocking every stream on one tunnel.
    ///
    /// Goes through `claim_dead_slot`, so it cannot double-reconnect a slot
    /// the dial path is already reviving, and `reconnect_slot` keeps its
    /// exponential backoff when the server itself is down.
    pub fn spawn_pool_keepalive(
        client: Arc<Self>,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            loop {
                // Event-driven wake (transport EOF / tunnel retirement) with
                // the 10 s sweep as a backstop for any missed signal.
                tokio::select! {
                    _ = tokio::time::sleep(
                        std::time::Duration::from_secs(10),
                    ) => {},
                    _ = client.wiring.disconnect_signal.notified() => {},
                }
                // Defense in depth: the claim guard makes a leaked
                // `reconnecting` flag unreachable, but if some future change
                // breaks that invariant the pool would wedge exactly like
                // the 2026-11-07 outage. Force-release any claim older than
                // `RECONNECT_STUCK_AFTER` instead of letting the slot stay
                // unclaimable forever.
                {
                    let pool = client.pool.lock().await;
                    for (idx, slot) in pool.iter().enumerate() {
                        if !slot.mux.reconnecting.load(Ordering::Acquire) {
                            continue;
                        }
                        let Some(since) = *slot.mux.reconnecting_since.lock()
                        else {
                            continue;
                        };
                        let held = since.elapsed();
                        if held < RECONNECT_STUCK_AFTER {
                            continue;
                        }
                        log::warn!(
                            "{}: [slot {}] reconnecting claim held for {held:?}, force-releasing (stuck claim?)",
                            client.log_tag(),
                            idx + 1,
                        );
                        slot.mux.reconnecting.store(false, Ordering::Release);
                        *slot.mux.reconnecting_since.lock() = None;
                    }
                }
                let mut dead: Vec<(usize, ReconnectGuard)> = Vec::new();
                while dead.len() < client.pool_size {
                    match client.claim_dead_slot().await.0 {
                        Some(claimed) => dead.push(claimed),
                        None => break,
                    }
                }
                // Revive concurrently and at staggered times: a peer that
                // recycles tunnels kills several slots at once, and a serial
                // loop left the last slot down for ~20 s. The jitter also
                // stops the replacements from sharing a birth time, which is
                // what made them all get recycled together again.
                futures_util::future::join_all(dead.into_iter().map(
                    |(idx, guard)| {
                        let client = Arc::clone(&client);
                        async move {
                            // The claim guard rides with this future: whether
                            // the reconnect completes, fails, or the whole
                            // task is torn down, the flag is released exactly
                            // once.
                            let _guard = guard;
                            let jitter =
                                crate::obfuscation::range::rand_range(0, 4_000);
                            tokio::time::sleep(
                                std::time::Duration::from_millis(
                                    jitter as u64,
                                ),
                            )
                            .await;
                            client.reconnect_slot(idx).await;
                        }
                    },
                ))
                .await;
            }
        })
    }

    async fn open_stream(
        &self,
    ) -> Result<
        (Arc<MlessMultiplexer>, u64, mpsc::UnboundedReceiver<Vec<u8>>),
        Box<dyn std::error::Error>,
    > {
        // Every wait below is bounded by one shared deadline: a dial may
        // wait for a reconnect or for stream capacity, but never forever.
        let deadline = tokio::time::Instant::now() + OPEN_STREAM_MAX_WAIT;
        loop {
            if let Some(stream) = self.try_register_stream().await {
                return Ok(stream);
            }

            let (claimed, has_reconnecting) = self.claim_dead_slot().await;
            if let Some((idx, guard)) = claimed {
                let mux = self
                    .reconnect_slot(idx)
                    .await
                    .ok_or("mless: connection unavailable")?;
                drop(guard);
                if let Some((stream_id, rx)) = mux.try_register_stream() {
                    return Ok((mux, stream_id, rx));
                }
                continue;
            }
            if has_reconnecting {
                if tokio::time::Instant::now() >= deadline {
                    log::warn!(
                        "mless: dial gave up after {OPEN_STREAM_MAX_WAIT:?}: pool reconnect still in flight"
                    );
                    return Err(
                        "mless: connection unavailable (reconnect still in progress)"
                            .into(),
                    );
                }
                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                continue;
            }

            let notified = self.wiring.capacity_notify.notified();
            tokio::pin!(notified);
            if let Some(stream) = self.try_register_stream().await {
                return Ok(stream);
            }
            tokio::select! {
                _ = &mut notified => {},
                _ = tokio::time::sleep_until(deadline) => {
                    log::warn!(
                        "mless: dial gave up after {OPEN_STREAM_MAX_WAIT:?}: pool at stream capacity"
                    );
                    return Err(
                        "mless: connection unavailable (pool at stream capacity)"
                            .into(),
                    );
                },
            }
        }
    }

    fn log_tag(&self) -> String {
        format!(
            "mless/{:02x}{:02x}{:02x}{:02x}",
            self.uuid[0], self.uuid[1], self.uuid[2], self.uuid[3]
        )
    }
}

#[async_trait]
impl OutboundClient for MlessOutboundClient {
    async fn dial(
        &self, dest: &Destination,
    ) -> Result<Box<dyn StreamRelay>, Box<dyn std::error::Error>> {
        let (mux, stream_id, rx) = self.open_stream().await?;
        let vless_header = build_vless_header(&self.uuid, dest, false);
        log::debug!(
            "{}: [slot {}] dial tcp {dest} -> stream#{stream_id}",
            self.log_tag(),
            mux.slot
        );
        Ok(Box::new(MlessStreamRelay {
            slot: mux.slot,
            stream_id,
            rx,
            multiplexer: Arc::downgrade(&mux),
            first_write: true,
            vless_header,
            read_buf: Vec::new(),
            read_pos: 0,
            ever_received: false,
            pending_vless_response: true,
            vless_resp_prefix: Vec::new(),
        }))
    }

    async fn dial_udp(
        &self, dest: &Destination,
    ) -> Result<Box<dyn PacketRelay>, Box<dyn std::error::Error>> {
        // Port-based UDP policy. Hermes server only forwards DNS (port 53)
        // because Cloudflare Workers has no outbound UDP socket API; DNS
        // works via the TCP fallback defined in RFC 7766.
        //
        // - 53 (DNS):       go through mless → hermes → TCP-53 upstream
        // - 443 (QUIC):     reject. Browsers retry over TCP automatically;
        //                   pretending to succeed would only stall HTTP/3.
        // - 123 (NTP), 5353 (mDNS), 137-139 (NetBIOS), 67/68 (DHCP):
        //                   direct. These talk to local/time services that
        //                   don't need proxying.
        // - Anything else:  reject (consistent with prior behavior).
        match dest.port {
            53 => {
                let (mux, stream_id, rx) = self.open_stream().await?;
                let header = build_vless_header(&self.uuid, dest, true);
                log::debug!(
                    "{}: [slot {}] dial udp {dest} -> stream#{stream_id}",
                    self.log_tag(),
                    mux.slot
                );
                Ok(Box::new(MlessPacketRelay {
                    handle: MlessStreamHandle {
                        stream_id,
                        rx,
                        multiplexer: Arc::downgrade(&mux),
                    },
                    vless_header: header,
                    first_write: true,
                }))
            },
            443 => {
                // QUIC: fail fast so the browser falls back to TCP/HTTP-2.
                log::debug!(
                    "{}: rejecting udp/443 (QUIC) — browser will fall back to TCP",
                    self.log_tag(),
                );
                Err(crate::outbound::common::ERR_UDP_NOT_SUPPORTED.into())
            },
            123 | 5353 | 137 | 138 | 139 | 67 | 68 => {
                log::debug!(
                    "{}: udp/{} -> direct (local/time service)",
                    self.log_tag(),
                    dest.port,
                );
                self.direct_fallback.dial_udp(dest).await
            },
            _ => Err(crate::outbound::common::ERR_UDP_NOT_SUPPORTED.into()),
        }
    }
}
/// TCP stream relay backed by a Mless multiplexed stream.
///
/// The first `write()` sends a combined FIRST+DATA frame so the server
/// has the TLS ClientHello to forward immediately after connecting.
///
/// Reads are internally buffered so callers see a byte-stream interface
/// regardless of how data arrives in channel messages.
///
/// The server prepends a 2-byte VLESS response header `[version, addon_len]`
/// to the first data frame. We must consume and discard it before returning
/// payload bytes to the caller.
pub struct MlessStreamRelay {
    /// Pool slot of the tunnel carrying this stream, for log attribution.
    slot: usize,
    stream_id: u64,
    rx: mpsc::UnboundedReceiver<Vec<u8>>,
    multiplexer: Weak<MlessMultiplexer>,
    first_write: bool,
    vless_header: Vec<u8>,
    read_buf: Vec<u8>,
    read_pos: usize,
    ever_received: bool,
    /// Whether we still need to skip the 2-byte VLESS response header
    /// from the first received data chunk.
    pending_vless_response: bool,
    /// Partial buffer for accumulating the 2-byte VLESS response header
    /// when it arrives split across chunks.
    vless_resp_prefix: Vec<u8>,
}

#[async_trait]
impl StreamRelay for MlessStreamRelay {
    async fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.read_pos >= self.read_buf.len() {
            // Two timeouts:
            // - First byte (`ever_received=false`): 30s. CF Worker cold
            //   start / concurrency limits can delay first response by
            //   10-40s. 30s balances patience vs. leaking stale streams.
            // - Subsequent reads (`ever_received=true`): 300s. This is an
            //   idle period in an established TLS stream (HTTP keep-alive,
            //   HTTP/2 PING gap, WebSocket idle, etc.). Hermes side has a
            //   120s session-wide idle timer that resets on any stream
            //   activity, so 300s here covers browser pool retention even
            //   for the single-stream-on-a-WS edge case.
            let read_timeout = if self.ever_received {
                std::time::Duration::from_secs(300)
            } else {
                std::time::Duration::from_secs(30)
            };
            // The VLESS 2-byte response header may arrive as its own frame
            // (or split across frames), leaving no payload. Keep reading
            // instead of reporting a false EOF.
            loop {
                match tokio::time::timeout(read_timeout, self.rx.recv()).await {
                    Ok(Some(data)) => {
                        self.ever_received = true;
                        let mut data = data;
                        // Strip the 2-byte VLESS response header
                        // [version, addon_len] from the first data chunk(s).
                        if self.pending_vless_response {
                            let needed = 2 - self.vless_resp_prefix.len();
                            if data.len() < needed {
                                // Not enough bytes yet; buffer and wait for
                                // more.
                                self.vless_resp_prefix.extend_from_slice(&data);
                                continue;
                            }
                            // Consume the remaining header bytes.
                            let header_rest = &data[..needed];
                            self.vless_resp_prefix.extend_from_slice(header_rest);
                            let header = &self.vless_resp_prefix;
                            log::debug!(
                                "mless: [slot {}] stream#{} vless response head={:02x?}",
                                self.slot,
                                self.stream_id,
                                header,
                            );
                            if header[1] != 0 {
                                return Err(std::io::Error::new(
                                    std::io::ErrorKind::InvalidData,
                                    format!(
                                        "vless response status {}",
                                        header[1]
                                    ),
                                ));
                            }
                            data = data[needed..].to_vec();
                            self.vless_resp_prefix.clear();
                            self.pending_vless_response = false;
                        }
                        if data.is_empty() {
                            // Header-only frame — the payload comes in the
                            // next frame.
                            continue;
                        }
                        self.read_buf = data;
                        self.read_pos = 0;
                        break;
                    },
                    Ok(None) => {
                        log::debug!(
                            "mless: [slot {}] stream#{} rx channel closed (server sent CLOSE or disconnected)",
                            self.slot,
                            self.stream_id,
                        );
                        return Ok(0);
                    },
                    Err(_) => {
                        log::debug!(
                            "mless: [slot {}] stream#{} timeout ({}s), closing",
                            self.slot,
                            self.stream_id,
                            if self.ever_received { 300 } else { 30 },
                        );
                        if let Some(mux) = self.multiplexer.upgrade() {
                            mux.close_stream(self.stream_id);
                        }
                        return Ok(0);
                    },
                }
            }
        }
        let available = self.read_buf.len() - self.read_pos;
        let to_copy = buf.len().min(available);
        buf[..to_copy].copy_from_slice(
            &self.read_buf[self.read_pos..self.read_pos + to_copy],
        );
        self.read_pos += to_copy;
        if self.read_pos >= self.read_buf.len() {
            self.read_buf.clear();
            self.read_pos = 0;
        }
        Ok(to_copy)
    }

    async fn write(&mut self, buf: &[u8]) -> std::io::Result<()> {
        if let Some(mux) = self.multiplexer.upgrade() {
            if self.first_write {
                // First write: send VLESS header + data as a single FIRST frame.
                let mut combined =
                    Vec::with_capacity(self.vless_header.len() + buf.len());
                combined.extend_from_slice(&self.vless_header);
                combined.extend_from_slice(buf);
                // Send plaintext - io_loop handles encryption
                let _ = mux.ws_tx.send(MlessMessage::Data {
                    stream_id: self.stream_id,
                    flags: FLAG_FIRST,
                    payload: combined,
                });
                self.first_write = false;
            } else {
                mux.send_data(self.stream_id, buf);
            }
        }
        Ok(())
    }

    async fn shutdown(&mut self) -> std::io::Result<()> {
        if let Some(mux) = self.multiplexer.upgrade() {
            mux.close_stream(self.stream_id);
        }
        Ok(())
    }
}

impl Drop for MlessStreamRelay {
    fn drop(&mut self) {
        if let Some(mux) = self.multiplexer.upgrade() {
            mux.close_stream(self.stream_id);
        }
    }
}

/// UDP packet relay backed by a Mless multiplexed stream.
pub struct MlessPacketRelay {
    handle: MlessStreamHandle,
    vless_header: Vec<u8>,
    /// First datagram still needs the VLESS header prepended; subsequent
    /// datagrams are raw payloads sent as plain DATA frames.
    first_write: bool,
}

#[async_trait]
impl PacketRelay for MlessPacketRelay {
    async fn read_packet(
        &mut self, buf: &mut [u8],
    ) -> std::io::Result<(usize, Destination)> {
        match self.handle.rx.recv().await {
            Some(data) => {
                let len = data.len().min(buf.len());
                buf[..len].copy_from_slice(&data[..len]);
                let dest = Destination {
                    address: crate::inbound::Address::Ipv4([8, 8, 4, 4]),
                    port: 53,
                    resolved_ip: None,
                };
                Ok((len, dest))
            },
            None => Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionReset,
                "mless stream closed",
            )),
        }
    }

    async fn write_packet(
        &mut self, buf: &[u8], _dest: &Destination,
    ) -> std::io::Result<()> {
        if let Some(mux) = self.handle.multiplexer.upgrade() {
            if self.first_write {
                // First datagram: bundle VLESS header + payload into a single
                // FIRST frame so the server can connect to the upstream
                // immediately.
                let mut combined =
                    Vec::with_capacity(self.vless_header.len() + buf.len());
                combined.extend_from_slice(&self.vless_header);
                combined.extend_from_slice(buf);
                // Send plaintext - io_loop handles encryption
                let _ = mux.ws_tx.send(MlessMessage::Data {
                    stream_id: self.handle.stream_id,
                    flags: FLAG_FIRST,
                    payload: combined,
                });
                self.first_write = false;
            } else {
                mux.send_data(self.handle.stream_id, buf);
            }
        }
        Ok(())
    }

    async fn close(&mut self) -> std::io::Result<()> {
        self.handle.close().await;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::connection::ConnError;
    use crate::crypto::{CryptoLayer, NoCrypto};
    use crate::transport::TransportSession;

    /// Connection manager that never yields a session; only exists so the
    /// test client can be constructed. `reconnect_slot` would fail fast
    /// against it (acquire error), which the claim tests never reach.
    struct DeadConnMgr;

    #[async_trait]
    impl ConnectionManager for DeadConnMgr {
        async fn acquire_uplink(
            &self,
        ) -> Result<Box<dyn TransportSession>, ConnError> {
            Err(ConnError::Closed)
        }

        async fn acquire_downlink(
            &self,
        ) -> Result<Box<dyn TransportSession>, ConnError> {
            Err(ConnError::Closed)
        }

        async fn release(&self, _session: Box<dyn TransportSession>) {}

        fn is_healthy(&self) -> bool {
            false
        }

        async fn shutdown(&self) {}
    }

    struct TestCryptoFactory;

    impl CryptoFactory for TestCryptoFactory {
        fn create(&self, _secret: &str) -> Box<dyn CryptoLayer> {
            Box::new(NoCrypto)
        }

        fn name(&self) -> &'static str {
            "test"
        }
    }

    fn test_client(
        slots: Vec<Arc<MlessMultiplexer>>,
    ) -> Arc<MlessOutboundClient> {
        let pool_size = slots.len();
        Arc::new(MlessOutboundClient {
            pool: tokio::sync::Mutex::new(
                slots
                    .into_iter()
                    .map(|mux| MuxSlot {
                        mux,
                        consecutive_fails: AtomicU32::new(0),
                        conn_mgr: Arc::new(DeadConnMgr),
                    })
                    .collect(),
            ),
            next: AtomicUsize::new(0),
            pool_size,
            wiring: MuxPoolWiring {
                max_streams: 0,
                capacity_notify: Arc::new(Notify::new()),
                pool_gate: PoolRetireGate::new(),
                disconnect_signal: Arc::new(Notify::new()),
            },
            uuid: [0u8; 16],
            uuid_str: String::new(),
            crypto_factory: Arc::new(TestCryptoFactory),
            direct_fallback: DirectOutboundClient::default(),
        })
    }

    fn new_relay(rx: mpsc::UnboundedReceiver<Vec<u8>>) -> MlessStreamRelay {
        MlessStreamRelay {
            slot: 1,
            stream_id: 1,
            rx,
            multiplexer: Weak::new(),
            first_write: false,
            vless_header: Vec::new(),
            read_buf: Vec::new(),
            read_pos: 0,
            ever_received: false,
            pending_vless_response: true,
            vless_resp_prefix: Vec::new(),
        }
    }

    /// The 2-byte VLESS response header arriving as its own frame must not
    /// be reported as EOF — the payload comes in the next frame.
    #[tokio::test]
    async fn standalone_response_header_is_not_eof() {
        let (tx, rx) = mpsc::unbounded_channel();
        let mut relay = new_relay(rx);
        tx.send(vec![0x00, 0x00]).unwrap();
        tx.send(vec![1, 2, 3]).unwrap();

        let mut buf = [0u8; 16];
        let n = relay.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], &[1, 2, 3]);
    }

    /// Header split across frames: no EOF in between, payload intact.
    #[tokio::test]
    async fn split_response_header_is_not_eof() {
        let (tx, rx) = mpsc::unbounded_channel();
        let mut relay = new_relay(rx);
        tx.send(vec![0x00]).unwrap();
        tx.send(vec![0x00, 0xaa, 0xbb]).unwrap();

        let mut buf = [0u8; 16];
        let n = relay.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], &[0xaa, 0xbb]);
    }

    /// After the header-only frame, EOF still surfaces correctly once the
    /// channel closes.
    #[tokio::test]
    async fn eof_after_header_only_frame_still_works() {
        let (tx, rx) = mpsc::unbounded_channel();
        let mut relay = new_relay(rx);
        tx.send(vec![0x00, 0x00]).unwrap();
        drop(tx);

        let mut buf = [0u8; 16];
        let n = relay.read(&mut buf).await.unwrap();
        assert_eq!(n, 0, "channel close must surface EOF");
    }

    /// Dropping the claim guard — on completion, failure or cancellation —
    /// must release the slot's `reconnecting` flag. This is the invariant
    /// whose absence wedged all five pool slots in the 2026-11-07 outage.
    #[tokio::test]
    async fn guard_releases_reconnecting_flag_on_drop() {
        let (mux, _ws_rx) = MlessMultiplexer::test_mux(
            1,
            0,
            PoolRetireGate::new(),
        );
        mux.dead.store(true, Ordering::Relaxed);
        let client = test_client(vec![Arc::clone(&mux)]);

        let (claimed, _) = client.claim_dead_slot().await;
        let (_, guard) = claimed.expect("dead slot must be claimable");
        assert!(mux.reconnecting.load(Ordering::Acquire));
        assert!(mux.reconnecting_since.lock().is_some());

        drop(guard);
        assert!(!mux.reconnecting.load(Ordering::Acquire));
        assert!(mux.reconnecting_since.lock().is_none());
    }

    /// A claiming task aborted mid-reconnect (a probe timeout dropping the
    /// dial, a relay task dropped on client disconnect) must leave the slot
    /// claimable again. Regression test for the 2026-11-07 outage: five
    /// probe timeouts leaked five `reconnecting` flags, every dial then
    /// spun on the 200 ms poll forever, and the proxy stayed dead until the
    /// process was restarted.
    #[tokio::test]
    async fn aborted_claimer_releases_reconnecting_flag() {
        let (mux, _ws_rx) = MlessMultiplexer::test_mux(
            1,
            0,
            PoolRetireGate::new(),
        );
        mux.dead.store(true, Ordering::Relaxed);
        let client = test_client(vec![Arc::clone(&mux)]);

        let task = tokio::spawn({
            let client = Arc::clone(&client);
            async move {
                // Claim like a dial-path reconnect would, then park —
                // standing in for the 30 s backoff a probe timeout would
                // cut short.
                let (claimed, _) = client.claim_dead_slot().await;
                let _guard = claimed.expect("dead slot claimable").1;
                futures_util::future::pending::<()>().await;
            }
        });
        for _ in 0..100 {
            if mux.reconnecting.load(Ordering::Acquire) {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        assert!(
            mux.reconnecting.load(Ordering::Acquire),
            "claim must be visible before the abort"
        );

        task.abort();
        let _ = task.await;
        assert!(
            !mux.reconnecting.load(Ordering::Acquire),
            "aborting the claiming task must release the reconnecting flag"
        );
        assert!(mux.reconnecting_since.lock().is_none());
    }
}
