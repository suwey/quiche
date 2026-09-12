use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::AtomicU64;
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
    if cfg.wss_fronts.as_ref().is_some_and(|f| !f.is_empty()) {
        if cfg.reality.is_none() {
            return Err(
                "vless: wss_fronts requires a [outbounds.reality] section — \
                 the WSS fallback tunnels the same REALITY stream through \
                 the relay-owned CDN front"
                    .to_string(),
            );
        }
        if cfg.wss_fallback.is_none() {
            return Err(
                "vless: wss_fronts requires a [outbounds.wss_fallback] section                  (broker + relay_id for ticket requests)"
                    .to_string(),
            );
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

/// Direct-path circuit breaker window. After one failed direct dial the leg
/// is skipped for this long (connectcore's recovery budget, engine.go: a
/// dead direct must not tax every dial); a success re-enables it instantly.
const DIRECT_COOLDOWN_MS: u64 = 30_000;

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
    /// Consecutive build failures — drives the replenisher's exponential
    /// backoff, so a dead/blackholed server is probed at 250ms → 8s instead
    /// of spawning a fresh 5s-timeout connect every cycle.
    fail_streak: AtomicUsize,
    /// Epoch millis before which the replenisher must not spawn new builds.
    next_build_at: AtomicU64,
    /// Set when the pool's owner (e.g. a rotated-out WSS session) is gone:
    /// stops the replenisher and on-demand builds, so a dead session's
    /// bridge port is not probed forever by orphaned tasks.
    closed: std::sync::atomic::AtomicBool,
}

/// Epoch milliseconds (wall clock; jumps are harmless for backoff).
fn epoch_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
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
            fail_streak: AtomicUsize::new(0),
            next_build_at: AtomicU64::new(0),
            closed: std::sync::atomic::AtomicBool::new(false),
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
        if self.closed.load(Ordering::Relaxed) {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "vless pool closed",
            ));
        }
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
                self.fail_streak.store(0, Ordering::Relaxed);
                self.next_build_at.store(0, Ordering::Relaxed);
                let mut ready = self.ready.lock().await;
                if ready.len() < self.water_mark {
                    ready.push_back((ws, std::time::Instant::now()));
                }
            },
            Err(e) => {
                // Exponential backoff: a dead/blackholed server must be
                // probed at 250ms → 8s, not with a fresh 5s-timeout connect
                // every replenisher cycle.
                let streak = self.fail_streak.fetch_add(1, Ordering::Relaxed) + 1;
                let backoff_ms =
                    250u64 << streak.saturating_sub(1).min(5);
                self.next_build_at.store(
                    epoch_millis() + backoff_ms,
                    Ordering::Relaxed,
                );
                log::warn!(
                    "vless pool: build failed (streak {streak}, \
                     retry in {backoff_ms}ms): {e}"
                );
            },
        }
    }

    fn spawn_build(self: &Arc<Self>) {
        if self.closed.load(Ordering::Relaxed) {
            return;
        }
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
    /// Honors the failure backoff (`next_build_at`) so a dead server is not
    /// hammered with connect attempts every cycle.
    fn spawn_replenish(self: &Arc<Self>) {
        let this = self.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_millis(250))
                    .await;
                if this.closed.load(Ordering::Relaxed) {
                    return;
                }
                if epoch_millis()
                    < this.next_build_at.load(Ordering::Relaxed)
                {
                    continue;
                }
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
//
// Direct-first WSS/CDN fallback (OpenRung): the client always tries the
// direct REALITY path first. Only after the direct transport itself failed
// (a remote path failure — exactly Go's `directPathError` gate) does it walk
// the relay's signed WSS fronts in order: request a broker ticket, dial the
// CDN front, and point the REALITY transport at a local loopback bridge that
// copies bytes into the front's multiplexing session.
pub struct VlessOutboundClient {
    /// Direct REALITY leg (always present).
    direct: Arc<VlessPool>,
    uuid: [u8; 16],
    /// VLESS flow control, sent only on TCP requests (§S2.8: servers reject
    /// UDP + flow).
    flow: Option<String>,
    /// REALITY SNI (also the bridge leg's borrow-target name).
    tls_server: String,
    insecure: bool,
    tls_fp: bool,
    /// REALITY params reused by the bridge leg (present iff the direct leg
    /// is REALITY, which wss_fronts requires).
    reality_params: Option<crate::transport::reality::RealityParams>,
    /// Fallback configuration (None unless fronts + fallback are configured).
    wss: Option<WssFallbackSetup>,
    /// The active WSS front session, once the ladder succeeded.
    active: tokio::sync::Mutex<Option<std::sync::Arc<ActiveFront>>>,
    /// Single-flight guard so concurrent dials run one ladder at a time.
    activating: tokio::sync::Mutex<()>,
    /// Direct-path circuit breaker: epoch millis until which the direct leg
    /// must not be attempted. Set on a direct failure, cleared on success —
    /// while cooling, dials fall straight through to the WSS front instead
    /// of paying the full connect timeout against a dead server.
    direct_cooldown_until: AtomicU64,
    /// Test channel: dial fronts over plain TCP against a mock front.
    #[cfg(test)]
    plain_front_dial: bool,
}

/// Static fallback configuration, validated at construction.
struct WssFallbackSetup {
    relay_id: String,
    broker: String,
    /// Canonical, sorted front set (wsscore order).
    fronts: Vec<crate::wssfront::WssFront>,
    ticket_budget: Duration,
    handshake_timeout: Duration,
    native_no_sni: bool,
}

/// One live WSS front: the multiplexing session plus a REALITY pool whose
/// transports run over the local loopback bridge.
struct ActiveFront {
    front_id: String,
    session: std::sync::Arc<crate::wssfront::WssFrontSession>,
    pool: Arc<VlessPool>,
}

impl Drop for ActiveFront {
    fn drop(&mut self) {
        // A rotated-out session's bridge listener dies with it; stop its
        // pool's replenisher and builds so the dead loopback port is not
        // probed forever by orphaned tasks.
        self.pool
            .closed
            .store(true, std::sync::atomic::Ordering::Relaxed);
    }
}

impl VlessOutboundClient {
    pub async fn from_config(
        configs: Vec<&OutboundConfig>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        Self::from_config_inner(configs, false).await
    }

    /// `plain_front_dial` is a test channel: fronts are then dialed over
    /// plain TCP against a mock front (mocks address 127.0.0.1:port, which
    /// production canonical-URL validation forbids).
    async fn from_config_inner(
        configs: Vec<&OutboundConfig>, plain_front_dial: bool,
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

        let reality_params = match &pool.builder {
            TransportBuilder::Reality { params } => Some(params.clone()),
            _ => None,
        };

        // WSS fallback setup: only active with fronts, a REALITY leg, and a
        // broker to mint tickets. Fronts must be canonical and sorted
        // (wsscore rules) — the import only emits such sets, and an explicit
        // config that violates them is an operator error worth rejecting.
        let wss = match (&cfg.wss_fronts, &cfg.wss_fallback) {
            (Some(front_cfgs), Some(fb))
                if !front_cfgs.is_empty() && fb.enabled =>
            {
                if reality_params.is_none() {
                    return Err("vless: wss_fronts requires the reality \
                                transport"
                        .into());
                }
                let broker = match fb.broker.as_deref() {
                    Some(b) if !b.trim().is_empty() => b.trim().to_string(),
                    _ => {
                        return Err(
                            "vless: wss_fallback requires a broker URL"
                                .into(),
                        )
                    },
                };
                let relay_id = match fb.relay_id.as_deref() {
                    Some(r) if !r.trim().is_empty() => r.trim().to_string(),
                    _ => {
                        return Err(
                            "vless: wss_fallback requires the relay_id"
                                .into(),
                        )
                    },
                };
                let fronts: Vec<crate::wssfront::WssFront> = front_cfgs
                    .iter()
                    .map(|f| crate::wssfront::WssFront {
                        id: f.id.clone(),
                        url: f.url.clone(),
                        protocol_version: f.protocol_version,
                    })
                    .collect();
                // The plain dial channel (tests) addresses mock fronts on
                // 127.0.0.1:port directly; production requires an already
                // canonical, sorted front set (wsscore rules) — exactly what
                // the directory import emits — and re-validates every front
                // URL again at dial time.
                let fronts = if plain_front_dial {
                    fronts
                } else {
                    let canonical =
                        crate::wssfront::normalize_fronts(&fronts).map_err(
                            |e| format!("vless: invalid wss_fronts: {e}"),
                        )?;
                    if canonical != fronts {
                        return Err("vless: wss_fronts must be canonical and \
                                    sorted by id (wsscore order)"
                            .into());
                    }
                    canonical
                };
                Some(WssFallbackSetup {
                    relay_id,
                    broker,
                    fronts,
                    ticket_budget: Duration::from_millis(
                        fb.ticket_budget_ms.unwrap_or(
                            crate::wssfront::TICKET_TOTAL_DEADLINE
                                .as_millis() as u64,
                        ),
                    ),
                    handshake_timeout: Duration::from_millis(
                        fb.handshake_timeout_ms.unwrap_or(
                            crate::wssfront::DEFAULT_HANDSHAKE_TIMEOUT
                                .as_millis() as u64,
                        ),
                    ),
                    native_no_sni: fb.native_no_sni,
                })
            },
            _ => None,
        };

        Ok(Self {
            direct: pool,
            uuid,
            flow,
            tls_server,
            insecure,
            tls_fp,
            reality_params,
            wss,
            active: tokio::sync::Mutex::new(None),
            activating: tokio::sync::Mutex::new(()),
            direct_cooldown_until: AtomicU64::new(0),
            #[cfg(test)]
            plain_front_dial,
        })
    }

    #[cfg(test)]
    fn plain_front_dial(&self) -> bool {
        self.plain_front_dial
    }

    #[cfg(not(test))]
    fn plain_front_dial(&self) -> bool {
        false
    }

    /// Take a transport through the currently active WSS front session, if
    /// one is alive. A dead session deactivates the fallback: recovery
    /// begins with a fresh direct attempt (docs/wss-fallback.md).
    async fn acquire_from_active(&self) -> Option<VlessStream> {
        let active = { self.active.lock().await.clone() }?;
        if active.session.is_dead() {
            log::info!(
                "WSS front session ended; falling back to the direct path"
            );
            *self.active.lock().await = None;
            return None;
        }
        if active.session.budget_left() == 0 {
            // The ticket's stream budget is spent. Rotate: this session
            // keeps serving its in-flight streams while they last, but new
            // dials must activate a fresh session — the sidecar closes the
            // whole session the moment one more stream arrives.
            log::info!(
                "WSS front {} ticket stream budget spent; rotating",
                active.front_id
            );
            *self.active.lock().await = None;
            return None;
        }
        match active.pool.acquire().await {
            Some(stream) => {
                active.pool.spawn_build();
                Some(stream)
            },
            None => match active.pool.build_one().await {
                Ok(stream) => Some(stream),
                Err(e) => {
                    log::warn!("WSS front {} bridge build failed: {e}", active.front_id);
                    *self.active.lock().await = None;
                    None
                },
            },
        }
    }

    /// Direct-first transport acquisition. Gated by the circuit breaker: a
    /// failed direct dial puts the leg in cooldown so the next dials reach
    /// the WSS front immediately instead of paying the connect timeout
    /// against a dead server; a success clears the cooldown.
    async fn try_direct(&self) -> std::io::Result<VlessStream> {
        if epoch_millis()
            < self.direct_cooldown_until.load(Ordering::Relaxed)
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "direct path cooling down after failure",
            ));
        }
        let result = async {
            if let Some(stream) = self.direct.acquire().await {
                self.direct.spawn_build();
                return Ok(stream);
            }
            self.direct.build_one().await
        }
        .await;
        match result {
            Ok(stream) => {
                self.direct_cooldown_until.store(0, Ordering::Relaxed);
                Ok(stream)
            },
            Err(e) => {
                self.direct_cooldown_until.store(
                    epoch_millis() + DIRECT_COOLDOWN_MS,
                    Ordering::Relaxed,
                );
                log::info!(
                    "direct path failed ({e}); cooling down for \
                     {}s before retrying",
                    DIRECT_COOLDOWN_MS / 1000
                );
                Err(e)
            },
        }
    }

    /// Walk the relay's signed fronts in order (connectcore
    /// attemptWSSCandidate): ticket → binding/expiry checks → dial → local
    /// bridge. The first front that yields a session wins; every failure is
    /// scoped to the front and never poisons the direct leg.
    async fn activate_wss_ladder(
        &self, setup: &WssFallbackSetup,
    ) -> Result<std::sync::Arc<ActiveFront>, String> {
        let params = self.reality_params.clone().ok_or_else(|| {
            "vless: wss fallback requires the reality transport".to_string()
        })?;
        let mut last_err = String::from("no fronts attempted");
        for front in &setup.fronts {
            log::info!(
                "direct path failed; trying WSS front {} ({})",
                front.id, front.url
            );

            // 1. Ticket ladder across the broker fronts (15s budget).
            let ticket = match crate::wssfront::request_wss_session_ticket(
                &setup.broker,
                &setup.relay_id,
                &front.id,
                setup.ticket_budget,
            )
            .await
            {
                Ok(t) => t,
                Err(e) => {
                    log::warn!(
                        "WSS front {}: ticket request failed: {e}",
                        front.id
                    );
                    last_err = format!("ticket: {e}");
                    continue;
                },
            };

            // 2. Ticket binding: the broker's URL must equal the exact
            //    signed front URL (connectcore/wss.go:357) and the ticket
            //    must still be alive (:361).
            if ticket.url != front.url {
                log::warn!(
                    "WSS front {}: ticket URL does not match the signed front",
                    front.id
                );
                last_err = "ticket_binding: URL does not match the \
                            signed relay front"
                    .to_string();
                continue;
            }
            if ticket.expires_at <= chrono::Utc::now() {
                log::warn!("WSS front {}: ticket is already expired", front.id);
                last_err = "ticket_expired".to_string();
                continue;
            }

            // 3. Dial the front: TLS + strict WS upgrade + yamux + bridge.
            let session = match crate::wssfront::establish_wss_session(
                &front.url,
                &ticket.ticket,
                ticket.max_streams,
                setup.handshake_timeout,
                setup.native_no_sni,
                self.plain_front_dial(),
            )
            .await
            {
                Ok(s) => s,
                Err(e) => {
                    log::warn!(
                        "WSS front {}: handshake failed: {e}",
                        front.id
                    );
                    last_err = format!("wss_handshake: {e}");
                    continue;
                },
            };
            log::info!("connected through WSS front {}", front.id);
            let session = std::sync::Arc::new(session);

            // 4. The bridge leg dials the local loopback listener and runs
            //    the unmodified REALITY transport over it (fragmentation is
            //    pointless on loopback). The pre-build water mark stays at 1:
            //    every bridge connection burns one unit of the ticket's
            //    stream budget, so warming 30 (the direct-pool default)
            //    would spend half the ticket before any real traffic.
            let pool = VlessPool::new(
                session.bridge_addr,
                self.tls_server.clone(),
                self.insecure,
                self.tls_fp,
                None,
                TransportBuilder::Reality { params: params.clone() },
                1,
            );
            pool.spawn_replenish();
            return Ok(std::sync::Arc::new(ActiveFront {
                front_id: front.id.clone(),
                session,
                pool,
            }));
        }
        Err(last_err)
    }

    /// Obtain one ready transport: active WSS front first, then the direct
    /// path, then the front ladder.
    async fn obtain_stream(
        &self,
    ) -> Result<VlessStream, Box<dyn std::error::Error>> {
        // 1. Active WSS front session.
        if let Some(stream) = self.acquire_from_active().await {
            return Ok(stream);
        }

        // 2. Direct-first.
        let direct_err = match self.try_direct().await {
            Ok(stream) => return Ok(stream),
            Err(e) => e,
        };

        // 3. Ladder over the signed fronts (single-flight).
        if let Some(setup) = &self.wss {
            let _guard = self.activating.lock().await;
            // Another dial may have activated a front meanwhile.
            if let Some(stream) = self.acquire_from_active().await {
                return Ok(stream);
            }
            match self.activate_wss_ladder(setup).await {
                Ok(active) => {
                    let stream = match active.pool.acquire().await {
                        Some(stream) => {
                            active.pool.spawn_build();
                            stream
                        },
                        None => active
                            .pool
                            .build_one()
                            .await
                            .map_err(|e| {
                                format!(
                                    "WSS front {}: bridge transport failed: {e}",
                                    active.front_id
                                )
                            })?,
                    };
                    *self.active.lock().await = Some(active);
                    return Ok(stream);
                },
                Err(ladder_err) => {
                    return Err(format!(
                        "direct path failed ({direct_err}); WSS fallback \
                         failed: {ladder_err}"
                    )
                    .into());
                },
            }
        }

        Err(direct_err.into())
    }
}

#[async_trait]
impl OutboundClient for VlessOutboundClient {
    async fn dial(
        &self, dest: &Destination,
    ) -> Result<Box<dyn StreamRelay>, Box<dyn std::error::Error>> {
        let stream = self.obtain_stream().await?;
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

        let stream = self.obtain_stream().await?;
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

// ---------------------------------------------------------------------------
// VLESS UDP framing
// ---------------------------------------------------------------------------

// Xray's VLESS UDP body is a sequence of [2-byte BE length] + [packet]
// frames in BOTH directions (sing-vmess vless/client.go PacketConn Read/
// Write, the reference implementation openrung's sing-box data plane uses).
// TCP is an unframed byte stream — framing applies only to VlessCommand::Udp.
// The initial client write bundles the first frame with the request header.

fn udp_frame_packet(packet: &[u8]) -> Vec<u8> {
    let mut framed = Vec::with_capacity(packet.len() + 2);
    framed.extend_from_slice(&(packet.len() as u16).to_be_bytes());
    framed.extend_from_slice(packet);
    framed
}

/// Incremental de-framer for the server's UDP frame stream: feed raw read
/// bytes (frame boundaries need not align), emit complete packets.
struct UdpDeframer {
    hdr: [u8; 2],
    hdr_filled: usize,
    payload: Vec<u8>,
    payload_left: usize,
}

impl UdpDeframer {
    fn new() -> Self {
        Self {
            hdr: [0; 2],
            hdr_filled: 0,
            payload: Vec::new(),
            payload_left: 0,
        }
    }

    fn feed(&mut self, data: &[u8], out: &mut Vec<Vec<u8>>) {
        let mut pos = 0;
        while pos < data.len() {
            if self.hdr_filled < 2 {
                let take = (2 - self.hdr_filled).min(data.len() - pos);
                self.hdr[self.hdr_filled..self.hdr_filled + take]
                    .copy_from_slice(&data[pos..pos + take]);
                self.hdr_filled += take;
                pos += take;
                if self.hdr_filled < 2 {
                    break;
                }
                self.payload_left = u16::from_be_bytes(self.hdr) as usize;
                self.payload = Vec::with_capacity(self.payload_left);
            }
            if self.payload_left > 0 {
                let take = self.payload_left.min(data.len() - pos);
                self.payload.extend_from_slice(&data[pos..pos + take]);
                pos += take;
                self.payload_left -= take;
                if self.payload_left > 0 {
                    break;
                }
            }
            out.push(std::mem::take(&mut self.payload));
            self.hdr_filled = 0;
        }
    }
}

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
        let is_udp = matches!(command, VlessCommand::Udp);
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
            // UDP responses arrive as [2-byte BE length]+[packet] frames; TCP
            // is an unframed stream. Vision is TCP-only (§S2.8: UDP keeps
            // flow empty), so VisionReality never sees UDP framing.
            let mut udp_deframer = is_udp.then(UdpDeframer::new);
            tokio::spawn(async move {
                match reader {
                    VlessReader::Ws(mut reader) => loop {
                        match reader.recv().await {
                            Ok(WsFrame::Binary(d)) => {
                                if let Some(dfr) = udp_deframer.as_mut() {
                                    let mut packets = Vec::new();
                                    dfr.feed(&d, &mut packets);
                                    let mut dead = false;
                                    for packet in packets {
                                        if data_tx.send(packet).is_err() {
                                            dead = true;
                                            break;
                                        }
                                    }
                                    if dead {
                                        break;
                                    }
                                } else if data_tx.send(d).is_err() {
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
                                if let Some(dfr) = udp_deframer.as_mut() {
                                    let mut packets = Vec::new();
                                    dfr.feed(&buf[..n], &mut packets);
                                    let mut dead = false;
                                    for packet in packets {
                                        if data_tx.send(packet).is_err() {
                                            dead = true;
                                            break;
                                        }
                                    }
                                    if dead {
                                        break;
                                    }
                                } else if data_tx
                                    .send(buf[..n].to_vec())
                                    .is_err()
                                {
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
        // On first write: do VLESS handshake with payload bundled. The
        // payload is the framed packet — VLESS UDP bodies carry a 2-byte BE
        // length prefix per packet (the server parses the first two raw
        // bytes as a length, so a bare DNS query would stall forever).
        if let DeferredUdpState::Pending { stream, uuid, dest, flow } =
            &mut *guard
        {
            let stream = stream.take().expect("stream already taken");
            let uuid = *uuid;
            let dest = dest.clone();
            let flow = flow.clone();
            let first = udp_frame_packet(buf);
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
        // Send subsequent packets via the active relay (framed likewise).
        if let DeferredUdpState::Active { outbound_tx, .. } = &*guard {
            outbound_tx
                .send(udp_frame_packet(buf))
                .map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "vless udp closed",
                    )
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
    use std::task::Context;
    use std::task::Poll;

    /// LIVE full-stack transfer probe (network, #[ignore] by default):
    /// drives the complete production data plane — vless client →
    /// (dead direct leg fails fast) → WSS ladder → bridge → relay →
    /// target — first with a plain-HTTP download, then over TLS, exactly
    /// what the browser does for media. Reports HTTP status, bytes, timing,
    /// and stalls.
    ///
    /// Run with:
    ///   FULLSTACK_CONFIG=/Users/suwey/config.toml \
    ///   cargo test -p anywhere --lib -- --ignored live_full --nocapture
    #[tokio::test(flavor = "multi_thread")]
    #[ignore]
    async fn live_full_stack_transfer_probe() {
        let Ok(path) = std::env::var("FULLSTACK_CONFIG") else {
            return;
        };
        let raw = std::fs::read_to_string(&path)
            .expect("config file readable");
        let cfg: crate::config::Config =
            toml::from_str(&raw).expect("config parses");
        let ob = cfg
            .outbounds
            .iter()
            .find(|o| o.type_ == "vless")
            .expect("a vless outbound");
        let client = VlessOutboundClient::from_config(vec![ob])
            .await
            .expect("client builds");

        // ---- plain HTTP sustained transfer (speedtest.tele2.net) ----
        let host = "speedtest.tele2.net";
        let dest = Destination::new(
            crate::inbound::Address::Domain(host.to_string()),
            80,
        );
        let mut relay = client.dial(&dest).await.expect("dial through the stack");
        let request = format!(
            "GET /1MB.zip HTTP/1.1\r\nHost: {host}\r\n\
             User-Agent: curl/8.7.1\r\nAccept: */*\r\n\
             Connection: close\r\n\r\n"
        );
        relay.write(request.as_bytes()).await.expect("request written");
        let (total, head) = drain_relay(relay).await;
        println!(
            "PLAIN: {total} bytes, status: {}",
            String::from_utf8_lossy(&head).lines().next().unwrap_or("?")
        );
        assert!(
            total > 1_000_000,
            "sustained plain transfer failed: only {total} bytes"
        );

        // ---- HTTPS through the tunnel (TLS over the vless stream) ----
        // The StreamRelay is bridged to AsyncRead/AsyncWrite via a shared
        // mutex + owned-buffer futures (no self-referential borrows).
        for (host, req, min_bytes) in [
            ("www.youtube.com", "GET /generate_204 HTTP/1.1", 0usize),
            (
                "speed.cloudflare.com",
                "GET /__down?bytes=8000000 HTTP/1.1",
                1_000_000,
            ),
        ] {
            let dest = Destination::new(
                crate::inbound::Address::Domain(host.to_string()),
                443,
            );
            let relay = client.dial(&dest).await.expect("dial for https");
            let io = RelayIo::new(relay);
            let start = std::time::Instant::now();
            let connector = boring::ssl::SslConnector::builder(
                boring::ssl::SslMethod::tls(),
            )
            .expect("ssl builder")
            .build();
            let tls_config = connector
                .configure()
                .expect("default connector configure");
            let mut tls = match tokio::time::timeout(
                Duration::from_secs(15),
                tokio_boring::connect(tls_config, host, io),
            )
            .await
            {
                Ok(Ok(t)) => t,
                Ok(Err(e)) => {
                    println!("HTTPS {host}: TLS handshake failed: {e}");
                    continue;
                },
                Err(_) => {
                    println!("HTTPS {host}: TLS handshake timed out");
                    continue;
                },
            };
            use tokio::io::AsyncReadExt as _;
            use tokio::io::AsyncWriteExt as _;
            let request = format!(
                "{req}\r\nHost: {host}\r\nUser-Agent: curl/8.7.1\r\n\
                 Accept: */*\r\nConnection: close\r\n\r\n"
            );
            tls.write_all(request.as_bytes()).await.unwrap();
            let mut total = 0usize;
            let mut head: Vec<u8> = Vec::new();
            let mut buf = vec![0u8; 32 * 1024];
            loop {
                match tokio::time::timeout(
                    Duration::from_secs(25),
                    tls.read(&mut buf),
                )
                .await
                {
                    Ok(Ok(0)) | Ok(Err(_)) => break,
                    Ok(Ok(n)) => {
                        if head.len() < 64 {
                            head.extend_from_slice(
                                &buf[..n.min(64 - head.len())],
                            );
                        }
                        total += n;
                    },
                    Err(_) => {
                        println!("HTTPS {host}: STALL at {total} bytes");
                        break;
                    },
                }
            }
            println!(
                "HTTPS {host}: {total} bytes in {:?}, status: {}",
                start.elapsed(),
                String::from_utf8_lossy(&head).lines().next().unwrap_or("?")
            );
            if min_bytes > 0 {
                assert!(
                    total > min_bytes,
                    "sustained TLS transfer failed: {total} bytes"
                );
            }
        }

        // ---- application layer: mint a real videoplayback URL via the
        // innertube player API through the tunnel, then fetch it through
        // the tunnel and observe googlevideo's actual status code ----
        println!("---- innertube player API probe ----");
        let player_body = serde_json::json!({
            "context": {
                "client": {
                    "clientName": "ANDROID",
                    "clientVersion": "20.10.38",
                    "androidSdkVersion": 34,
                    "hl": "en",
                }
            },
            "videoId": "aqz-KE-bpKQ",
            "contentCheckOk": true,
            "racyCheckOk": true,
        })
        .to_string();
        let api_host = "www.youtube.com";
        let dest = Destination::new(
            crate::inbound::Address::Domain(api_host.to_string()),
            443,
        );
        let relay = client.dial(&dest).await.expect("dial for player api");
        let io = RelayIo::new(relay);
        let connector = boring::ssl::SslConnector::builder(
            boring::ssl::SslMethod::tls(),
        )
        .unwrap()
        .build();
        let mut tls = match tokio_boring::connect(
            connector.configure().unwrap(),
            api_host,
            io,
        )
        .await
        {
            Ok(t) => t,
            Err(_) => panic!("player api tls failed"),
        };
        use tokio::io::AsyncReadExt as _;
        use tokio::io::AsyncWriteExt as _;
        let req = format!(
            "POST /youtubei/v1/player HTTP/1.1\r\nHost: {api_host}\r\n\
             Content-Type: application/json\r\n\
             Content-Length: {}\r\nUser-Agent: com.google.android.youtube/20.\
             10.38 (Linux; U; Android 14) gzip\r\n\
             Connection: close\r\n\r\n{player_body}",
            player_body.len()
        );
        tls.write_all(req.as_bytes()).await.unwrap();
        let mut api_resp = Vec::new();
        let mut buf = vec![0u8; 32 * 1024];
        loop {
            match tokio::time::timeout(Duration::from_secs(20), tls.read(&mut buf)).await {
                Ok(Ok(0)) | Ok(Err(_)) => break,
                Ok(Ok(n)) => api_resp.extend_from_slice(&buf[..n]),
                Err(_) => { println!("player api read stall"); break; }
            }
        }
        let api_text = String::from_utf8_lossy(&api_resp);
        let status_line =
            api_text.lines().next().unwrap_or("?").to_string();
        println!("player api status: {status_line}, {} bytes", api_resp.len());
        // Extract the first googlevideo URL from the adaptiveFormats.
        let gv_url = api_text
            .split('"')
            .find(|s| s.starts_with("https://") && s.contains("googlevideo.com/videoplayback"))
            .map(|s| s.to_string());
        let Some(gv_url) = gv_url else {
            println!("no googlevideo URL in player response");
            if let Some(pos) = api_text.find("playabilityStatus") {
                let snippet = &api_text[pos..(pos + 400).min(api_text.len())];
                let clean: String = snippet.chars().filter(|c| c.is_ascii_graphic() || *c == ' ').collect();
                println!("PLAYABILITY: {clean}");
            } else {
                println!("body head: {}", &api_text[api_text.find("\r\n\r\n").map(|i| i + 4).unwrap_or(0)..]);
            }
            return;
        };
        let gv_host = gv_url
            .split('/')
            .nth(2)
            .unwrap_or_default()
            .to_string();
        println!("videoplayback host: {gv_host}");
        // Fetch the URL through the tunnel.
        let dest = Destination::new(
            crate::inbound::Address::Domain(gv_host.clone()),
            443,
        );
        let relay = client.dial(&dest).await.expect("dial googlevideo");
        let io = RelayIo::new(relay);
        let connector = boring::ssl::SslConnector::builder(
            boring::ssl::SslMethod::tls(),
        )
        .unwrap()
        .build();
        let mut tls = match tokio_boring::connect(
            connector.configure().unwrap(),
            &gv_host,
            io,
        )
        .await
        {
            Ok(t) => t,
            Err(_) => panic!("googlevideo tls failed"),
        };
        let req = format!(
            "GET {} HTTP/1.1\r\nHost: {gv_host}\r\nUser-Agent: com.google.\
             android.youtube/20.10.38 (Linux; U; Android 14) gzip\r\n\
             Accept: */*\r\nConnection: close\r\n\r\n",
            &gv_url[gv_url.find("googlevideo.com").map(|i| i + "googlevideo.com".len()).unwrap_or(0)..]
                .split('&')
                .map(|p| if p.starts_with("url=") { url_escape(p) } else { p.to_string() })
                .collect::<Vec<_>>()
                .join("&")
        );
        tls.write_all(req.as_bytes()).await.unwrap();
        let mut gv_resp = Vec::new();
        let mut total = 0usize;
        loop {
            match tokio::time::timeout(Duration::from_secs(25), tls.read(&mut buf)).await {
                Ok(Ok(0)) | Ok(Err(_)) => break,
                Ok(Ok(n)) => { gv_resp.extend_from_slice(&buf[..n]); total += n; if gv_resp.len() > 300_000 { break; } }
                Err(_) => { println!("googlevideo STALL at {total}"); break; }
            }
        }
        let gv_text = String::from_utf8_lossy(&gv_resp);
        println!(
            "VIDEO FETCH: {total} bytes, status: {}",
            gv_text.lines().next().unwrap_or("?")
        );
        if total > 100_000 {
            println!("googlevideo serves video data through this exit — tunnel + exit IP OK");
        }
    }

    fn url_escape(p: &str) -> String {
        p.replace('%', "%25")
    }

    /// Drain a relay to EOF (or a stall), returning (bytes, head).
    async fn drain_relay(
        mut relay: Box<dyn crate::relay::StreamRelay>,
    ) -> (usize, Vec<u8>) {
        let start = std::time::Instant::now();
        let mut total = 0usize;
        let mut chunks = 0usize;
        let mut head: Vec<u8> = Vec::new();
        let mut buf = vec![0u8; 32 * 1024];
        loop {
            match tokio::time::timeout(
                Duration::from_secs(20),
                relay.read(&mut buf),
            )
            .await
            {
                Ok(Ok(0)) => {
                    println!(
                        "clean EOF after {total} bytes in {:?}",
                        start.elapsed()
                    );
                    break;
                },
                Ok(Ok(n)) => {
                    if head.len() < 64 {
                        head.extend_from_slice(&buf[..n.min(64 - head.len())]);
                    }
                    total += n;
                    chunks += 1;
                    if chunks % 32 == 0 {
                        println!(
                            "progress: {total} bytes, {:?} elapsed",
                            start.elapsed()
                        );
                    }
                },
                Ok(Err(e)) => {
                    println!("read error after {total} bytes: {e}");
                    break;
                },
                Err(_) => {
                    println!(
                        "STALL: no data for 20s at {total} bytes \
                         (after {chunks} chunks)"
                    );
                    break;
                },
            }
        }
        (total, head)
    }

    /// Bridge `Box<dyn StreamRelay>` (async-trait) to AsyncRead/AsyncWrite.
    /// Both directions go through a shared mutex; the in-flight futures own
    /// their buffers and the lock guard, so no self-referential borrows.
    struct RelayIo {
        inner: std::sync::Arc<
            tokio::sync::Mutex<Box<dyn crate::relay::StreamRelay>>,
        >,
        read_fut: Option<
            std::pin::Pin<
                Box<
                    dyn std::future::Future<
                            Output = io::Result<(usize, Vec<u8>)>,
                        > + Send,
                >,
            >,
        >,
        write_fut: Option<
            std::pin::Pin<
                Box<dyn std::future::Future<Output = io::Result<()>> + Send>,
            >,
        >,
        leftover: Vec<u8>,
    }

    impl RelayIo {
        fn new(relay: Box<dyn crate::relay::StreamRelay>) -> Self {
            Self {
                inner: std::sync::Arc::new(tokio::sync::Mutex::new(relay)),
                read_fut: None,
                write_fut: None,
                leftover: Vec::new(),
            }
        }
    }

    impl tokio::io::AsyncRead for RelayIo {
        fn poll_read(
            mut self: std::pin::Pin<&mut Self>, cx: &mut Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            if !self.leftover.is_empty() {
                let n = self.leftover.len().min(buf.remaining());
                buf.put_slice(&self.leftover[..n]);
                self.leftover.drain(..n);
                return Poll::Ready(Ok(()));
            }
            loop {
                if let Some(fut) = self.read_fut.as_mut() {
                    match fut.as_mut().poll(cx) {
                        Poll::Ready(Ok((n, data))) => {
                            self.read_fut = None;
                            let take = n.min(buf.remaining());
                            buf.put_slice(&data[..take]);
                            if take < n {
                                self.leftover.extend_from_slice(&data[take..n]);
                            }
                            return Poll::Ready(Ok(()));
                        },
                        Poll::Ready(Err(e)) => {
                            self.read_fut = None;
                            return Poll::Ready(Err(e));
                        },
                        Poll::Pending => return Poll::Pending,
                    }
                }
                let inner = self.inner.clone();
                self.read_fut = Some(Box::pin(async move {
                    let mut guard = inner.lock().await;
                    let mut data = vec![0u8; 32 * 1024];
                    let n = guard.read(&mut data).await?;
                    data.truncate(n);
                    Ok((n, data))
                }));
            }
        }
    }

    impl tokio::io::AsyncWrite for RelayIo {
        fn poll_write(
            mut self: std::pin::Pin<&mut Self>, cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            if let Some(fut) = self.write_fut.as_mut() {
                match fut.as_mut().poll(cx) {
                    Poll::Ready(Ok(())) => {
                        self.write_fut = None;
                        return Poll::Ready(Ok(buf.len()));
                    },
                    Poll::Ready(Err(e)) => {
                        self.write_fut = None;
                        return Poll::Ready(Err(e));
                    },
                    Poll::Pending => return Poll::Pending,
                }
            }
            let inner = self.inner.clone();
            let data = buf.to_vec();
            self.write_fut = Some(Box::pin(async move {
                let mut guard = inner.lock().await;
                guard.write(&data).await
            }));
            self.poll_write(cx, buf)
        }

        fn poll_flush(
            self: std::pin::Pin<&mut Self>, _cx: &mut Context<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>, _cx: &mut Context<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    // VLESS UDP framing: [2-byte BE length]+[packet] in both directions.
    // The deframer must reassemble packets torn across read boundaries.
    #[test]
    fn udp_framing_round_trip_with_torn_boundaries() {
        let packets: Vec<Vec<u8>> = vec![
            b"aaaa".to_vec(),
            b"bb".to_vec(),
            Vec::new(), // zero-length frame is legal
            vec![7u8; 1000],
        ];
        let mut stream = Vec::new();
        for p in &packets {
            stream.extend(udp_frame_packet(p));
        }
        let mut dfr = UdpDeframer::new();
        let mut out = Vec::new();
        for b in &stream {
            dfr.feed(std::slice::from_ref(b), &mut out);
        }
        assert_eq!(out, packets);
    }

    #[test]
    fn udp_frame_header_is_big_endian_length() {
        let f = udp_frame_packet(&[0xAA, 0xBB, 0xCC]);
        assert_eq!(&f[..2], &[0x00, 0x03]);
        assert_eq!(&f[2..], &[0xAA, 0xBB, 0xCC]);
    }

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
    // -- direct-first WSS/CDN fallback ladder (OpenRung) ----------------------

    use crate::config::WssFallbackConfig;
    use crate::config::WssFrontConfig;

    const LADDER_PBK: &str = "Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc=";

    /// Bind and immediately drop a loopback listener; its port now refuses
    /// connections deterministically (ECONNREFUSED on loopback).
    fn refused_port() -> u16 {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap().port()
    }

    fn ladder_cfg(
        server: String, fronts: Vec<WssFrontConfig>, broker: String,
    ) -> OutboundConfig {
        OutboundConfig {
            type_: "vless".into(),
            tag: Some("ladder".into()),
            server: Some(server),
            password: Some("b831381d-6324-4d53-ad4f-8cda48b30811".into()),
            sni: Some("www.example.com".into()),
            tls_fragment: false,
            reality: Some(crate::transport::reality::RealityConfig {
                public_key: LADDER_PBK.into(),
                short_id: "01ab".into(),
            }),
            wss_fronts: Some(fronts),
            wss_fallback: Some(WssFallbackConfig {
                broker: Some(broker),
                relay_id: Some("relay_x".into()),
                enabled: true,
                ticket_budget_ms: Some(5_000),
                handshake_timeout_ms: Some(3_000),
                native_no_sni: true,
            }),
            ..Default::default()
        }
    }

    fn front_cfg(id: &str, url: String) -> WssFrontConfig {
        WssFrontConfig { id: id.into(), url, protocol_version: 1 }
    }

    fn front_url(addr: std::net::SocketAddr) -> String {
        format!("wss://127.0.0.1:{}/api/v1/wss-bridge", addr.port())
    }

    /// Broker routing tickets per front: `tickets` maps front_id to the URL
    /// embedded in the ticket; unknown fronts get a 404.
    async fn spawn_ticket_broker(
        tickets: std::collections::HashMap<String, String>,
    ) -> String {
        crate::wssfront::testutil::spawn_mock_broker_router(move |body| {
            let front_id = crate::wssfront::testutil::front_id_of(&body);
            match tickets.get(&front_id) {
                Some(url) => crate::wssfront::testutil::http_ok(
                    &crate::wssfront::testutil::ticket_body(
                        "v1.k.claims.sig",
                        120,
                        url,
                    ),
                ),
                None => crate::wssfront::testutil::http_status(404, &[]),
            }
        })
        .await
    }

    #[tokio::test]
    async fn wss_ladder_activates_first_front_after_direct_failure() {
        let front_addr =
            crate::wssfront::testutil::spawn_mock_front("v1.k.claims.sig")
                .await;
        let url = front_url(front_addr);
        let broker = spawn_ticket_broker(
            [("front-a".to_string(), url.clone())].into_iter().collect(),
        )
        .await;

        // The direct endpoint refuses connections (a blackholed relay IP).
        let refused = refused_port();
        let cfg = ladder_cfg(
            format!("127.0.0.1:{refused}"),
            vec![front_cfg("front-a", url)],
            broker,
        );
        validate_vless_config(&cfg).unwrap();
        let client =
            VlessOutboundClient::from_config_inner(vec![&cfg], true)
                .await
                .unwrap();

        // The ladder must mint a ticket from the mock broker, dial the mock
        // front through it, and activate that front.
        let setup = client.wss.as_ref().unwrap();
        let active = client
            .activate_wss_ladder(setup)
            .await
            .expect("ladder must activate the first front");
        assert_eq!(active.front_id, "front-a");
        assert!(active.session.bridge_addr.ip().is_loopback());
        assert!(!active.session.is_dead());
    }

    #[tokio::test]
    async fn wss_ladder_walks_to_second_front_on_ticket_denial() {
        let front_a =
            crate::wssfront::testutil::spawn_mock_front("v1.k.claims.sig")
                .await;
        let front_b =
            crate::wssfront::testutil::spawn_mock_front("v1.k.claims.sig")
                .await;
        // front-a is unknown to the broker (404); front-b gets a ticket.
        let broker = spawn_ticket_broker(
            [("front-b".to_string(), front_url(front_b))]
                .into_iter()
                .collect(),
        )
        .await;

        let refused = refused_port();
        let cfg = ladder_cfg(
            format!("127.0.0.1:{refused}"),
            vec![
                front_cfg("front-a", front_url(front_a)),
                front_cfg("front-b", front_url(front_b)),
            ],
            broker,
        );
        let client =
            VlessOutboundClient::from_config_inner(vec![&cfg], true)
                .await
                .unwrap();
        let setup = client.wss.as_ref().unwrap();
        let active = client
            .activate_wss_ladder(setup)
            .await
            .expect("ladder must walk to the second front");
        assert_eq!(active.front_id, "front-b");
    }

    #[tokio::test]
    async fn wss_ladder_rejects_ticket_bound_to_wrong_front() {
        let front_a =
            crate::wssfront::testutil::spawn_mock_front("v1.k.claims.sig")
                .await;
        let front_b =
            crate::wssfront::testutil::spawn_mock_front("v1.k.claims.sig")
                .await;
        // The broker answers front-a with a ticket carrying front-b's URL:
        // the binding check (connectcore/wss.go:357) must skip front-a.
        let tickets = [
            ("front-a".to_string(), front_url(front_b)),
            ("front-b".to_string(), front_url(front_b)),
        ]
        .into_iter()
        .collect();
        let broker = spawn_ticket_broker(tickets).await;

        let refused = refused_port();
        let cfg = ladder_cfg(
            format!("127.0.0.1:{refused}"),
            vec![
                front_cfg("front-a", front_url(front_a)),
                front_cfg("front-b", front_url(front_b)),
            ],
            broker,
        );
        let client =
            VlessOutboundClient::from_config_inner(vec![&cfg], true)
                .await
                .unwrap();
        let setup = client.wss.as_ref().unwrap();
        let active = client
            .activate_wss_ladder(setup)
            .await
            .expect("front-b must still activate");
        assert_eq!(active.front_id, "front-b");
    }

    #[tokio::test]
    async fn wss_ladder_all_fail_yields_combined_error() {
        // Broker unreachable: every front fails on the ticket request.
        let dead_broker = format!("http://127.0.0.1:{}", refused_port());
        let front_a = crate::wssfront::testutil::spawn_mock_front("t").await;
        let cfg = ladder_cfg(
            format!("127.0.0.1:{}", refused_port()),
            vec![front_cfg("front-a", front_url(front_a))],
            dead_broker,
        );
        validate_vless_config(&cfg).unwrap();
        let client =
            VlessOutboundClient::from_config_inner(vec![&cfg], true)
                .await
                .unwrap();

        let msg = match client.obtain_stream().await {
            Err(e) => e.to_string(),
            Ok(_) => panic!("direct + all fronts failed: expected error"),
        };
        assert!(msg.contains("direct path failed"), "{msg}");
        assert!(msg.contains("WSS fallback failed"), "{msg}");
        // The active front must remain unset after a failed ladder.
        assert!(client.active.lock().await.is_none());
    }

    #[tokio::test]
    async fn wss_disabled_fallback_never_attempts_fronts() {
        // Fronts configured but the fallback disabled: the direct failure is
        // returned as-is — no ticket attempt, no front dial.
        let mut cfg = ladder_cfg(
            format!("127.0.0.1:{}", refused_port()),
            vec![front_cfg(
                "front-a",
                "wss://a.b-cdn.net/api/v1/wss-bridge".into(),
            )],
            "http://127.0.0.1:1".into(),
        );
        cfg.wss_fallback.as_mut().unwrap().enabled = false;
        validate_vless_config(&cfg).unwrap();
        let client =
            VlessOutboundClient::from_config(vec![&cfg]).await.unwrap();
        assert!(
            client.wss.is_none(),
            "disabled fallback must not build a setup"
        );

        let msg = match client.obtain_stream().await {
            Err(e) => e.to_string(),
            Ok(_) => panic!("expected direct failure"),
        };
        assert!(!msg.contains("WSS"), "{msg}");
    }

    #[test]
    fn vless_config_rejects_fronts_without_reality_or_fallback() {
        // fronts without the reality section
        let cfg = OutboundConfig {
            type_: "vless".into(),
            server: Some("127.0.0.1:443".into()),
            password: Some("b831381d-6324-4d53-ad4f-8cda48b30811".into()),
            sni: Some("www.example.com".into()),
            wss_fronts: Some(vec![front_cfg(
                "a",
                "wss://a.b-cdn.net/api/v1/wss-bridge".into(),
            )]),
            wss_fallback: Some(WssFallbackConfig {
                broker: Some("https://broker.openrung.org/".into()),
                relay_id: Some("relay_x".into()),
                enabled: true,
                ticket_budget_ms: None,
                handshake_timeout_ms: None,
                native_no_sni: true,
            }),
            ..Default::default()
        };
        let err = validate_vless_config(&cfg).unwrap_err();
        assert!(err.contains("reality"), "{err}");

        // reality but no fallback section
        let cfg = OutboundConfig {
            type_: "vless".into(),
            server: Some("127.0.0.1:443".into()),
            password: Some("b831381d-6324-4d53-ad4f-8cda48b30811".into()),
            sni: Some("www.example.com".into()),
            reality: Some(crate::transport::reality::RealityConfig {
                public_key: LADDER_PBK.into(),
                short_id: "01ab".into(),
            }),
            wss_fronts: Some(vec![front_cfg(
                "a",
                "wss://a.b-cdn.net/api/v1/wss-bridge".into(),
            )]),
            ..Default::default()
        };
        let err = validate_vless_config(&cfg).unwrap_err();
        assert!(err.contains("wss_fallback"), "{err}");
    }

    #[tokio::test]
    async fn vless_config_rejects_non_canonical_fronts() {
        let refused = refused_port();
        let broker = spawn_ticket_broker(Default::default()).await;
        // Unsorted front set (wsscore canonical order required).
        let cfg = ladder_cfg(
            format!("127.0.0.1:{refused}"),
            vec![
                front_cfg("b", "wss://b.b-cdn.net/api/v1/wss-bridge".into()),
                front_cfg("a", "wss://a.b-cdn.net/api/v1/wss-bridge".into()),
            ],
            broker,
        );
        let err = match VlessOutboundClient::from_config(vec![&cfg]).await {
            Err(e) => e.to_string(),
            Ok(_) => panic!("non-canonical fronts must be rejected"),
        };
        assert!(err.contains("canonical"), "{err}");
    }

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
        let latency = client.test_latency("https://www.example.com").await;
        assert!(
            latency.is_none(),
            "dial against a non-REALITY endpoint must fail, got {latency:?}"
        );
    }
}
