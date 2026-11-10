use async_trait::async_trait;
use base64::Engine as _;
use std::collections::HashMap;
use std::sync::Arc;

use crate::config::Config;
use crate::config::OutboundConfig;
use crate::inbound::Destination;
use crate::outbound::OutboundClient;
use crate::outbound::anytls::AnyTlsOutboundClient;
use crate::outbound::direct::DirectOutboundClient;
use crate::outbound::mless::MlessOutboundClient;
use crate::outbound::quic::QuicOutboundClient;
use crate::outbound::shadowsocks::ShadowsocksOutboundClient;
use crate::outbound::ssh::SshOutboundClient;
use crate::outbound::urltest::UrlTestOutboundClient;
use crate::outbound::urltest::UrlTestState;
use crate::outbound::urltest::{self, SelectMode};
use crate::outbound::vless::VlessOutboundClient;
use crate::relay::PacketRelay;
use crate::relay::StreamRelay;

/// A config-validation failure with a **stable machine-readable key**.
///
/// The web UI is multilingual: it maps `key` to a localized message and may
/// render `detail` (server-side English, parameterized) as the fallback or
/// secondary line. Keys are part of the UI contract — never reword them,
/// only ever ADD new ones. Current keys:
///
/// - `outbound_missing_tag` — an `[[outbounds]]` entry has no `tag`
/// - `outbound_duplicate_tag` — two entries share a tag
/// - `urltest_child_not_found` — a urltest/select child references a tag
///   that is not defined anywhere
///
/// The UI layer adds transport-level keys around these (`config_parse_error`,
/// `config_read_error`, `config_write_error`, `no_config_path`,
/// `force_required`, `restart_failed`).
#[derive(Debug)]
pub struct ConfigError {
    /// Stable i18n key, e.g. `urltest_child_not_found`.
    pub key: &'static str,
    /// Human-readable English fallback with the parameters spelled out.
    pub detail: String,
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.detail)
    }
}

impl std::error::Error for ConfigError {}

/// Holds outbound clients keyed by configured tag.
pub struct OutboundRegistry {
    clients: Arc<HashMap<String, Arc<dyn OutboundClient>>>,
    /// Per-group shared states for UI access (all group types unified).
    pub urltest_states: HashMap<String, Arc<UrlTestState>>,
    /// JoinHandles of urltest background test loops. Aborted on in-process
    /// reload so the outbound clients they hold (esp. mless/vless mux
    /// persistent connections) are released before the next run() iteration.
    test_loop_handles: Arc<std::sync::Mutex<Vec<tokio::task::AbortHandle>>>,
}

impl OutboundRegistry {
    fn tag(config: &OutboundConfig) -> Result<&str, Box<dyn std::error::Error>> {
        config
            .tag
            .as_deref()
            .ok_or_else(|| "outbound missing tag".into())
    }

    fn validate_tags(
        configs: &[OutboundConfig],
    ) -> Result<(), ConfigError> {
        let mut seen: std::collections::HashSet<&str> =
            std::collections::HashSet::with_capacity(configs.len());
        for config in configs {
            let tag = Self::tag(config).map_err(|e| ConfigError {
                key: "outbound_missing_tag",
                detail: format!("outbound without a tag: {e}"),
            })?;
            // Uniqueness matters as much as presence: the registry is a
            // tag→client HashMap, so a duplicate would silently overwrite
            // the first outbound and everything routed to the hidden one
            // would land on its twin.
            if !seen.insert(tag) {
                return Err(ConfigError {
                    key: "outbound_duplicate_tag",
                    detail: format!(
                        "duplicate outbound tag '{tag}' — tags must be unique"
                    ),
                });
            }
        }
        Ok(())
    }

    /// Definition-level urltest child check: every child tag must reference
    /// a configured outbound (or the implicit auto-inserted `direct`).
    ///
    /// Deliberately definition-only, and deliberately NOT part of the
    /// web-UI save path's leniency: a typo'd child tag would leave the
    /// group unable to resolve a child and every rule routed to it dead,
    /// with only per-connection warnings to show for it (2026-11-10 field
    /// report: `outbounds = ["CF"]` with no CF outbound defined). What IS
    /// tolerated is a defined child whose construction fails at startup —
    /// the registry holds it as a deferred client (see
    /// DeferredOutboundClient) and the urltest probe cycle is what revives
    /// it, which is also why the Android placeholder template starts.
    fn check_urltest_children(
        outbounds: &[OutboundConfig],
    ) -> Result<(), ConfigError> {
        let configured: std::collections::HashSet<String> = outbounds
            .iter()
            .filter_map(|o| Self::tag(o).ok().map(str::to_string))
            .chain(["direct".to_string()])
            .collect();
        for cfg in outbounds
            .iter()
            .filter(|o| o.type_ == "urltest" || o.type_ == "select")
        {
            let tag = Self::tag(cfg).map_err(|e| ConfigError {
                key: "outbound_missing_tag",
                detail: format!("outbound without a tag: {e}"),
            })?;
            let Some(child_tags) = cfg.outbounds.as_ref() else {
                continue; // missing field: warn-and-skip in from_config
            };
            let missing: Vec<&str> = child_tags
                .iter()
                .filter(|t| !configured.contains(t.as_str()))
                .map(String::as_str)
                .collect();
            if !missing.is_empty() {
                return Err(ConfigError {
                    key: "urltest_child_not_found",
                    detail: format!(
                        "{} '{tag}': child {} not found among configured outbound tags",
                        cfg.type_,
                        missing
                            .iter()
                            .map(|t| format!("'{t}'"))
                            .collect::<Vec<_>>()
                            .join(", "),
                    ),
                });
            }
        }
        Ok(())
    }

    /// The one config-integrity gate, shared verbatim by all three entry
    /// points — engine startup ([`Self::from_config`]), the web-UI save
    /// path, and `anywhere -t`. Outbound tags must be present and unique,
    /// and urltest children must reference defined outbounds; anything
    /// failing here refuses to start (startup), is rejected with 400
    /// (save), or is reported by `-t`.
    ///
    /// Deliberately tolerated: a defined child whose construction fails at
    /// startup (the Android placeholder template) — see
    /// DeferredOutboundClient.
    pub fn validate_config_refs(
        config: &Config,
    ) -> Result<(), ConfigError> {
        Self::validate_tags(&config.outbounds)?;
        Self::check_urltest_children(&config.outbounds)?;
        Ok(())
    }
    /// Resolve `ech = true` into a concrete ECHConfigList for the TLS
    /// outbounds that anywhere itself is the TLS client of (quic / anytls /
    /// vless-over-ws-tls). Explicit `ech_config` (base64) always wins; with
    /// only `ech = true` the config is acquired from the outbound host's DNS
    /// HTTPS record through the `[dns].direct` upstreams (DoH first).
    /// Acquisition failure disables ECH for that outbound with a warning —
    /// the handshake path remains fail-closed on ECH rejection regardless
    /// (see `ech::ensure_ech_accepted`). REALITY outbounds are skipped:
    /// their borrowed-target SNI is the camouflage, and
    /// `vless::validate_vless_config` rejects the combination anyway.
    async fn resolve_outbound_ech(
        cfg: &OutboundConfig, dns_direct: &[String],
    ) -> OutboundConfig {
        if !cfg.ech || cfg.ech_config.is_some() || cfg.reality.is_some() {
            return cfg.clone();
        }
        if cfg.type_ != "vless" && cfg.type_ != "anytls" && cfg.type_ != "quic" {
            return cfg.clone();
        }
        let host = match crate::outbound::common::resolve_sni(cfg) {
            Ok(host) => host,
            Err(_) => return cfg.clone(),
        };
        match crate::ech::acquire_outbound_config(
            &host, true, None, dns_direct,
        )
        .await
        {
            Some(bytes) => {
                let mut resolved = cfg.clone();
                resolved.ech_config = Some(
                    base64::engine::general_purpose::STANDARD.encode(bytes),
                );
                resolved
            },
            None => cfg.clone(),
        }
    }

    /// Construct a single outbound client from its config. The one
    /// construction path shared by startup ([`Self::from_config`]'s loop)
    /// and the deferred retry path ([`DeferredOutboundClient::ensure`]) —
    /// mless pool keepalives register their handles here so both paths get
    /// the same lifecycle.
    async fn construct_outbound(
        cfg: &OutboundConfig, dns_direct: &[String],
        tls_fragment: Option<crate::tlsfragment::FragmentConfig>,
        loop_handles: &std::sync::Mutex<Vec<tokio::task::AbortHandle>>,
    ) -> Result<Arc<dyn OutboundClient>, Box<dyn std::error::Error>> {
        let client = match cfg.type_.as_str() {
            "quic" => {
                let cfg = Self::resolve_outbound_ech(cfg, dns_direct).await;
                Arc::new(QuicOutboundClient::from_config(vec![&cfg]).await?)
                    as Arc<dyn OutboundClient>
            },
            "anytls" => {
                let cfg = Self::resolve_outbound_ech(cfg, dns_direct).await;
                Arc::new(AnyTlsOutboundClient::from_config(vec![&cfg]).await?)
                    as Arc<dyn OutboundClient>
            },
            "vless" => Arc::new(
                VlessOutboundClient::from_config(vec![cfg]).await?,
            ) as Arc<dyn OutboundClient>,
            "ssh" => Arc::new(SshOutboundClient::from_config(cfg).await?)
                as Arc<dyn OutboundClient>,
            "mless" => {
                MlessOutboundClient::from_config(vec![cfg]).await?
                    as Arc<dyn OutboundClient>
            },
            "shadowsocks" => Arc::new(
                ShadowsocksOutboundClient::from_config(cfg).await?,
            ) as Arc<dyn OutboundClient>,
            "direct" => Arc::new(DirectOutboundClient::new(tls_fragment))
                as Arc<dyn OutboundClient>,
            other => {
                return Err(format!("unknown outbound type '{other}'").into());
            },
        };
        Self::register_background_handles(&client, loop_handles);
        Ok(client)
    }

    /// Collect whatever background loops the constructed client spawned
    /// (mless pool keepalive). Generic on purpose: the factory carries no
    /// per-type knowledge, and the deferred retry path gets the same
    /// registration for free.
    fn register_background_handles(
        client: &Arc<dyn OutboundClient>,
        loop_handles: &std::sync::Mutex<Vec<tokio::task::AbortHandle>>,
    ) {
        for handle in client.background_abort_handles() {
            loop_handles.lock().expect("loop handles poisoned").push(handle);
        }
    }

    fn clients_from_direct_configs(
        configs: &[OutboundConfig],
        tls_fragment: Option<crate::tlsfragment::FragmentConfig>,
    ) -> Result<
        HashMap<String, Arc<dyn OutboundClient>>,
        Box<dyn std::error::Error>,
    > {
        let mut clients: HashMap<String, Arc<dyn OutboundClient>> =
            HashMap::new();

        for config in configs.iter().filter(|c| c.type_ == "direct") {
            clients.insert(
                Self::tag(config)?.to_string(),
                Arc::new(DirectOutboundClient::new(tls_fragment.clone())),
            );
        }

        Ok(clients)
    }

    /// Build registry from config. Connects QUIC clients etc. during
    /// construction. A "direct" outbound is always available — if not
    /// configured, one is auto-inserted.
    pub async fn from_config(
        config: &Config,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        // Same aggregate the web-UI save path and `anywhere -t` run — one
        // body, so a check added there automatically applies to startup
        // too. It tolerates defined-but-unstartable urltest children on
        // purpose: they come back as deferred clients (see
        // DeferredOutboundClient).
        Self::validate_config_refs(config)?;
        let tls_fragment = if config.common.tls_fragment {
            Some(crate::tlsfragment::FragmentConfig::default())
        } else {
            None
        };
        let mut clients: HashMap<String, Arc<dyn OutboundClient>> =
            Self::clients_from_direct_configs(
                &config.outbounds,
                tls_fragment.clone(),
            )?;

        // The implicit `direct` must exist before urltest children resolve.
        clients.entry("direct".to_string()).or_insert_with(|| {
            Arc::new(DirectOutboundClient::new(tls_fragment.clone()))
                as Arc<dyn OutboundClient>
        });

        // Shared with deferred outbounds so a construction that eventually
        // succeeds registers its background loops with the same lifecycle
        // `shutdown_test_loops` aborts on in-process reload.
        let test_loop_handles: Arc<
            std::sync::Mutex<Vec<tokio::task::AbortHandle>>,
        > = Arc::new(std::sync::Mutex::new(Vec::new()));

        for cfg in config.outbounds.iter().filter(|o| o.type_ != "direct") {
            let tag = Self::tag(cfg)?.to_string();
            match Self::construct_outbound(
                cfg,
                &config.dns.direct,
                tls_fragment.clone(),
                &test_loop_handles,
            )
            .await
            {
                Ok(client) => {
                    clients.insert(tag, client);
                },
                Err(e) => {
                    log::error!(
                        "failed to init outbound '{tag}' ({}): {e}",
                        cfg.type_,
                    );
                },
            }
        }

        // The registry carries every DEFINED node: a construction failure
        // becomes a deferred client that retries on each dial / urltest
        // probe (fault recovery), instead of vanishing until the next
        // engine restart.
        let dns_direct = config.dns.direct.clone();
        for cfg in config.outbounds.iter().filter(|o| o.type_ != "direct") {
            let tag = Self::tag(cfg)?.to_string();
            clients.entry(tag).or_insert_with(|| {
                Arc::new(DeferredOutboundClient::new(
                    cfg.clone(),
                    dns_direct.clone(),
                    tls_fragment.clone(),
                    Arc::clone(&test_loop_handles),
                )) as Arc<dyn OutboundClient>
            });
        }

        // --- urltest outbounds (must come after all referenced outbounds are
        // registered) ---
        // Handles both `type = "urltest"` and legacy `type = "select"`.
        // `select` is treated as `urltest` with `mode = "select"`.
        // The health-check loop is only spawned when `needs_health_check()`
        // is true (i.e. mode is latency or seq, not select).
        let mut urltest_states: HashMap<String, Arc<UrlTestState>> =
            HashMap::new();

        for cfg in config
            .outbounds
            .iter()
            .filter(|o| o.type_ == "urltest" || o.type_ == "select")
        {
            let tag = Self::tag(cfg)?.to_string();
            let Some(child_tags) = cfg.outbounds.clone() else {
                log::error!(
                    "{} '{tag}': missing 'outbounds' field, skipping urltest",
                    cfg.type_,
                );
                continue;
            };
            // Every child is defined (check_urltest_children) and backed by
            // a registry entry — a live client or a deferred one that
            // retries construction on each probe. A group whose children
            // are all still deferred is kept: the probe cycle is what
            // revives them.
            let valid_children = child_tags.clone();

            // Resolve mode: `type = "select"` implies Select mode;
            // `type = "urltest"` uses the `mode` field (default Latency).
            let mode = if cfg.type_ == "select" {
                urltest::SelectMode::Select
            } else {
                use std::str::FromStr;
                cfg.mode
                    .as_deref()
                    .map(|s| urltest::SelectMode::from_str(s).unwrap_or_default())
                    .unwrap_or_default()
            };

            let test_url = cfg
                .url
                .clone()
                .unwrap_or_else(|| "www.google.com".to_string());
            let interval = cfg.interval.unwrap_or(300);

            let client = UrlTestOutboundClient::new(
                valid_children,
                &clients,
                test_url,
                mode,
            );
            let state = client.state.clone();
            let test_url_for_loop = client.test_url.clone();

            urltest_states.insert(tag.clone(), state.clone());

            let client_arc = Arc::new(client) as Arc<dyn OutboundClient>;

            // Only spawn the health-check loop for modes that need it.
            if mode.needs_health_check() {
                test_loop_handles.lock().expect("loop handles poisoned").push(urltest::spawn_test_loop(
                    Arc::clone(&client_arc),
                    test_url_for_loop,
                    interval,
                ).abort_handle());
            }

            clients.insert(tag.clone(), client_arc);
        }

        // Ensure a "direct" outbound is always available (used by built-in
        // private rules).
        clients.entry("direct".to_string()).or_insert_with(|| {
            Arc::new(DirectOutboundClient::new(tls_fragment))
                as Arc<dyn OutboundClient>
        });

        // --- GLOBAL group ---
        // Auto-created urltest(mode=seq) containing all leaf outbounds.
        // In GLOBAL mode the rules engine routes all non-builtin traffic
        // here.  Seq mode gives automatic failover by default; the user
        // can pin a specific node via PUT /proxies/GLOBAL.
        //
        // Skip auto-creation if the user already configured an outbound
        // named "GLOBAL" — theirs wins.
        if !clients.contains_key("GLOBAL") {
            let global_children: Vec<String> = config
                .outbounds
                .iter()
                .enumerate()
                .filter(|(_, c)| c.type_ != "urltest")
                .map(|(i, c)| c.tag_or_default(i))
                .filter(|tag| tag != "direct" && tag != "reject")
                .filter(|tag| clients.contains_key(tag))
                .collect();

            if !global_children.is_empty() {
                let global_client = UrlTestOutboundClient::new(
                    global_children,
                    &clients,
                    "www.google.com".to_string(),
                    SelectMode::Seq,
                );

                // Derive pin from the last user rule (MATCH/catch-all).
                // If its outbound is a leaf proxy in GLOBAL's children, pin to it.
                let pin_tag = config.rules.iter().rev().find_map(|r| {
                    let is_catch_all = r.domain.is_none()
                        && r.domain_suffix.is_none()
                        && r.domain_keyword.is_none()
                        && r.ip_cidr.is_none()
                        && r.port.is_none()
                        && r.port_range.is_none()
                        && r.network.is_none()
                        && r.protocol.is_none()
                        && r.geo_url.is_none();
                    if is_catch_all {
                        Some(r.outbound.clone())
                    } else {
                        None
                    }
                });
                if let Some(ref pin) = pin_tag {
                    if global_client.state.set_fixed_by_name(pin) {
                        log::info!(
                            "GLOBAL: pinned to '{pin}' (from catch-all rule)"
                        );
                    } else {
                        log::warn!(
                            "GLOBAL: catch-all rule outbound '{pin}' is not a child, not pinning"
                        );
                    }
                }

                urltest_states
                    .insert("GLOBAL".to_string(), global_client.state.clone());
                let global_arc =
                    Arc::new(global_client) as Arc<dyn OutboundClient>;
                test_loop_handles.lock().expect("loop handles poisoned").push(urltest::spawn_test_loop(
                    Arc::clone(&global_arc),
                    "www.google.com".to_string(),
                    300,
                ).abort_handle());
                clients.insert("GLOBAL".to_string(), global_arc);
            }
        } // end if !clients.contains_key("GLOBAL")

        Ok(Self {
            clients: Arc::new(clients),
            urltest_states,
            test_loop_handles: Arc::clone(&test_loop_handles),
        })
    }

    /// Get a client by configured tag.
    pub fn get(&self, tag: &str) -> Option<&Arc<dyn OutboundClient>> {
        self.clients.get(tag)
    }

    /// Shared handle to the underlying tag->client map. Used by DnsHijack
    /// to dispatch DNS queries through the same outbound pool.
    pub fn clients_arc(&self) -> Arc<HashMap<String, Arc<dyn OutboundClient>>> {
        self.clients.clone()
    }

    /// Abort all urltest background test loops so the outbound clients they
    /// reference (esp. mless/vless mux persistent connections) are released.
    /// Called during in-process reload shutdown.
    pub fn shutdown_test_loops(&self) {
        let handles = self
            .test_loop_handles
            .lock()
            .expect("test_loop_handles poisoned")
            .drain(..)
            .collect::<Vec<_>>();
        for h in handles {
            h.abort();
        }
    }
}

/// An outbound that is defined in the config but whose construction failed
/// at startup (the placeholder server in the Android template, transient
/// DNS on one node of many). The registry holds it so urltest groups keep
/// referencing the node; **every dial or latency probe retries
/// construction** — the first success replaces the inner client
/// permanently, which makes the urltest probe cycle the fault-recovery
/// mechanism the user asked for.
struct DeferredOutboundClient {
    cfg: OutboundConfig,
    /// `dns.direct` upstreams, needed by ECH resolution for
    /// anytls/vless/quic constructions.
    dns_direct: Vec<String>,
    tls_fragment: Option<crate::tlsfragment::FragmentConfig>,
    loop_handles: Arc<std::sync::Mutex<Vec<tokio::task::AbortHandle>>>,
    /// Serializes construction retries (DNS/TLS take seconds — a tokio
    /// mutex, so probes don't block the executor while waiting).
    constructing: tokio::sync::Mutex<()>,
    inner: std::sync::RwLock<Option<Arc<dyn OutboundClient>>>,
}

impl DeferredOutboundClient {
    fn new(
        cfg: OutboundConfig, dns_direct: Vec<String>,
        tls_fragment: Option<crate::tlsfragment::FragmentConfig>,
        loop_handles: Arc<
            std::sync::Mutex<Vec<tokio::task::AbortHandle>>,
        >,
    ) -> Self {
        Self {
            cfg,
            dns_direct,
            tls_fragment,
            loop_handles,
            constructing: tokio::sync::Mutex::new(()),
            inner: std::sync::RwLock::new(None),
        }
    }

    async fn ensure(
        &self,
    ) -> Result<Arc<dyn OutboundClient>, String> {
        if let Some(client) = self.inner.read().unwrap().clone() {
            return Ok(client);
        }
        let _guard = self.constructing.lock().await;
        // Double-check: another task may have constructed while we waited.
        if let Some(client) = self.inner.read().unwrap().clone() {
            return Ok(client);
        }
        let client = OutboundRegistry::construct_outbound(
            &self.cfg,
            &self.dns_direct,
            self.tls_fragment.clone(),
            &self.loop_handles,
        )
        .await
        .map_err(|e| {
            log::warn!(
                "outbound '{}' ({}): deferred init retry failed: {e}",
                self.cfg.tag.as_deref().unwrap_or("?"),
                self.cfg.type_,
            );
            e.to_string()
        })?;
        log::info!(
            "outbound '{}' ({}) initialized on retry",
            self.cfg.tag.as_deref().unwrap_or("?"),
            self.cfg.type_,
        );
        *self.inner.write().unwrap() = Some(Arc::clone(&client));
        Ok(client)
    }
}

#[async_trait]
impl OutboundClient for DeferredOutboundClient {
    async fn dial(
        &self, dest: &Destination,
    ) -> Result<Box<dyn StreamRelay>, Box<dyn std::error::Error>> {
        // Split statements: the ensure() future (whose error path is not
        // Send) must be dropped before the inner dial's await point.
        let client =
            self.ensure().await.map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;
        client.dial(dest).await
    }

    async fn dial_udp(
        &self, initial_dest: &Destination,
    ) -> Result<Box<dyn PacketRelay>, Box<dyn std::error::Error>> {
        let client =
            self.ensure().await.map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;
        client.dial_udp(initial_dest).await
    }

    // test_latency: inherited default — it dials via Self::dial, which
    // retries construction; the probe timeout bounds each attempt, so a
    // node whose server is still down just fails its probe and is retried
    // on the next urltest cycle.
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::OutboundConfig;

    fn outbound(type_: &str, tag: Option<&str>) -> OutboundConfig {
        OutboundConfig {
            type_: type_.to_string(),
            tag: tag.map(str::to_string),
            server: None,
            password: None,
            method: None,
            plugin: None,
            plugin_opts: None,
            cmd: None,
            proxy_type: None,
            sni: None,
            fp: false,
            ech_config: None,
            outbounds: None,
            interval: None,
            url: None,
            insecure: false,
            idle_session_check_interval: None,
            idle_session_timeout: None,
            min_idle_session: None,
            xmux: None,
            wss_fronts: None,
            wss_fallback: None,
            transport: None,
            flow: None,
            reality: None,
            ech: false,
            tls_fragment: false,
            tls_fragment_config: None,
            uot: false,
            mode: None,
        }
    }

    #[test]
    fn indexes_direct_outbound_by_configured_tag() {
        let outbounds = vec![outbound("direct", Some("direct-1"))];
        let clients =
            OutboundRegistry::clients_from_direct_configs(&outbounds, None)
                .unwrap();

        assert!(clients.contains_key("direct-1"));
        assert!(!clients.contains_key("direct"));
    }

    #[test]
    fn rejects_outbound_without_tag() {
        let outbounds = vec![outbound("direct", None)];

        assert!(
            OutboundRegistry::clients_from_direct_configs(&outbounds, None)
                .is_err()
        );
    }

    #[test]
    fn validates_tags_for_all_outbound_types() {
        let outbounds = vec![outbound("quic", None)];

        assert!(OutboundRegistry::validate_tags(&outbounds).is_err());
    }

    #[test]
    fn rejects_duplicate_outbound_tags() {
        let outbounds = vec![
            outbound("direct", Some("dup")),
            outbound("mless", Some("dup")),
        ];

        let err = OutboundRegistry::validate_tags(&outbounds).unwrap_err();
        assert_eq!(err.key, "outbound_duplicate_tag");
        assert!(
            err.to_string().contains("duplicate outbound tag 'dup'"),
            "error should name the duplicated tag: {err}"
        );
    }

    /// Regression pin for the 2026-11-10 policy decision: a urltest child
    /// referencing an unknown/unstartable outbound is a WARNING at startup,
    /// never a config error. The Android default config is an
    /// intentionally-incomplete template (placeholder mless server that
    /// cannot initialize) — the engine must start with it so the Web UI is
    /// reachable for the user to fill in their real server.
    #[test]
    fn urltest_with_unknown_children_still_passes_config_validation() {
        let config = Config::from_string(
            "[[outbounds]]\n\
             type = \"mless\"\n\
             tag = \"CF\"\n\
             server = \"REDACTED\"\n\
             \n\
             [[outbounds]]\n\
             type = \"urltest\"\n\
             tag = \"auto\"\n\
             outbounds = [\"CF\"]\n\
             \n\
             [[rules]]\n\
             outbound = \"auto\"\n",
        )
        .unwrap();

        assert!(OutboundRegistry::validate_config_refs(&config).is_ok());
    }

    #[test]
    fn urltest_child_with_undefined_tag_is_fatal() {
        // Definition-level check: 'typo' is not defined anywhere — the
        // group could never resolve it, so the save (and the engine start)
        // is rejected. Contrast with the test above, where the child IS
        // defined but merely cannot initialize.
        let config = Config::from_string(
            "[[outbounds]]\n\
             type = \"direct\"\n\
             tag = \"direct-1\"\n\
             \n\
             [[outbounds]]\n\
             type = \"urltest\"\n\
             tag = \"auto\"\n\
             outbounds = [\"typo\"]\n",
        )
        .unwrap();

        let err = OutboundRegistry::validate_config_refs(&config)
            .unwrap_err();
        assert_eq!(err.key, "urltest_child_not_found");
        assert!(
            err.to_string().contains("'typo'"),
            "error should name the undefined child: {err}"
        );
    }

    #[tokio::test]
    async fn registry_holds_defined_nodes_even_when_init_fails() {
        // The Android template scenario: 'flaky' is defined with a
        // placeholder server (construction fails — unresolvable host),
        // 'healthy' initializes. Both must be present in the registry —
        // the failed one as a deferred client that retries construction
        // on each dial / urltest probe (fault recovery) — and the group
        // references both.
        let config = Config::from_string(
            "[[outbounds]]\n\
             type = \"direct\"\n\
             tag = \"healthy\"\n\
             \n\
             [[outbounds]]\n\
             type = \"mless\"\n\
             tag = \"flaky\"\n\
             server = \"REDACTED\"\n\
             \n\
             [[outbounds]]\n\
             type = \"urltest\"\n\
             tag = \"auto\"\n\
             outbounds = [\"flaky\", \"healthy\"]\n",
        )
        .unwrap();

        let registry = OutboundRegistry::from_config(&config).await.unwrap();

        assert!(registry.get("healthy").is_some());
        assert!(
            registry.get("flaky").is_some(),
            "a defined node whose init failed must stay in the registry"
        );
        assert!(registry.get("auto").is_some());

        // The deferred client retries construction on dial and surfaces
        // the failure to the caller (bounded: unresolvable host).
        let flaky = registry.get("flaky").unwrap();
        let dest: crate::inbound::Destination =
            "REDACTED:2096".parse().unwrap();
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(15),
            flaky.dial(&dest),
        )
        .await
        .expect("deferred dial must not hang");
        assert!(
            result.is_err(),
            "placeholder server cannot initialize — dial must surface the error"
        );
    }
}
