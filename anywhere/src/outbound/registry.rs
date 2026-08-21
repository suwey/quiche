use std::collections::HashMap;
use std::sync::Arc;

use crate::config::Config;
use crate::config::OutboundConfig;
use crate::outbound::OutboundClient;
use crate::outbound::anytls::AnyTlsOutboundClient;
use crate::outbound::direct::DirectOutboundClient;
use crate::outbound::mless::MlessOutboundClient;
use crate::outbound::quic::QuicOutboundClient;
use crate::outbound::urltest::UrlTestOutboundClient;
use crate::outbound::urltest::UrlTestState;
use crate::outbound::urltest::{
    self, SelectMode,
};
use crate::outbound::shadowsocks::ShadowsocksOutboundClient;
use crate::outbound::ssh::SshOutboundClient;
use crate::outbound::vless::VlessOutboundClient;

/// Holds outbound clients keyed by configured tag.
pub struct OutboundRegistry {
    clients: Arc<HashMap<String, Arc<dyn OutboundClient>>>,
    /// Per-group shared states for UI access (all group types unified).
    pub urltest_states: HashMap<String, Arc<UrlTestState>>,
    /// JoinHandles of urltest background test loops. Aborted on in-process
    /// reload so the outbound clients they hold (esp. mless/vless mux
    /// persistent connections) are released before the next run() iteration.
    test_loop_handles: std::sync::Mutex<Vec<tokio::task::JoinHandle<()>>>,
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
    ) -> Result<(), Box<dyn std::error::Error>> {
        for config in configs {
            Self::tag(config)?;
        }
        Ok(())
    }

    fn clients_from_direct_configs(
        configs: &[OutboundConfig],
    ) -> Result<
        HashMap<String, Arc<dyn OutboundClient>>,
        Box<dyn std::error::Error>,
    > {
        let mut clients: HashMap<String, Arc<dyn OutboundClient>> =
            HashMap::new();

        for config in configs.iter().filter(|c| c.type_ == "direct") {
            clients.insert(
                Self::tag(config)?.to_string(),
                Arc::new(DirectOutboundClient),
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
        Self::validate_tags(&config.outbounds)?;
        let mut clients: HashMap<String, Arc<dyn OutboundClient>> =
            Self::clients_from_direct_configs(&config.outbounds)?;

        for cfg in config.outbounds.iter().filter(|o| o.type_ == "quic") {
            let client = QuicOutboundClient::from_config(vec![cfg]).await?;
            clients.insert(Self::tag(cfg)?.to_string(), Arc::new(client));
        }

        for cfg in config.outbounds.iter().filter(|o| o.type_ == "anytls") {
            match AnyTlsOutboundClient::from_config(vec![cfg]).await {
                Ok(client) => {
                    clients.insert(Self::tag(cfg)?.to_string(), Arc::new(client));
                },
                Err(e) => {
                    log::error!(
                        "failed to init anytls outbound '{}': {e}",
                        Self::tag(cfg).unwrap_or("?"),
                    );
                },
            }
        }
        for cfg in config.outbounds.iter().filter(|o| o.type_ == "vless") {
            match VlessOutboundClient::from_config(vec![cfg]).await {
                Ok(client) => {
                    clients.insert(Self::tag(cfg)?.to_string(), Arc::new(client));
                },
                Err(e) => {
                    log::error!(
                        "failed to init vless outbound '{}': {e}",
                        Self::tag(cfg).unwrap_or("?"),
                    );
                },
            }
        }

        for cfg in config.outbounds.iter().filter(|o| o.type_ == "ssh") {
            match SshOutboundClient::from_config(cfg).await {
                Ok(client) => {
                    clients.insert(Self::tag(cfg)?.to_string(), Arc::new(client));
                },
                Err(e) => {
                    log::error!(
                        "failed to init ssh outbound '{}': {e}",
                        Self::tag(cfg).unwrap_or("?"),
                    );
                },
            }
        }

        for cfg in config.outbounds.iter().filter(|o| o.type_ == "mless") {
            match MlessOutboundClient::from_config(vec![cfg]).await {
                Ok(client) => {
                    clients.insert(Self::tag(cfg)?.to_string(), Arc::new(client));
                },
                Err(e) => {
                    log::error!(
                        "failed to init mless outbound '{}': {e}",
                        Self::tag(cfg).unwrap_or("?"),
                    );
                },
            }
        }

        for cfg in config.outbounds.iter().filter(|o| o.type_ == "shadowsocks") {
            match ShadowsocksOutboundClient::from_config(cfg).await {
                Ok(client) => {
                    clients.insert(Self::tag(cfg)?.to_string(), Arc::new(client));
                },
                Err(e) => {
                    log::error!(
                        "failed to init shadowsocks outbound '{}': {e}",
                        Self::tag(cfg).unwrap_or("?"),
                    );
                },
            }
        }

        // --- urltest outbounds (must come after all referenced outbounds are
        // registered) ---
        // Handles both `type = "urltest"` and legacy `type = "select"`.
        // `select` is treated as `urltest` with `mode = "select"`.
        // The health-check loop is only spawned when `needs_health_check()`
        // is true (i.e. mode is latency or seq, not select).
        let mut urltest_states: HashMap<String, Arc<UrlTestState>> =
            HashMap::new();
        let mut test_loop_handles: Vec<tokio::task::JoinHandle<()>> =
            Vec::new();

        for cfg in config
            .outbounds
            .iter()
            .filter(|o| o.type_ == "urltest" || o.type_ == "select")
        {
            let tag = Self::tag(cfg)?.to_string();
            let child_tags = cfg.outbounds.clone().ok_or_else(|| {
                format!("{} '{tag}': missing 'outbounds' field", cfg.type_)
            })?;

            // Filter out children that failed initialization, log a warning.
            let valid_children: Vec<String> = child_tags
                .into_iter()
                .filter(|t| {
                    if clients.contains_key(t) {
                        true
                    } else {
                        log::warn!(
                            "{} '{tag}': child '{}' not found, skipping",
                            cfg.type_,
                            t,
                        );
                        false
                    }
                })
                .collect();

            if valid_children.is_empty() {
                log::error!(
                    "{} '{tag}': no valid children, skipping",
                    cfg.type_
                );
                continue;
            }

            // Resolve mode: `type = "select"` implies Select mode;
            // `type = "urltest"` uses the `mode` field (default Latency).
            let mode = if cfg.type_ == "select" {
                urltest::SelectMode::Select
            } else {
                cfg.mode
                    .as_deref()
                    .map(urltest::SelectMode::from_str)
                    .unwrap_or_default()
            };

            let test_url = cfg
                .url
                .clone()
                .unwrap_or_else(|| "www.google.com".to_string());
            let interval = cfg.interval.unwrap_or(300);

            let client =
                UrlTestOutboundClient::new(valid_children, &clients, test_url, mode);
            let state = client.state.clone();
            let test_url_for_loop = client.test_url.clone();

            urltest_states.insert(tag.clone(), state.clone());

            let client_arc = Arc::new(client) as Arc<dyn OutboundClient>;

            // Only spawn the health-check loop for modes that need it.
            if mode.needs_health_check() {
                test_loop_handles.push(urltest::spawn_test_loop(
                    Arc::clone(&client_arc),
                    test_url_for_loop,
                    interval,
                ));
            }

            clients.insert(tag.clone(), client_arc);
        }

        // Ensure a "direct" outbound is always available (used by built-in
        // private rules).
        clients.entry("direct".to_string()).or_insert_with(|| {
            Arc::new(DirectOutboundClient) as Arc<dyn OutboundClient>
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
                if is_catch_all { Some(r.outbound.clone()) } else { None }
            });
            if let Some(ref pin) = pin_tag {
                if global_client.state.set_fixed_by_name(pin) {
                    log::info!("GLOBAL: pinned to '{pin}' (from catch-all rule)");
                } else {
                    log::warn!("GLOBAL: catch-all rule outbound '{pin}' is not a child, not pinning");
                }
            }

            urltest_states.insert(
                "GLOBAL".to_string(),
                global_client.state.clone(),
            );
            let global_arc = Arc::new(global_client) as Arc<dyn OutboundClient>;
            test_loop_handles.push(urltest::spawn_test_loop(
                Arc::clone(&global_arc),
                "www.google.com".to_string(),
                300,
            ));
            clients.insert("GLOBAL".to_string(), global_arc);
        }
        } // end if !clients.contains_key("GLOBAL")

        Ok(Self {
            clients: Arc::new(clients),
            urltest_states,
            test_loop_handles: std::sync::Mutex::new(test_loop_handles),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::OutboundConfig;

    fn outbound(type_: &str, tag: Option<&str>) -> OutboundConfig {
        OutboundConfig { type_: type_.to_string(),
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
        transport: None,
        tls_fragment: false, uot: false, mode: None }
    }

    #[test]
    fn indexes_direct_outbound_by_configured_tag() {
        let outbounds = vec![outbound("direct", Some("direct-1"))];
        let clients =
            OutboundRegistry::clients_from_direct_configs(&outbounds).unwrap();

        assert!(clients.contains_key("direct-1"));
        assert!(!clients.contains_key("direct"));
    }

    #[test]
    fn rejects_outbound_without_tag() {
        let outbounds = vec![outbound("direct", None)];

        assert!(
            OutboundRegistry::clients_from_direct_configs(&outbounds).is_err()
        );
    }

    #[test]
    fn validates_tags_for_all_outbound_types() {
        let outbounds = vec![outbound("quic", None)];

        assert!(OutboundRegistry::validate_tags(&outbounds).is_err());
    }
}
