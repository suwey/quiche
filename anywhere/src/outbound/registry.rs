use std::collections::HashMap;
use std::sync::Arc;

use crate::config::Config;
use crate::config::OutboundConfig;
use crate::outbound::OutboundClient;
use crate::outbound::anytls::AnyTlsOutboundClient;
use crate::outbound::direct::DirectOutboundClient;
use crate::outbound::mless::MlessOutboundClient;
use crate::outbound::quic::QuicOutboundClient;
use crate::outbound::ssh::SshOutboundClient;
use crate::outbound::urltest::UrlTestOutboundClient;
use crate::outbound::urltest::UrlTestState;
use crate::outbound::urltest::{
    self,
};
use crate::outbound::vless::VlessOutboundClient;

/// Holds outbound clients keyed by configured tag.
pub struct OutboundRegistry {
    clients: Arc<HashMap<String, Arc<dyn OutboundClient>>>,
    /// Per-urltest-node shared states for UI access.
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

        // --- urltest outbounds (must come after all referenced outbounds are
        // registered) ---
        let mut urltest_states: HashMap<String, Arc<UrlTestState>> =
            HashMap::new();
        let mut test_loop_handles: Vec<tokio::task::JoinHandle<()>> =
            Vec::new();

        for cfg in config.outbounds.iter().filter(|o| o.type_ == "urltest") {
            let tag = Self::tag(cfg)?.to_string();
            let child_tags = cfg.outbounds.clone().ok_or_else(|| {
                format!("urltest '{tag}': missing 'outbounds' field")
            })?;

            // Filter out children that failed initialization, log a warning.
            let valid_children: Vec<String> = child_tags
                .into_iter()
                .filter(|t| {
                    if clients.contains_key(t) {
                        true
                    } else {
                        log::warn!(
                            "urltest '{tag}': child '{}' not found, skipping",
                            t,
                        );
                        false
                    }
                })
                .collect();

            if valid_children.is_empty() {
                log::error!(
                    "urltest '{tag}': no valid children, skipping urltest"
                );
                continue;
            }

            let test_url = cfg
                .url
                .clone()
                .unwrap_or_else(|| "www.google.com".to_string());
            let interval = cfg.interval.unwrap_or(600);

            let client =
                UrlTestOutboundClient::new(valid_children, &clients, test_url);
            let state = client.state.clone();
            let test_url_for_loop = client.test_url.clone();

            urltest_states.insert(tag.clone(), state.clone());

            let client_arc = Arc::new(client) as Arc<dyn OutboundClient>;
            test_loop_handles.push(urltest::spawn_test_loop(
                Arc::clone(&client_arc),
                test_url_for_loop,
                interval,
            ));

            clients.insert(tag.clone(), client_arc);
        }

        // Ensure a "direct" outbound is always available (used by built-in
        // private rules).
        clients.entry("direct".to_string()).or_insert_with(|| {
            Arc::new(DirectOutboundClient) as Arc<dyn OutboundClient>
        });

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
        OutboundConfig {
            type_: type_.to_string(),
            tag: tag.map(str::to_string),
            server: None,
            password: None,
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
            tls_fragment: false,
        }
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
