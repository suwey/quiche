use serde::Deserialize;
use std::collections::HashMap;

use serde::Deserializer;

use crate::dns::DnsConfig;

#[derive(Debug, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub common: CommonConfig,

    #[serde(default)]
    pub users: Vec<UserConfig>,

    #[serde(default)]
    pub inbounds: Vec<InboundConfig>,

    #[serde(default)]
    pub outbounds: Vec<OutboundConfig>,

    #[serde(default)]
    pub rules: Vec<RuleConfig>,

    #[serde(default)]
    pub ui: UiConfig,

    #[serde(default)]
    pub dns: DnsConfig,
}

#[derive(Debug, Deserialize)]
pub struct UserConfig {
    pub name: String,
    pub password: String,
}

#[derive(Debug, Deserialize)]
pub struct InboundConfig {
    #[serde(rename = "type")]
    pub type_: String,

    pub tag: Option<String>,

    pub listen: Option<String>,

    pub cert: Option<String>,

    pub key: Option<String>,

    // --- TUN inbound fields ---
    /// TUN device address in CIDR form (default: "10.0.0.1/24").
    #[serde(default)]
    pub addr: Option<String>,

    /// TUN device MTU.
    #[serde(default)]
    pub mtu: Option<u16>,

    /// TUN interface name (default: "tun0").
    #[serde(default)]
    pub name: Option<String>,

    /// Automatically manage policy routing rules (`ip rule`/`ip route`).
    /// When false, only the TUN device is created; no routing rules are
    /// installed. Cleanup of stale rules from previous runs still happens
    /// at startup. Default: true.
    #[serde(default = "default_true")]
    pub auto_route: bool,

    /// Automatically manage routing and iptables (bypass fwmark, policy
    /// routing, DNS REDIRECT, etc.). True for router environments. Set to
    /// false on desktop Linux (only the TUN device is created, no ip
    /// rule/iptables changes).
    #[serde(default = "default_auto_hijack")]
    pub auto_hijack: bool,
    /// When true, DNS queries from local processes (127.0.0.1) are always
    /// resolved via the direct upstream, bypassing rule matching. Useful on
    /// routers where the device's own DNS should not depend on proxy state.
    #[serde(default = "default_local_direct")]
    pub local_direct: bool,

    /// Sniff TLS SNI / HTTP Host from TCP streams to recover domain
    /// information in TUN mode. Default: true.
    #[serde(default = "default_sniff_true")]
    pub sniff: Option<bool>,

    /// WAN interfaces whose local address should bypass TUN routing via
    /// `from <wan_ip> lookup main`. These are monitored dynamically so PPPoE
    /// redial/address changes are handled. Only effective when auto_hijack is
    /// true.
    #[serde(default)]
    pub monitor_wan_ifaces: Option<Vec<String>>,

    /// LAN interfaces whose local address/subnet should bypass TUN routing
    /// via `from <lan_ip>` and `to <lan_subnet>` rules plus DNAT mangle marks.
    /// Installed at startup. Only effective when auto_hijack is true.
    #[serde(default)]
    pub bypass_lan_ifaces: Option<Vec<String>>,

    /// Custom padding scheme text for anytls inbound (optional).
    #[serde(default)]
    pub padding_scheme: Option<String>,
}

fn default_auto_hijack() -> bool {
    true
}

fn default_true() -> bool {
    true
}

fn default_sniff_true() -> Option<bool> {
    Some(true)
}
fn default_local_direct() -> bool {
    true
}
/// WebSocket transport configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct WsConfig {
    pub path: Option<String>,
    pub headers: Option<HashMap<String, String>>,
}

/// Nested transport configuration.
#[derive(Debug, Deserialize)]
pub struct TransportConfig {
    #[serde(rename = "type")]
    pub type_: String,
    pub ws: Option<WsConfig>,
    pub xhttp: Option<crate::transport::xhttp::config::XhttpConfig>,
}

#[derive(Debug, Deserialize, Default)]
pub struct OutboundConfig {
    #[serde(rename = "type")]
    pub type_: String,

    pub tag: Option<String>,

    pub server: Option<String>,

    pub password: Option<String>,

    /// Shadowsocks 2022 加密方法 (e.g. "2022-blake3-aes-256-gcm").
    pub method: Option<String>,

    /// SIP003 plugin name (e.g. "obfs-local"). Shadowsocks only.
    pub plugin: Option<String>,

    /// SIP003 plugin options (semicolon-delimited k=v, e.g. "obfs=http;obfs-host=example.com").
    pub plugin_opts: Option<String>,

    /// UDP-over-TCP (UoT): tunnel UDP over the TCP stream instead of native
    /// UDP relay. For servers without UDP support (shadowsocks / anytls).
    /// Default: false.
    #[serde(default)]
    pub uot: bool,

    /// Command to spawn for tunnel creation (used by SSH outbound).
    /// e.g. `ssh -D 1080 -N user@host`.
    pub cmd: Option<String>,

    /// Proxy protocol for SSH outbound: "socks5" or "http" (default).
    pub proxy_type: Option<String>,

    /// TLS SNI for anytls / vless outbound (default: server hostname).
    pub sni: Option<String>,

    #[serde(default = "default_true")]
    pub fp: bool,

    pub ech_config: Option<String>,

    /// Enable TLS ClientHello fragmentation with jitter to evade DPI SNI matching.
    /// Default: true. Fragments the first TLS write across multiple TCP
    /// segments with random sizes and delays.
    #[serde(default = "default_true")]
    pub tls_fragment: bool,

    // --- shared sub-config fields (urltest / vless) ---
    /// List of outbound tags this urltest node manages.
    #[serde(default)]
    pub outbounds: Option<Vec<String>>,

    /// Interval between latency tests in seconds (default: 600).
    pub interval: Option<u64>,

    /// Selection mode for urltest groups: "latency" (default) picks the
    /// lowest-latency child; "seq" picks the first alive child in order
    /// (a.k.a. fallback semantics).
    pub mode: Option<String>,

    /// URL to test latency against (e.g. "www.google.com").
    pub url: Option<String>,

    // --- vless flat fields ---
    /// Disable TLS certificate verification.
    #[serde(default)]
    pub insecure: bool,
    /// Nested transport config.
    #[serde(default)]
    pub transport: Option<TransportConfig>,

    // --- anytls session pool ---
    /// How often the pool cleanup task runs (seconds, default: 60).
    pub idle_session_check_interval: Option<u64>,

    /// Sessions idle longer than this are eligible for removal (seconds,
    /// default: 180).
    pub idle_session_timeout: Option<u64>,

    /// Minimum number of sessions to keep alive in the pool (default: 2).
    pub min_idle_session: Option<usize>,

    /// Connection pool tuning (applies to vless/mless/xhttp outbounds).
    /// Configured as a top-level `[outbounds.xmux]` section.
    /// For vless: `pool_size` controls the number of pre-built WS connections.
    /// For mless: `pool_size` controls the number of parallel WS multiplexers.
    /// For xhttp: uses `max_concurrency`, `max_connections`, etc.
    #[serde(default)]
    pub xmux: Option<crate::transport::xhttp::config::XmuxConfig>,
}

fn default_rule_type() -> String {
    "default".to_string()
}

#[derive(Debug, Deserialize, Clone)]
pub struct RuleConfig {
    #[serde(rename = "type", default = "default_rule_type")]
    pub type_: String,

    #[serde(default, deserialize_with = "deserialize_string_or_vec")]
    pub domain: Option<Vec<String>>,

    #[serde(default, deserialize_with = "deserialize_string_or_vec")]
    pub domain_suffix: Option<Vec<String>>,

    #[serde(default, deserialize_with = "deserialize_string_or_vec")]
    pub domain_keyword: Option<Vec<String>>,

    #[serde(default, deserialize_with = "deserialize_string_or_vec")]
    pub ip_cidr: Option<Vec<String>>,

    pub port: Option<u16>,

    /// Inclusive range "min-max", e.g. "8000-9000".
    pub port_range: Option<String>,

    /// "tcp" or "udp".
    pub network: Option<String>,

    /// Protocol shorthand — expands to known port/network combinations.
    /// Supported: "bittorrent" (tcp:6881-6889, udp:6881).
    pub protocol: Option<String>,

    pub outbound: String,

    /// URL to a sing-box rule-set (.srs) file containing geo rules (site + ip).
    pub geo_url: Option<String>,

    /// Update interval string like "3d", "24h", "30m".
    pub update_interval: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
pub struct CommonConfig {
    pub cache_dir: Option<String>,
    /// Enable TLS ClientHello fragmentation on direct outbound connections
    /// to evade DPI SNI matching. Default: false.
    #[serde(default)]
    pub tls_fragment: bool,
}

#[derive(Debug, Deserialize, Clone, Default)]
pub struct UiConfig {
    pub listen: Option<String>,
    pub secret: Option<String>,
    pub serve_path: Option<String>,
}

impl Config {
    pub fn load(path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let base_dir = std::path::Path::new(path)
            .parent()
            .unwrap_or(std::path::Path::new("."));

        let mut config: Config = toml::from_str(&std::fs::read_to_string(path)?)?;

        // Resolve relative cert/key paths relative to the config file directory.
        for inbound in &mut config.inbounds {
            resolve_path(&base_dir, &mut inbound.cert);
            resolve_path(&base_dir, &mut inbound.key);
        }

        // Resolve relative serve_path relative to the config file directory.
        resolve_path(&base_dir, &mut config.ui.serve_path);

        Ok(config)
    }

    /// Parse config from an inline TOML string (used by Android JNI where
    /// no file system path is available).
    pub fn from_string(content: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let config: Config = toml::from_str(content)?;
        Ok(config)
    }

    pub fn outbounds_by_type(&self, type_name: &str) -> Vec<&OutboundConfig> {
        self.outbounds
            .iter()
            .filter(|o| o.type_ == type_name)
            .collect()
    }

    pub fn inbounds_by_type(&self, type_name: &str) -> Vec<&InboundConfig> {
        self.inbounds
            .iter()
            .filter(|i| i.type_ == type_name)
            .collect()
    }

    pub fn passwords(&self) -> Vec<String> {
        self.users.iter().map(|u| u.password.clone()).collect()
    }
}

impl InboundConfig {
    pub fn tag_or_default(&self, idx: usize) -> String {
        self.tag.clone().unwrap_or_else(|| format!("inbound-{idx}"))
    }
}

impl OutboundConfig {
    pub fn tag_or_default(&self, idx: usize) -> String {
        self.tag
            .clone()
            .unwrap_or_else(|| format!("outbound-{idx}"))
    }
}

/// Deserialize an `Option<Vec<String>>` from either a single string or an array
/// of strings.
fn deserialize_string_or_vec<'de, D>(
    d: D,
) -> Result<Option<Vec<String>>, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de;

    struct Visitor;

    impl<'de> de::Visitor<'de> for Visitor {
        type Value = Option<Vec<String>>;

        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("a string or array of strings")
        }

        fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
            Ok(Some(vec![v.to_string()]))
        }

        fn visit_seq<A: de::SeqAccess<'de>>(
            self, mut seq: A,
        ) -> Result<Self::Value, A::Error> {
            let mut v = Vec::new();
            while let Some(elem) = seq.next_element::<String>()? {
                v.push(elem);
            }
            if v.is_empty() { Ok(None) } else { Ok(Some(v)) }
        }

        fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
            Ok(None)
        }

        fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
            Ok(None)
        }
    }

    d.deserialize_any(Visitor)
}
fn resolve_path(base: &std::path::Path, path: &mut Option<String>) {
    if let Some(p) = path {
        let p_path = std::path::Path::new(p.as_str());
        if p_path.is_relative() {
            *p = base.join(p_path).to_string_lossy().to_string();
        }
    }
}
