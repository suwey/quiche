//! Subscription import — fetch a subscription URL and convert proxies to
//! anywhere TOML config format.
//!
//! Supported input formats (auto-detected):
//! 1. Clash YAML (`proxies:` section)
//! 2. sing-box JSON (`outbounds` array)
//! 3. Base64-encoded node list (one URI per line)
//! 4. Plain-text node URIs (`ss://`, `vless://`, `vmess://`, ...)
//!
//! Supported outbound types (converted to anywhere TOML):
//! - `ss` / `shadowsocks`  → `[[outbounds]] type = "shadowsocks"`
//! - `anytls`              → `[[outbounds]] type = "anytls"`
//! - `vless`               → `[[outbounds]] type = "vless"` (WS transport, or
//!   the REALITY transport when the source carries REALITY params:
//!   `security=reality&pbk=&sid=` in URIs, Clash `reality-opts`, sing-box
//!   `tls.reality`)
//!
//! Unsupported types are printed as `skip: <type>...` and omitted from output.

use std::collections::HashMap;

use base64::Engine;

/// Supported proxy types in anywhere.
const SUPPORTED_TYPES: &[&str] = &["shadowsocks", "ss", "anytls", "vless"];

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Fetch a subscription URL and return the response (body + selected headers).
pub async fn fetch_subscription(
    url: &str, ua: &str,
) -> Result<crate::http_client::HttpResponse, String> {
    crate::http_client::http_get_with_headers(url, ua).await
}

/// Convert raw subscription bytes to anywhere TOML config text.
///
/// For Clash YAML the output includes `[[outbounds]]` (proxies + `url-test`
/// groups), `[[rules]]`, and `[dns]` where the subscription provides them.
/// sing-box JSON and URI lists produce outbounds only. Unsupported proxy /
/// rule types are collected into the `skip` list.
pub fn convert_subscription(
    body: &[u8], skips: &mut Vec<String>,
) -> Result<String, String> {
    let body_str = String::from_utf8_lossy(body);

    let sub = if body_str.trim_start().starts_with('{') {
        // sing-box JSON
        SubOutput {
            outbounds: parse_singbox_json(&body_str, skips)?,
            rules: Vec::new(),
            dns: None,
        }
    } else if body_str.contains("proxies:") || body_str.contains("proxies :") {
        // Clash YAML
        parse_clash_yaml(&body_str, skips)?
    } else {
        // Try base64 decode, then plain text URIs.
        SubOutput {
            outbounds: parse_uri_list(&body_str, skips)?,
            rules: Vec::new(),
            dns: None,
        }
    };

    Ok(render_sub_output(&sub))
}

// ---------------------------------------------------------------------------
// Outbound TOML representation
// ---------------------------------------------------------------------------

/// A single outbound entry in the TOML output.
/// Fields are kept in insertion order for clean rendering.
pub struct TomlOutbound {
    pub type_: String,
    pub tag: String,
    pub fields: Vec<(String, TomlValue)>,
    /// Optional nested `[outbounds.transport]` section.
    pub transport: Option<TransportConfig>,
    /// Optional nested `[outbounds.reality]` section (REALITY transport).
    pub reality: Option<RealitySection>,
    /// OpenRung WSS CDN fronts, rendered as `[[outbounds.wss_fronts]]`
    /// array-of-tables entries (OpenRung directory import only).
    pub wss_fronts: Vec<WssFrontSection>,
    /// Optional `[outbounds.wss_fallback]` section (OpenRung directory import
    /// only) — carries the broker base URL used for WSS ticket requests.
    pub wss_fallback: Option<WssFallbackSection>,
}

pub enum TomlValue {
    Str(String),
    Int(i64),
    Bool(bool),
    List(Vec<String>),
}

pub struct TransportConfig {
    pub type_: String,
    pub ws_path: Option<String>,
    pub ws_headers: Option<HashMap<String, String>>,
}

/// `[outbounds.reality]` section — its presence enables the REALITY transport.
pub struct RealitySection {
    pub public_key: String,
    /// Always rendered: sources that omit short_id mean the zero short id,
    /// and anywhere's `RealityConfig` requires the field.
    pub short_id: String,
}

/// One `[[outbounds.wss_fronts]]` entry — a signed, relay-specific OpenRung
/// WSS CDN front (crate::wssfront::WssFront on the wire).
pub struct WssFrontSection {
    pub id: String,
    pub url: String,
    pub protocol_version: i64,
}

/// `[outbounds.wss_fallback]` section — direct-first WSS/CDN fallback knobs.
pub struct WssFallbackSection {
    /// Broker base URL for WSS session ticket requests
    /// (POST {broker}/api/v1/wss/tickets).
    pub broker: String,
    /// The OpenRung relay ID (`relay_...`) bound into tickets.
    pub relay_id: String,
}

impl TomlOutbound {
    pub fn new(type_: &str, tag: &str) -> Self {
        Self {
            type_: type_.to_string(),
            tag: tag.to_string(),
            fields: Vec::new(),
            transport: None,
            reality: None,
            wss_fronts: Vec::new(),
            wss_fallback: None,
        }
    }

    pub fn field(mut self, key: &str, val: impl Into<TomlValue>) -> Self {
        self.fields.push((key.to_string(), val.into()));
        self
    }

    pub fn set_transport(&mut self, transport: TransportConfig) {
        self.transport = Some(transport);
    }

    pub fn set_reality(&mut self, reality: RealitySection) {
        self.reality = Some(reality);
    }
}

impl From<String> for TomlValue {
    fn from(v: String) -> Self {
        TomlValue::Str(v)
    }
}

impl From<&str> for TomlValue {
    fn from(v: &str) -> Self {
        TomlValue::Str(v.to_string())
    }
}

impl From<i64> for TomlValue {
    fn from(v: i64) -> Self {
        TomlValue::Int(v)
    }
}

impl From<bool> for TomlValue {
    fn from(v: bool) -> Self {
        TomlValue::Bool(v)
    }
}

impl From<u16> for TomlValue {
    fn from(v: u16) -> Self {
        TomlValue::Int(v as i64)
    }
}

impl From<u32> for TomlValue {
    fn from(v: u32) -> Self {
        TomlValue::Int(v as i64)
    }
}

impl From<u64> for TomlValue {
    fn from(v: u64) -> Self {
        TomlValue::Int(v as i64)
    }
}

impl From<Vec<String>> for TomlValue {
    fn from(v: Vec<String>) -> Self {
        TomlValue::List(v)
    }
}

/// Render `Vec<(String, TomlValue)>` as TOML `key = value` lines.
fn render_fields(fields: &[(String, TomlValue)]) -> String {
    let mut out = String::new();
    for (k, v) in fields {
        match v {
            TomlValue::Str(s) => {
                out.push_str(&format!("{k} = \"{}\"\n", escape_toml_str(s)));
            },
            TomlValue::Int(i) => {
                out.push_str(&format!("{k} = {i}\n"));
            },
            TomlValue::Bool(b) => {
                out.push_str(&format!("{k} = {b}\n"));
            },
            TomlValue::List(items) => {
                if items.is_empty() {
                    continue;
                }
                if items.len() == 1 {
                    out.push_str(&format!(
                        "{k} = [\"{}\"]\n",
                        escape_toml_str(&items[0])
                    ));
                } else {
                    out.push_str(&format!(
                        "{k} = [\n{}\n]\n",
                        items
                            .iter()
                            .map(|s| format!("    \"{}\"", escape_toml_str(s)))
                            .collect::<Vec<_>>()
                            .join(",\n")
                    ));
                }
            },
        }
    }
    out
}

/// Render a list of outbounds as TOML text.
fn outbounds_to_toml(outbounds: &[TomlOutbound]) -> String {
    let mut out = String::new();
    for ob in outbounds {
        out.push_str("[[outbounds]]\n");
        out.push_str(&format!("type = \"{}\"\n", ob.type_));
        out.push_str(&format!("tag = \"{}\"\n", ob.tag));
        out.push_str(&render_fields(&ob.fields));
        if let Some(t) = &ob.transport {
            out.push_str("\n[outbounds.transport]\n");
            out.push_str(&format!("type = \"{}\"\n", t.type_));
            if let Some(p) = &t.ws_path {
                out.push_str("\n[outbounds.transport.ws]\n");
                out.push_str(&format!("path = \"{}\"\n", escape_toml_str(p)));
                if let Some(h) = &t.ws_headers {
                    out.push_str("headers = { ");
                    let entries: Vec<String> = h
                        .iter()
                        .map(|(k, v)| {
                            format!(
                                "{} = \"{}\"",
                                escape_toml_str(k),
                                escape_toml_str(v)
                            )
                        })
                        .collect();
                    out.push_str(&entries.join(", "));
                    out.push_str(" }\n");
                }
            }
        }
        if let Some(r) = &ob.reality {
            out.push_str("\n[outbounds.reality]\n");
            out.push_str(&format!(
                "public_key = \"{}\"\n",
                escape_toml_str(&r.public_key)
            ));
            out.push_str(&format!(
                "short_id = \"{}\"\n",
                escape_toml_str(&r.short_id)
            ));
        }
        for f in &ob.wss_fronts {
            out.push_str("\n[[outbounds.wss_fronts]]\n");
            out.push_str(&format!("id = \"{}\"\n", escape_toml_str(&f.id)));
            out.push_str(&format!("url = \"{}\"\n", escape_toml_str(&f.url)));
            out.push_str(&format!(
                "protocol_version = {}\n",
                f.protocol_version
            ));
        }
        if let Some(fb) = &ob.wss_fallback {
            out.push_str("\n[outbounds.wss_fallback]\n");
            out.push_str(&format!(
                "broker = \"{}\"\n",
                escape_toml_str(&fb.broker)
            ));
            out.push_str(&format!(
                "relay_id = \"{}\"\n",
                escape_toml_str(&fb.relay_id)
            ));
        }
        out.push('\n');
    }
    out
}

/// Public renderer for `TomlOutbound` lists — shared with the OpenRung
/// directory import (`--sub-openrung`), which emits the same `[[outbounds]]`
/// shape from a signed relay list instead of a subscription payload.
pub fn render_outbounds(outbounds: &[TomlOutbound]) -> String {
    outbounds_to_toml(outbounds)
}

fn escape_toml_str(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

// ---------------------------------------------------------------------------
// Rules / DNS / full sub output
// ---------------------------------------------------------------------------

/// A single `[[rules]]` entry. Match fields are rendered first, `outbound`
/// last (matching the example config order).
struct TomlRule {
    outbound: String,
    fields: Vec<(String, TomlValue)>,
}

impl TomlRule {
    fn new(outbound: impl Into<String>) -> Self {
        Self {
            outbound: outbound.into(),
            fields: Vec::new(),
        }
    }

    fn field(mut self, key: &str, val: impl Into<TomlValue>) -> Self {
        self.fields.push((key.to_string(), val.into()));
        self
    }
}

/// The `[dns]` section (`direct` / `remote` / `fakeip`).
struct TomlDns {
    fields: Vec<(String, TomlValue)>,
}

/// Full subscription output: outbounds + rules + optional dns.
struct SubOutput {
    outbounds: Vec<TomlOutbound>,
    rules: Vec<TomlRule>,
    dns: Option<TomlDns>,
}

fn rules_to_toml(rules: &[TomlRule]) -> String {
    let mut out = String::new();
    for r in rules {
        out.push_str("[[rules]]\n");
        out.push_str(&render_fields(&r.fields));
        out.push_str(&format!(
            "outbound = \"{}\"\n",
            escape_toml_str(&r.outbound)
        ));
        out.push('\n');
    }
    out
}

fn dns_to_toml(dns: &TomlDns) -> String {
    let mut out = String::from("[dns]\n");
    out.push_str(&render_fields(&dns.fields));
    out.push('\n');
    out
}

fn render_sub_output(sub: &SubOutput) -> String {
    let mut out = outbounds_to_toml(&sub.outbounds);
    if !sub.rules.is_empty() {
        out.push_str(&rules_to_toml(&sub.rules));
    }
    if let Some(dns) = &sub.dns {
        out.push_str(&dns_to_toml(dns));
    }
    out
}

// ---------------------------------------------------------------------------
// Clash YAML parser
// ---------------------------------------------------------------------------

fn parse_clash_yaml(
    text: &str, skips: &mut Vec<String>,
) -> Result<SubOutput, String> {
    let yaml: noyalib::Value =
        noyalib::from_str(text).map_err(|e| format!("YAML parse error: {e}"))?;

    let proxies = yaml
        .get("proxies")
        .and_then(|v| v.as_sequence())
        .ok_or("no 'proxies' section found in Clash YAML")?;

    let mut outbounds = Vec::new();
    let mut proxy_tags: std::collections::HashSet<String> =
        std::collections::HashSet::new();
    for proxy in proxies {
        let ptype = proxy
            .get("type")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");

        let name = proxy
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("unnamed");

        let ob = match ptype {
            "ss" => parse_clash_ss(proxy, name),
            "anytls" => parse_clash_anytls(proxy, name),
            "vless" => parse_clash_vless(proxy, name),
            other => {
                if !SUPPORTED_TYPES.contains(&other) {
                    skips.push(other.to_string());
                }
                None
            },
        };
        if let Some(ob) = ob {
            proxy_tags.insert(ob.tag.clone());
            outbounds.push(ob);
        }
    }

    // proxy-groups: collect url-test and select group names for valid_refs.
    let (urltest_names, select_names): (
        std::collections::HashSet<String>,
        std::collections::HashSet<String>,
    ) = yaml
        .get("proxy-groups")
        .and_then(|v| v.as_sequence())
        .map(|gs| {
            let mut ut = std::collections::HashSet::new();
            let mut sel = std::collections::HashSet::new();
            for g in gs {
                let gtype = g.get("type").and_then(|v| v.as_str());
                let name = g
                    .get("name")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                match (gtype, name) {
                    (Some("url-test") | Some("fallback"), Some(n)) => {
                        ut.insert(n);
                    },
                    (Some("select"), Some(n)) => {
                        sel.insert(n);
                    },
                    _ => {},
                }
            }
            (ut, sel)
        })
        .unwrap_or_default();

    // Valid outbound reference set = proxies + url-test groups + select groups.
    let mut valid_refs = proxy_tags.clone();
    valid_refs.extend(urltest_names.iter().cloned());
    valid_refs.extend(select_names.iter().cloned());

    if let Some(groups) = yaml.get("proxy-groups").and_then(|v| v.as_sequence()) {
        for g in groups {
            let gtype = g.get("type").and_then(|v| v.as_str()).unwrap_or("");
            let gname =
                g.get("name").and_then(|v| v.as_str()).unwrap_or("unnamed");
            if gtype == "url-test" {
                if let Some(ob) = parse_clash_urltest(g, gname, &valid_refs) {
                    outbounds.push(ob);
                }
            } else if gtype == "select" {
                if let Some(ob) = parse_clash_urltest(g, gname, &valid_refs) {
                    outbounds.push(ob.field("mode", "select"));
                }
            } else if gtype == "fallback" {
                if let Some(ob) = parse_clash_urltest(g, gname, &valid_refs) {
                    outbounds.push(ob.field("mode", "seq"));
                }
            } else if !matches!(gtype, "load-balance" | "relay" | "") {
                skips.push(format!("group:{gtype}"));
            }
        }
    }

    let rules = yaml
        .get("rules")
        .and_then(|v| v.as_sequence())
        .map(|rs| parse_clash_rules(rs, &valid_refs, skips))
        .unwrap_or_default();

    let dns = yaml
        .get("dns")
        .and_then(|v| v.as_mapping())
        .and_then(parse_clash_dns);

    Ok(SubOutput {
        outbounds,
        rules,
        dns,
    })
}

fn parse_clash_ss(proxy: &noyalib::Value, name: &str) -> Option<TomlOutbound> {
    let server = proxy.get("server")?.as_str()?;
    let port = proxy.get("port")?.as_u64()? as u16;
    let cipher = proxy.get("cipher").and_then(|v| v.as_str())?;
    let password = proxy.get("password").and_then(|v| v.as_str())?;

    let mut ob = TomlOutbound::new("shadowsocks", name)
        .field("server", format!("{server}:{port}"))
        .field("method", cipher)
        .field("password", password);

    // Parse SIP003 plugin
    if let Some(plugin) = proxy.get("plugin").and_then(|v| v.as_str()) {
        if plugin == "obfs" || plugin == "v2ray-plugin" {
            ob = ob.field("plugin", "obfs-local");
            if let Some(opts) =
                proxy.get("plugin-opts").and_then(|v| v.as_mapping())
            {
                let mut parts = Vec::new();
                if let Some(mode) = opts.get("mode").and_then(|v| v.as_str()) {
                    parts.push(format!("obfs={mode}"));
                }
                if let Some(host) = opts.get("host").and_then(|v| v.as_str()) {
                    parts.push(format!("obfs-host={host}"));
                }
                if !parts.is_empty() {
                    ob = ob.field("plugin_opts", parts.join(";"));
                }
            }
        }
    }

    Some(ob)
}

fn parse_clash_anytls(
    proxy: &noyalib::Value, name: &str,
) -> Option<TomlOutbound> {
    let server = proxy.get("server")?.as_str()?;
    let port = proxy.get("port")?.as_u64()? as u16;
    let password = proxy.get("password").and_then(|v| v.as_str())?;

    let mut ob = TomlOutbound::new("anytls", name)
        .field("server", format!("{server}:{port}"))
        .field("password", password);

    if let Some(sni) = proxy.get("sni").and_then(|v| v.as_str()) {
        ob = ob.field("sni", sni);
    }

    if let Some(fp) = proxy.get("fingerprint").and_then(|v| v.as_str()) {
        ob = ob.field("fp", true);
        let _ = fp; // fingerprint not directly used but implies fp=true
    }
    if let Some(true) = proxy.get("skip-cert-verify").and_then(|v| v.as_bool()) {
        ob = ob.field("insecure", true);
    }
    if let Some(v) = proxy
        .get("idle-session-check-interval")
        .and_then(|v| v.as_u64())
    {
        ob = ob.field("idle_session_check_interval", v as i64);
    }
    if let Some(v) = proxy.get("idle-session-timeout").and_then(|v| v.as_u64()) {
        ob = ob.field("idle_session_timeout", v as i64);
    }
    if let Some(v) = proxy.get("min-idle-session").and_then(|v| v.as_u64()) {
        ob = ob.field("min_idle_session", v as i64);
    }

    Some(ob)
}

/// Build a validated `[outbounds.reality]` section from subscription fields.
///
/// `public_key` must base64-decode to exactly 32 bytes and `short_id` must be
/// hex of at most 8 bytes — the same rules anywhere applies to handwritten
/// configs (`RealityConfig::parse`). Returns `None` when the values are
/// missing or invalid, so callers can skip the node (the existing skip
/// strategy for unrepresentable nodes).
fn validated_reality_section(
    public_key: Option<&str>, short_id: Option<&str>,
) -> Option<RealitySection> {
    let public_key = public_key?;
    let cfg = crate::transport::reality::RealityConfig {
        public_key: public_key.to_string(),
        short_id: short_id.unwrap_or("").to_string(),
    };
    // Empty short_id is valid (zero-padded on the wire, §S1.1).
    cfg.parse().ok()?;
    Some(RealitySection {
        public_key: public_key.to_string(),
        short_id: short_id.unwrap_or("").to_string(),
    })
}

/// Resolve flow + reality for a vless node into (optional flow field,
/// optional reality section). Shared by the Clash / sing-box / URI parsers.
///
/// anywhere's vless validator requires `flow` to come with a `reality`
/// section and rejects `reality` + `insecure` — nodes that would produce a
/// config failing those rules are skipped (`None`) instead of emitted.
/// `insecure` is the parsed `insecure` / `skip-cert-verify` flag.
fn resolve_vless_reality(
    flow: Option<&str>, reality_key: Option<&str>, reality_sid: Option<&str>,
    insecure: bool,
) -> Option<(Option<String>, Option<RealitySection>)> {
    let flow = flow.filter(|f| !f.is_empty());
    match reality_key {
        Some(_) => {
            if insecure {
                // REALITY's certificate check is a custom algorithm;
                // "skip verification" is undefined for it and anywhere
                // rejects the combination at load time.
                return None;
            }
            let section = validated_reality_section(reality_key, reality_sid)?;
            Some((flow.map(str::to_string), Some(section)))
        },
        None => {
            // flow without REALITY is unrepresentable (only TLS/REALITY
            // transports support flow, §S2.7) — skip rather than emit a
            // config the validator rejects.
            if flow.is_some() {
                return None;
            }
            Some((None, None))
        },
    }
}

fn parse_clash_vless(proxy: &noyalib::Value, name: &str) -> Option<TomlOutbound> {
    let server = proxy.get("server")?.as_str()?;
    let port = proxy.get("port")?.as_u64()? as u16;
    let uuid = proxy.get("uuid").and_then(|v| v.as_str())?;
    let network = proxy.get("network").and_then(|v| v.as_str());

    let mut ob = TomlOutbound::new("vless", name)
        .field("server", format!("{server}:{port}"))
        .field("password", uuid);

    if let Some(sni) = proxy
        .get("servername")
        .or_else(|| proxy.get("server-name"))
        .and_then(|v| v.as_str())
    {
        ob = ob.field("sni", sni);
    }
    let insecure = matches!(
        proxy.get("skip-cert-verify").and_then(|v| v.as_bool()),
        Some(true)
    );
    if insecure {
        ob = ob.field("insecure", true);
    }
    if proxy
        .get("client-fingerprint")
        .and_then(|v| v.as_str())
        .is_some()
    {
        ob = ob.field("fp", true);
    }

    // REALITY transport (Clash.Meta `reality-opts`) + flow.
    let reality_opts = proxy.get("reality-opts").and_then(|v| v.as_mapping());
    let reality_pk = reality_opts
        .and_then(|o| o.get("public-key"))
        .and_then(|v| v.as_str());
    if reality_opts.is_some() && reality_pk.is_none() {
        // reality declared without a public key — unusable node.
        return None;
    }
    let (flow, reality) = resolve_vless_reality(
        proxy.get("flow").and_then(|v| v.as_str()),
        reality_pk,
        reality_opts
            .and_then(|o| o.get("short-id"))
            .and_then(|v| v.as_str()),
        insecure,
    )?;
    // reality over WS is not supported (validator rejects the combination).
    if reality.is_some() && network == Some("ws") {
        return None;
    }
    if let Some(flow) = flow {
        ob = ob.field("flow", flow);
    }
    if let Some(reality) = reality {
        ob.set_reality(reality);
    }

    // WS transport
    if network == Some("ws") {
        let mut transport = TransportConfig {
            type_: "ws".to_string(),
            ws_path: None,
            ws_headers: None,
        };

        if let Some(ws_opts) = proxy.get("ws-opts").and_then(|v| v.as_mapping()) {
            if let Some(path) = ws_opts.get("path").and_then(|v| v.as_str()) {
                transport.ws_path = Some(path.to_string());
            }
            if let Some(headers) =
                ws_opts.get("headers").and_then(|v| v.as_mapping())
            {
                let mut h = HashMap::new();
                for (k, v) in headers {
                    if let Some(v) = v.as_str() {
                        h.insert(k.clone(), v.to_string());
                    }
                }
                if !h.is_empty() {
                    transport.ws_headers = Some(h);
                }
            }
        }

        ob.set_transport(transport);
    }

    Some(ob)
}

// ---------------------------------------------------------------------------
// Clash proxy-groups (url-test) / rules / dns
// ---------------------------------------------------------------------------

/// Parse a Clash `url-test` proxy-group into a `urltest` outbound.
///
/// `url` (a full URL in Clash) is normalized to a bare host, since anywhere's
/// urltest treats `url` as a hostname. References not in `valid_refs`
/// (proxies + url-test groups) are dropped; if none remain the group is
/// skipped to avoid an empty `urltest`.
fn parse_clash_urltest(
    group: &noyalib::Value, name: &str,
    valid_refs: &std::collections::HashSet<String>,
) -> Option<TomlOutbound> {
    let proxies = group.get("proxies").and_then(|v| v.as_sequence())?;
    let refs: Vec<String> = proxies
        .iter()
        .filter_map(|v| v.as_str())
        // Allow DIRECT (Clash) — mapped to "direct" (anywhere built-in).
        .filter(|s| valid_refs.contains(*s) || *s == "DIRECT")
        .map(|s| if s == "DIRECT" { "direct".to_string() } else { s.to_string() })
        .collect();
    if refs.is_empty() {
        return None;
    }

    let mut ob = TomlOutbound::new("urltest", name).field("outbounds", refs);

    if let Some(url) = group.get("url").and_then(|v| v.as_str()) {
        let host = url::Url::parse(url)
            .ok()
            .and_then(|u| u.host_str().map(|h| h.to_string()))
            .unwrap_or_else(|| url.to_string());
        ob = ob.field("url", host);
    }
    if let Some(interval) = group.get("interval").and_then(|v| v.as_u64()) {
        ob = ob.field("interval", interval as i64);
    }

    Some(ob)
}

/// Check if a CIDR string falls within the private/internal ranges that
/// anywhere automatically bypasses (builtin rules + TUN-layer drops).
/// Such rules are redundant in subscription output and are skipped.
///
/// Uses `crate::rules::PRIVATE_CIDRS` as the single source of truth.
fn is_private_cidr(cidr: &str) -> bool {
    let Some((ip_str, prefix_str)) = cidr.split_once('/') else {
        return false;
    };
    let Ok(prefix): Result<u8, _> = prefix_str.parse() else {
        return false;
    };

    // Check if the CIDR is contained within any private range.
    if let Ok(ip) = ip_str.parse::<std::net::IpAddr>() {
        for &private in crate::rules::PRIVATE_CIDRS {
            let (p_ip_str, p_prefix_str) = private.split_once('/').unwrap();
            let p_prefix: u8 = p_prefix_str.parse().unwrap();
            if cidr_contains(
                p_ip_str.parse::<std::net::IpAddr>().unwrap().into(),
                p_prefix,
                ip,
                prefix,
            ) {
                return true;
            }
        }
    }
    false
}

/// Returns true if the CIDR (p_ip/p_prefix) fully contains cidr (ip/prefix).
fn cidr_contains(
    net_ip: IpNet, net_prefix: u8, ip: std::net::IpAddr, prefix: u8,
) -> bool {
    match (net_ip, ip) {
        (IpNet::V4(net), std::net::IpAddr::V4(ip)) => {
            if prefix < net_prefix {
                return false; // can't be contained if wider
            }
            let net_u32 = u32::from(net);
            let ip_u32 = u32::from(ip);
            let mask = if net_prefix == 0 {
                0
            } else {
                !0u32 << (32 - net_prefix)
            };
            (net_u32 & mask) == (ip_u32 & mask)
        },
        (IpNet::V6(net), std::net::IpAddr::V6(ip)) => {
            if prefix < net_prefix {
                return false;
            }
            let net_u128 = u128::from(net);
            let ip_u128 = u128::from(ip);
            let mask = if net_prefix == 0 {
                0
            } else {
                !0u128 << (128 - net_prefix)
            };
            (net_u128 & mask) == (ip_u128 & mask)
        },
        _ => false, // v4 vs v6 mismatch
    }
}

/// Simple IP network enum for containment check.
enum IpNet {
    V4(std::net::Ipv4Addr),
    V6(std::net::Ipv6Addr),
}

impl From<std::net::IpAddr> for IpNet {
    fn from(ip: std::net::IpAddr) -> Self {
        match ip {
            std::net::IpAddr::V4(v) => IpNet::V4(v),
            std::net::IpAddr::V6(v) => IpNet::V6(v),
        }
    }
}

/// Parse Clash `rules:` entries into `[[rules]]`. Only directly-mappable
/// types are emitted (see migration plan §3); others are recorded in `skips`.
///
/// Rules with the same type and same outbound are merged into a single
/// `[[rules]]` entry with a list value (e.g. `domain_suffix = ["a", "b"]`).
/// IP-CIDR rules for private/internal ranges are skipped because anywhere
/// automatically adds builtin private-network bypass rules.
fn parse_clash_rules(
    rules: &[noyalib::Value], valid_refs: &std::collections::HashSet<String>,
    skips: &mut Vec<String>,
) -> Vec<TomlRule> {
    // Accumulator for merging: (field_key, outbound) -> Vec<value>
    let mut merged: std::collections::HashMap<(String, String), Vec<String>> =
        std::collections::HashMap::new();
    // Track order of first appearance for stable output ordering.
    let mut order: Vec<(String, String)> = Vec::new();
    // Standalone rules (port, port_range, network, MATCH) that can't be merged.
    let mut standalone: Vec<TomlRule> = Vec::new();

    for rule in rules {
        let Some(line) = rule.as_str() else { continue };
        let parts: Vec<&str> = line.split(',').map(|s| s.trim()).collect();
        if parts.is_empty() {
            continue;
        }
        let rtype = parts[0];

        // MATCH has no value field: `MATCH,TARGET`.
        if rtype == "MATCH" {
            if let Some(target) = parts.get(1) {
                if let Some(ob) = map_rule_target(target, valid_refs, skips) {
                    standalone.push(TomlRule::new(ob));
                }
            }
            continue;
        }

        // `TYPE,VALUE,TARGET[,FLAGS...]`
        let (Some(value), Some(target)) = (parts.get(1), parts.get(2)) else {
            continue;
        };
        let Some(ob) = map_rule_target(target, valid_refs, skips) else {
            continue;
        };

        match rtype {
            "DOMAIN" | "DOMAIN-SUFFIX" | "DOMAIN-KEYWORD" => {
                let field_key = match rtype {
                    "DOMAIN" => "domain",
                    "DOMAIN-SUFFIX" => "domain_suffix",
                    "DOMAIN-KEYWORD" => "domain_keyword",
                    _ => unreachable!(),
                };
                let key = (field_key.to_string(), ob.clone());
                if !merged.contains_key(&key) {
                    order.push(key.clone());
                }
                merged.entry(key).or_default().push(value.to_string());
            },
            "IP-CIDR" | "IP-CIDR6" => {
                // Skip private/internal CIDRs — anywhere auto-adds bypass rules.
                if is_private_cidr(value) {
                    continue;
                }
                let key = ("ip_cidr".to_string(), ob.clone());
                if !merged.contains_key(&key) {
                    order.push(key.clone());
                }
                merged.entry(key).or_default().push(value.to_string());
            },
            "DST-PORT" => {
                let mut rule = TomlRule::new(ob);
                let ok = if let Some((a, b)) = value.split_once('-') {
                    if a.parse::<u16>().is_ok() && b.parse::<u16>().is_ok() {
                        rule = rule.field("port_range", value.to_string());
                        true
                    } else {
                        false
                    }
                } else if let Ok(p) = value.parse::<u16>() {
                    rule = rule.field("port", p);
                    true
                } else {
                    false
                };
                if ok {
                    standalone.push(rule);
                }
            },
            "NETWORK" => {
                standalone
                    .push(TomlRule::new(ob).field("network", value.to_string()));
            },
            other => {
                skips.push(format!("rule-type:{other}"));
            },
        }
    }

    // Build merged rules in insertion order, then append standalone rules.
    let mut out: Vec<TomlRule> = Vec::new();
    for (field_key, outbound) in &order {
        if let Some(values) = merged.get(&(field_key.clone(), outbound.clone())) {
            let mut rule = TomlRule::new(outbound.clone());
            rule = rule.field(field_key, values.clone());
            out.push(rule);
        }
    }
    out.extend(standalone);
    out
}

/// Map a Clash rule TARGET to an anywhere `outbound` value.
/// `DIRECT` -> `direct`, `REJECT`/`REJECT-DROP` -> `none`, `PASS` dropped,
/// proxy/group names must exist in `valid_refs` else recorded in `skips`.
fn map_rule_target(
    target: &str, valid_refs: &std::collections::HashSet<String>,
    skips: &mut Vec<String>,
) -> Option<String> {
    match target {
        "DIRECT" => Some("direct".to_string()),
        "REJECT" | "REJECT-DROP" => Some("none".to_string()),
        "PASS" => None,
        other => {
            if valid_refs.contains(other) {
                Some(other.to_string())
            } else {
                skips.push(format!("rule-target:{other}"));
                None
            }
        },
    }
}

/// Parse Clash `dns:` into a `[dns]` section. Only `nameserver`/`fallback`/
/// `fake-ip-range` map (to `direct`/`remote`/`fakeip`); returns `None` if
/// none of those are present.
fn parse_clash_dns(dns: &noyalib::Mapping) -> Option<TomlDns> {
    let mut fields: Vec<(String, TomlValue)> = Vec::new();

    if let Some(ns) = dns.get("nameserver").and_then(|v| v.as_sequence()) {
        let list: Vec<String> = ns
            .iter()
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .collect();
        if !list.is_empty() {
            fields.push(("direct".to_string(), TomlValue::List(list)));
        }
    }
    if let Some(fb) = dns.get("fallback").and_then(|v| v.as_sequence()) {
        let list: Vec<String> = fb
            .iter()
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .collect();
        if !list.is_empty() {
            fields.push(("remote".to_string(), TomlValue::List(list)));
        }
    }
    if let Some(fip) = dns.get("fake-ip-range").and_then(|v| v.as_str()) {
        fields.push(("fakeip".to_string(), TomlValue::Str(fip.to_string())));
    }

    if let Some(filter) = dns.get("fake-ip-filter").and_then(|v| v.as_sequence())
    {
        let list: Vec<String> = filter
            .iter()
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .collect();
        if !list.is_empty() {
            fields.push(("fakeip_filter".to_string(), TomlValue::List(list)));
        }
    }

    if fields.is_empty() {
        None
    } else {
        Some(TomlDns { fields })
    }
}

// ---------------------------------------------------------------------------
// sing-box JSON parser
// ---------------------------------------------------------------------------

fn parse_singbox_json(
    text: &str, skips: &mut Vec<String>,
) -> Result<Vec<TomlOutbound>, String> {
    let json: serde_json::Value = serde_json::from_str(text)
        .map_err(|e| format!("JSON parse error: {e}"))?;

    let outbounds_arr = json
        .get("outbounds")
        .and_then(|v| v.as_array())
        .ok_or("no 'outbounds' array found in sing-box JSON")?;

    let mut outbounds = Vec::new();
    for ob in outbounds_arr {
        let otype = ob.get("type").and_then(|v| v.as_str()).unwrap_or("unknown");
        let tag = ob.get("tag").and_then(|v| v.as_str()).unwrap_or("unnamed");

        match otype {
            "shadowsocks" => {
                if let Some(o) = parse_singbox_ss(ob, tag) {
                    outbounds.push(o);
                }
            },
            "anytls" => {
                if let Some(o) = parse_singbox_anytls(ob, tag) {
                    outbounds.push(o);
                }
            },
            "vless" => {
                if let Some(o) = parse_singbox_vless(ob, tag) {
                    outbounds.push(o);
                }
            },
            other => {
                if !SUPPORTED_TYPES.contains(&other) {
                    skips.push(other.to_string());
                }
            },
        }
    }

    Ok(outbounds)
}

fn parse_singbox_ss(ob: &serde_json::Value, tag: &str) -> Option<TomlOutbound> {
    let server = ob.get("server")?.as_str()?;
    let port = ob.get("server_port")?.as_u64()? as u16;
    let method = ob.get("method").and_then(|v| v.as_str())?;
    let password = ob.get("password").and_then(|v| v.as_str())?;

    let mut out = TomlOutbound::new("shadowsocks", tag)
        .field("server", format!("{server}:{port}"))
        .field("method", method)
        .field("password", password);

    // Plugin
    if let Some(plugin) = ob.get("plugin").and_then(|v| v.as_str()) {
        if plugin == "obfs-local" {
            out = out.field("plugin", "obfs-local");
            if let Some(opts) = ob.get("plugin_opts").and_then(|v| v.as_str()) {
                out = out.field("plugin_opts", opts);
            }
        }
    }

    Some(out)
}

fn parse_singbox_anytls(
    ob: &serde_json::Value, tag: &str,
) -> Option<TomlOutbound> {
    let server = ob.get("server")?.as_str()?;
    let port = ob.get("server_port")?.as_u64()? as u16;
    let password = ob.get("password").and_then(|v| v.as_str())?;

    let mut out = TomlOutbound::new("anytls", tag)
        .field("server", format!("{server}:{port}"))
        .field("password", password);

    if let Some(sni) = ob
        .get("tls")
        .and_then(|v| v.get("server_name"))
        .and_then(|v| v.as_str())
    {
        out = out.field("sni", sni);
    }

    Some(out)
}

fn parse_singbox_vless(
    ob: &serde_json::Value, tag: &str,
) -> Option<TomlOutbound> {
    let server = ob.get("server")?.as_str()?;
    let port = ob.get("server_port")?.as_u64()? as u16;
    let uuid = ob.get("uuid").and_then(|v| v.as_str())?;

    let mut out = TomlOutbound::new("vless", tag)
        .field("server", format!("{server}:{port}"))
        .field("password", uuid);

    let tls = ob.get("tls").filter(|t| !t.is_null());
    if let Some(sni) = tls
        .and_then(|t| t.get("server_name"))
        .and_then(|v| v.as_str())
    {
        out = out.field("sni", sni);
    }
    let insecure = matches!(
        tls.and_then(|t| t.get("insecure")).and_then(|v| v.as_bool()),
        Some(true)
    );
    if insecure {
        out = out.field("insecure", true);
    }

    // REALITY transport (`tls.reality`) + flow. `enabled` defaults to true
    // when the object is present (sing-box only writes it explicitly).
    let reality_obj = tls
        .and_then(|t| t.get("reality"))
        .filter(|r| !r.is_null())
        .filter(|r| {
            r.get("enabled").and_then(|v| v.as_bool()).unwrap_or(true)
        });
    let reality_pk = reality_obj
        .and_then(|r| r.get("public_key"))
        .and_then(|v| v.as_str());
    if reality_obj.is_some() && reality_pk.is_none() {
        // reality declared without a public key — unusable node.
        return None;
    }
    let (flow, reality) = resolve_vless_reality(
        ob.get("flow").and_then(|v| v.as_str()),
        reality_pk,
        reality_obj
            .and_then(|r| r.get("short_id"))
            .and_then(|v| v.as_str()),
        insecure,
    )?;
    // reality over WS is not supported (validator rejects the combination).
    let network = ob
        .get("transport")
        .and_then(|t| t.get("type"))
        .and_then(|v| v.as_str());
    if reality.is_some() && network == Some("ws") {
        return None;
    }
    if let Some(flow) = flow {
        out = out.field("flow", flow);
    }
    if let Some(reality) = reality {
        out.set_reality(reality);
    }

    // WS transport
    if let Some(transport) = ob.get("transport").and_then(|v| v.as_object()) {
        if transport.get("type").and_then(|v| v.as_str()) == Some("ws") {
            let mut t = TransportConfig {
                type_: "ws".to_string(),
                ws_path: None,
                ws_headers: None,
            };
            if let Some(path) = transport.get("path").and_then(|v| v.as_str()) {
                t.ws_path = Some(path.to_string());
            }
            if let Some(headers) =
                transport.get("headers").and_then(|v| v.as_object())
            {
                let mut h = HashMap::new();
                for (k, v) in headers {
                    if let Some(v) = v.as_str() {
                        h.insert(k.clone(), v.to_string());
                    }
                }
                if !h.is_empty() {
                    t.ws_headers = Some(h);
                }
            }
            out.set_transport(t);
        }
    }

    Some(out)
}

// ---------------------------------------------------------------------------
// URI list parser (base64 or plain text)
// ---------------------------------------------------------------------------

fn parse_uri_list(
    text: &str, skips: &mut Vec<String>,
) -> Result<Vec<TomlOutbound>, String> {
    // Try base64 decode first.
    let decoded = if text.trim().chars().all(|c| {
        c.is_ascii_alphanumeric()
            || c == '+'
            || c == '/'
            || c == '='
            || c == '\n'
            || c == '\r'
    }) && !text.contains("://")
    {
        // Looks like base64.
        let cleaned: String =
            text.chars().filter(|c| !c.is_whitespace()).collect();
        base64::engine::general_purpose::STANDARD
            .decode(&cleaned)
            .ok()
            .and_then(|b| String::from_utf8(b).ok())
            .unwrap_or_else(|| text.to_string())
    } else {
        text.to_string()
    };

    let mut outbounds = Vec::new();
    let mut idx = 0;
    for line in decoded.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Some(uri) = line.strip_prefix("ss://") {
            if let Some(ob) = parse_ss_uri(uri, &mut idx) {
                outbounds.push(ob);
            }
        } else if let Some(uri) = line.strip_prefix("vless://") {
            if let Some(ob) = parse_vless_uri(uri, &mut idx) {
                outbounds.push(ob);
            }
        } else if let Some(uri) = line.strip_prefix("vmess://") {
            // vmess not supported by anywhere
            let _ = uri;
            skips.push("vmess".to_string());
        } else if let Some(uri) = line.strip_prefix("trojan://") {
            let _ = uri;
            skips.push("trojan".to_string());
        } else if line.starts_with("anytls://") {
            // anytls URI scheme — parse if possible
            skips.push("anytls-uri".to_string());
        }
    }

    if outbounds.is_empty() && skips.is_empty() {
        return Err("no recognizable proxy URIs found".to_string());
    }

    Ok(outbounds)
}

/// Parse `ss://` URI.
/// Format: `ss://base64(method:password@host:port)` or
///         `ss://base64(method:password)@host:port#name`
/// Also SIP002: `ss://base64(method:password)@host:port/?plugin=...#name`
fn parse_ss_uri(uri: &str, idx: &mut usize) -> Option<TomlOutbound> {
    // SIP002 format: ss://<userinfo>@<host:port>?<params>#<name>
    // where userinfo = base64url(method:password)
    let (userinfo, rest) = uri.split_once('@')?;
    let userinfo_decoded = if userinfo.contains(':') {
        // Not base64, plain method:password
        userinfo.to_string()
    } else {
        // Try base64 standard and url-safe
        base64::engine::general_purpose::STANDARD
            .decode(userinfo)
            .or_else(|_| {
                base64::engine::general_purpose::URL_SAFE.decode(userinfo)
            })
            .ok()
            .and_then(|b| String::from_utf8(b).ok())
            .unwrap_or_else(|| userinfo.to_string())
    };

    let (method, password) = userinfo_decoded.split_once(':')?;

    // Split off name fragment
    let (rest, name) = rest
        .split_once('#')
        .map(|(r, n)| (r, n))
        .unwrap_or((rest, ""));
    // Split off query params
    let (hostport, query) = rest
        .split_once('?')
        .map(|(r, q)| (r, Some(q)))
        .unwrap_or((rest, None));

    let hostport = hostport.trim();
    let name = name.trim();
    let name = if name.is_empty() {
        *idx += 1;
        format!("ss-{}", idx)
    } else {
        urlencoding::decode(name)
            .map(|s| s.into_owned())
            .unwrap_or_else(|_| name.to_string())
    };

    let mut ob = TomlOutbound::new("shadowsocks", &name)
        .field("server", hostport)
        .field("method", method)
        .field("password", password);

    // Parse plugin from query params
    if let Some(q) = query {
        for param in q.split('&') {
            if let Some(val) = param.strip_prefix("plugin=") {
                if val.starts_with("obfs-local") {
                    ob = ob.field("plugin", "obfs-local");
                    // Parse obfs-local opts: obfs-local;obfs=http;obfs-host=xxx
                    let opts: Vec<&str> = val.split(';').skip(1).collect();
                    if !opts.is_empty() {
                        ob = ob.field("plugin_opts", opts.join(";"));
                    }
                }
            }
        }
    }

    Some(ob)
}

/// Parse `vless://` URI.
/// Format: `vless://<uuid>@<host:port>?<params>#<name>`
///
/// REALITY params (`security=reality&pbk=<base64>&sid=<hex>&flow=...`) are
/// only applicable with `type=tcp` (or no type at all); nodes whose params
/// are invalid (bad `pbk` base64 / `sid` hex) or that anywhere cannot
/// represent (`flow` without `security=reality`, reality over `type=ws`) are
/// skipped by returning `None`.
fn parse_vless_uri(uri: &str, idx: &mut usize) -> Option<TomlOutbound> {
    let (uuid, rest) = uri.split_once('@')?;
    // Split off name fragment
    let (rest, name) = rest
        .split_once('#')
        .map(|(r, n)| (r, n))
        .unwrap_or((rest, ""));
    // Split off query params
    let (hostport, query) = rest
        .split_once('?')
        .map(|(r, q)| (r, Some(q)))
        .unwrap_or((rest, None));

    let hostport = hostport.trim();
    let name = name.trim();
    let name = if name.is_empty() {
        *idx += 1;
        format!("vless-{}", idx)
    } else {
        urlencoding::decode(name)
            .map(|s| s.into_owned())
            .unwrap_or_else(|_| name.to_string())
    };

    let mut ob = TomlOutbound::new("vless", &name)
        .field("server", hostport)
        .field("password", uuid);

    let mut transport = TransportConfig {
        type_: "ws".to_string(),
        ws_path: None,
        ws_headers: None,
    };
    // Query params collected in one pass; applied afterwards because `type=`
    // may appear before or after the reality params.
    let mut type_val: Option<String> = None;
    let mut security_reality = false;
    let mut pbk: Option<String> = None;
    let mut sid: Option<String> = None;
    let mut flow: Option<String> = None;

    if let Some(q) = query {
        for param in q.split('&') {
            if let Some(val) = param.strip_prefix("type=") {
                type_val = Some(
                    urlencoding::decode(val)
                        .map(|s| s.into_owned())
                        .unwrap_or_else(|_| val.to_string()),
                );
            } else if let Some(val) = param.strip_prefix("path=") {
                transport.ws_path = Some(
                    urlencoding::decode(val)
                        .map(|s| s.into_owned())
                        .unwrap_or_else(|_| val.to_string()),
                );
            } else if let Some(val) = param.strip_prefix("host=") {
                let mut h = HashMap::new();
                h.insert("Host".to_string(), val.to_string());
                transport.ws_headers = Some(h);
            } else if let Some(val) = param.strip_prefix("sni=") {
                ob = ob.field("sni", val);
            } else if let Some(val) = param.strip_prefix("security=") {
                if val == "tls" {
                    // TLS is implicit in anywhere vless
                } else if val == "reality" {
                    security_reality = true;
                }
            } else if let Some(val) = param.strip_prefix("pbk=") {
                pbk = Some(
                    urlencoding::decode(val)
                        .map(|s| s.into_owned())
                        .unwrap_or_else(|_| val.to_string()),
                );
            } else if let Some(val) = param.strip_prefix("sid=") {
                sid = Some(
                    urlencoding::decode(val)
                        .map(|s| s.into_owned())
                        .unwrap_or_else(|_| val.to_string()),
                );
            } else if let Some(val) = param.strip_prefix("flow=") {
                flow = Some(
                    urlencoding::decode(val)
                        .map(|s| s.into_owned())
                        .unwrap_or_else(|_| val.to_string()),
                );
            }
        }
    }

    let has_ws = type_val.as_deref() == Some("ws");

    if security_reality {
        // REALITY is a raw TLS byte stream: only plain TCP is supported.
        if matches!(type_val.as_deref(), Some(t) if t != "tcp") {
            return None;
        }
        let (flow, reality) =
            resolve_vless_reality(flow.as_deref(), pbk.as_deref(), sid.as_deref(), false)?;
        if let Some(flow) = flow {
            ob = ob.field("flow", flow);
        }
        if let Some(reality) = reality {
            ob.set_reality(reality);
        }
    } else if flow.is_some() {
        // flow without REALITY is unrepresentable in anywhere (§S2.7) —
        // skip the node instead of emitting a config the validator rejects.
        return None;
    }

    if has_ws {
        ob.set_transport(transport);
    }

    Some(ob)
}

// ---------------------------------------------------------------------------
// Main entry point (called from main.rs when --sub is given)
// ---------------------------------------------------------------------------

/// Heuristic: did the server return an HTML page (e.g. a "please upgrade
/// client" notice) instead of a subscription payload?
fn is_html_response(content_type: Option<&str>, body: &[u8]) -> bool {
    // Only treat as HTML when the body actually looks like HTML.
    // Some airports return `content-type: text/html` even for valid YAML/JSON
    // subscriptions, so content-type alone is not reliable.
    let prefix: Vec<u8> = body.iter().take(32).copied().collect();
    let s = String::from_utf8_lossy(&prefix)
        .trim_start()
        .to_ascii_lowercase();
    let body_is_html = s.starts_with("<!doctype") || s.starts_with("<html");
    if body_is_html {
        return true;
    }
    // If content-type says HTML but body doesn't look like HTML, still don't
    // treat it as HTML — the body is what matters.
    let _ = content_type;
    false
}

/// Parse and print the `subscription-userinfo` header
/// (`upload=...; download=...; total=...; expire=...`).
fn print_subscription_info(header: &str) {
    let mut upload = 0u64;
    let mut download = 0u64;
    let mut total = 0u64;
    let mut expire = 0u64;
    for part in header.split(';') {
        if let Some((k, v)) = part.split_once('=') {
            let val = v.trim().parse::<u64>().unwrap_or(0);
            match k.trim() {
                "upload" => upload = val,
                "download" => download = val,
                "total" => total = val,
                "expire" => expire = val,
                _ => {},
            }
        }
    }
    let used = upload + download;
    if total > 0 {
        let gb = 1024_u64 * 1024 * 1024;
        eprintln!(
            "traffic: {:.2} / {:.2} GB ({}%)",
            used as f64 / gb as f64,
            total as f64 / gb as f64,
            used * 100 / total
        );
    }
    if let Some(dt) =
        chrono::DateTime::from_timestamp(expire as i64, 0).filter(|_| expire > 0)
    {
        eprintln!("expire: {}", dt.format("%Y-%m-%d %H:%M:%S"));
    }
}

pub async fn run_subscription(
    url: &str, ua: &str, output_path: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    eprintln!("Fetching subscription: {url}");
    eprintln!("User-Agent: {ua}");
    let resp = fetch_subscription(url, ua).await?;
    eprintln!("Downloaded {} bytes", resp.body.len());

    if is_html_response(resp.content_type.as_deref(), &resp.body) {
        let save_path = std::path::Path::new("sub_error.html");
        let saved = std::fs::write(&save_path, &resp.body).is_ok();
        let saved_msg = if saved {
            format!("，响应内容已保存到 {}", save_path.display())
        } else {
            String::new()
        };
        return Err(format!(
            "订阅返回了 HTML 页面（多为\"请升级客户端\"提示）。\
                 可用 --sub-ua 指定一个被机场识别的 UA 后重试{}",
            saved_msg
        )
        .into());
    }

    if let Some(info) = resp.subscription_userinfo.as_deref() {
        print_subscription_info(info);
    }

    let mut skips = Vec::new();
    let toml_out = convert_subscription(&resp.body, &mut skips)?;

    if !skips.is_empty() {
        let mut seen = std::collections::HashSet::new();
        let unique: Vec<String> = skips
            .iter()
            .filter(|s| seen.insert(s.as_str()))
            .cloned()
            .collect();
        eprintln!("skip: {}", unique.join(", "));
    }

    std::fs::write(output_path, &toml_out)?;
    eprintln!(
        "Written {output_path} ({} outbounds, {} rules)",
        toml_out.matches("[[outbounds]]").count(),
        toml_out.matches("[[rules]]").count()
    );

    Ok(())
}
