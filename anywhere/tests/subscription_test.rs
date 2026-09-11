use anywhere::subscription::convert_subscription;

#[test]
fn test_clash_yaml_parsing() {
    let yaml = r#"
proxies:
  - name: "us-anytls-01"
    type: anytls
    server: example.com
    port: 443
    password: "test123"
    sni: example.com
  - name: "us-ss-01"
    type: ss
    server: ss.example.com
    port: 8388
    cipher: "2022-blake3-aes-128-gcm"
    password: "ss-password"
    plugin: obfs
    plugin-opts:
      mode: http
      host: ss.example.com
  - name: "us-vless-ws-01"
    type: vless
    server: vless.example.com
    port: 443
    uuid: "12345678-1234-1234-1234-123456789012"
    network: ws
    servername: vless.example.com
    ws-opts:
      path: "/vless-ws"
      headers:
        Host: vless.example.com
  - name: "us-vmess-01"
    type: vmess
    server: vmess.example.com
    port: 443
    uuid: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
  - name: "us-trojan-01"
    type: trojan
    server: trojan.example.com
    port: 443
    password: "trojan-pass"
"#;
    let mut skips = Vec::new();
    let toml_out = convert_subscription(yaml.as_bytes(), &mut skips).unwrap();

    // Should have 3 outbounds (anytls, ss, vless)
    let count = toml_out.matches("[[outbounds]]").count();
    assert_eq!(count, 3, "expected 3 outbounds, got {count}");

    // Check anytls
    assert!(toml_out.contains("type = \"anytls\""));
    assert!(toml_out.contains("tag = \"us-anytls-01\""));
    assert!(toml_out.contains("server = \"example.com:443\""));
    assert!(toml_out.contains("password = \"test123\""));
    assert!(toml_out.contains("sni = \"example.com\""));

    // Check shadowsocks
    assert!(toml_out.contains("type = \"shadowsocks\""));
    assert!(toml_out.contains("tag = \"us-ss-01\""));
    assert!(toml_out.contains("server = \"ss.example.com:8388\""));
    assert!(toml_out.contains("method = \"2022-blake3-aes-128-gcm\""));
    assert!(toml_out.contains("plugin = \"obfs-local\""));
    assert!(toml_out.contains("obfs=http;obfs-host=ss.example.com"));

    // Check vless with WS
    assert!(toml_out.contains("type = \"vless\""));
    assert!(toml_out.contains("tag = \"us-vless-ws-01\""));
    assert!(toml_out.contains("server = \"vless.example.com:443\""));
    assert!(
        toml_out.contains("password = \"12345678-1234-1234-1234-123456789012\"")
    );
    assert!(toml_out.contains("[outbounds.transport]"));
    assert!(toml_out.contains("type = \"ws\""));
    assert!(toml_out.contains("path = \"/vless-ws\""));
    assert!(toml_out.contains("Host"));

    // Check skips
    assert!(skips.contains(&"vmess".to_string()));
    assert!(skips.contains(&"trojan".to_string()));
}

#[test]
fn test_ss_uri_parsing() {
    // SIP002 format: ss://base64(method:password)@host:port#name
    let raw = "ss://YWVzLTI1Ni1nY206dGVzdHBhc3M=@127.0.0.1:8388#test-ss\n";
    let mut skips = Vec::new();
    let toml_out = convert_subscription(raw.as_bytes(), &mut skips).unwrap();

    assert!(toml_out.contains("type = \"shadowsocks\""));
    assert!(toml_out.contains("tag = \"test-ss\""));
    assert!(toml_out.contains("server = \"127.0.0.1:8388\""));
    assert!(toml_out.contains("method = \"aes-256-gcm\""));
    assert!(toml_out.contains("password = \"testpass\""));
}

#[test]
fn test_vless_uri_parsing() {
    let raw = "vless://12345678-1234-1234-1234-123456789012@example.com:443?type=ws&path=/vless&host=example.com&sni=example.com#test-vless\n";
    let mut skips = Vec::new();
    let toml_out = convert_subscription(raw.as_bytes(), &mut skips).unwrap();

    assert!(toml_out.contains("type = \"vless\""));
    assert!(toml_out.contains("tag = \"test-vless\""));
    assert!(toml_out.contains("server = \"example.com:443\""));
    assert!(
        toml_out.contains("password = \"12345678-1234-1234-1234-123456789012\"")
    );
    assert!(toml_out.contains("sni = \"example.com\""));
    assert!(toml_out.contains("[outbounds.transport]"));
    assert!(toml_out.contains("type = \"ws\""));
    assert!(toml_out.contains("path = \"/vless\""));
}

#[test]
fn test_skip_unsupported() {
    let raw = "vmess://abc\n trojan://def\n";
    let mut skips = Vec::new();
    let result = convert_subscription(raw.as_bytes(), &mut skips);
    // Should error because no supported proxies found
    assert!(result.is_err() || skips.len() >= 2);
    assert!(skips.contains(&"vmess".to_string()));
    assert!(skips.contains(&"trojan".to_string()));
}

#[test]
fn test_clash_groups_rules_dns() {
    let yaml = r#"
proxies:
  - name: "node-ss"
    type: ss
    server: ss.example.com
    port: 8388
    cipher: aes-256-gcm
    password: "pass1"
  - name: "node-vless"
    type: vless
    server: vless.example.com
    port: 443
    uuid: "abc-uuid"
    servername: vless.example.com
    skip-cert-verify: true
    client-fingerprint: chrome

proxy-groups:
  - name: "auto"
    type: url-test
    proxies: ["node-ss", "node-vless"]
    url: "http://www.gstatic.com/generate_204"
    interval: 300

rules:
  - DOMAIN-SUFFIX,google.com,auto
  - IP-CIDR,10.0.0.0/8,DIRECT
  - DST-PORT,8443,auto
  - GEOIP,CN,DIRECT
  - MATCH,auto

dns:
  nameserver:
    - https://doh.pub/dns-query
    - 223.5.5.5
  fallback:
    - 8.8.8.8
    - 1.1.1.1
  fake-ip-range: 198.18.0.1/16
"#;
    let mut skips = Vec::new();
    let toml_out = convert_subscription(yaml.as_bytes(), &mut skips).unwrap();

    // 2 proxies + 1 urltest group.
    assert_eq!(toml_out.matches("[[outbounds]]").count(), 3);

    // urltest group: url normalized to bare host.
    assert!(toml_out.contains("type = \"urltest\""));
    assert!(toml_out.contains("tag = \"auto\""));
    assert!(toml_out.contains("url = \"www.gstatic.com\""));
    assert!(toml_out.contains("interval = 300"));
    assert!(toml_out.contains("\"node-ss\""));
    assert!(toml_out.contains("\"node-vless\""));

    // vless new fields from skip-cert-verify / client-fingerprint.
    assert!(toml_out.contains("insecure = true"));
    assert!(toml_out.contains("fp = true"));

    // Rules: DOMAIN-SUFFIX, DST-PORT, MATCH emitted; GEOIP skipped.
    // IP-CIDR 10.0.0.0/8 is private — skipped (anywhere auto-adds bypass).
    assert_eq!(toml_out.matches("[[rules]]").count(), 3);
    assert!(toml_out.contains("domain_suffix = [\"google.com\"]"));
    assert!(toml_out.contains("outbound = \"auto\""));
    assert!(!toml_out.contains("ip_cidr = [\"10.0.0.0/8\"]"));
    assert!(toml_out.contains("port = 8443"));
    // Unsupported rule type recorded in skips.
    assert!(skips.contains(&"rule-type:GEOIP".to_string()));

    // DNS section.
    assert!(toml_out.contains("[dns]"));
    assert!(toml_out.contains("direct = ["));
    assert!(toml_out.contains("https://doh.pub/dns-query"));
    assert!(toml_out.contains("remote = ["));
    assert!(toml_out.contains("8.8.8.8"));
    assert!(toml_out.contains("fakeip = \"198.18.0.1/16\""));
}

#[test]
fn test_clash_select_group_parsing() {
    let yaml = r#"
proxies:
  - name: "node-ss"
    type: ss
    server: ss.example.com
    port: 8388
    cipher: aes-256-gcm
    password: "pass1"
  - name: "node-vless"
    type: vless
    server: vless.example.com
    port: 443
    uuid: "abc-uuid"
    servername: vless.example.com
    skip-cert-verify: true
    client-fingerprint: chrome

proxy-groups:
  - name: "auto"
    type: url-test
    proxies: ["node-ss", "node-vless"]
    url: "http://www.gstatic.com/generate_204"
    interval: 300
  - name: "manual"
    type: select
    proxies: ["auto", "node-ss", "DIRECT"]

rules:
  - DOMAIN-SUFFIX,google.com,manual
  - MATCH,manual
"#;
    let mut skips = Vec::new();
    let toml_out = convert_subscription(yaml.as_bytes(), &mut skips).unwrap();

    // 2 proxies + 1 urltest + 1 urltest(mode=select) = 4 outbounds.
    assert_eq!(toml_out.matches("[[outbounds]]").count(), 4);

    // Clash `select` group → urltest with mode = "select".
    assert!(toml_out.contains("tag = \"manual\""));
    assert!(toml_out.contains("mode = \"select\""));
    // DIRECT mapped to "direct"; children include the urltest group + proxies.
    assert!(toml_out.contains("\"auto\""));
    assert!(toml_out.contains("\"node-ss\""));
    assert!(toml_out.contains("\"direct\""));

    // Rules referencing the select group are preserved (not dropped).
    assert!(toml_out.contains("outbound = \"manual\""));
    assert_eq!(toml_out.matches("[[rules]]").count(), 2);
}

#[test]
fn test_merge_and_skip() {
    let yaml = r#"
proxies:
  - name: "merge-node"
    type: ss
    server: 8.8.8.8
    port: 8388
    cipher: aes-256-gcm
    password: "pass"

rules:
  - DOMAIN-SUFFIX,google.com,merge-node
  - DOMAIN-SUFFIX,youtube.com,merge-node
  - DOMAIN-SUFFIX,github.com,merge-node
  - DOMAIN,example.com,merge-node
  - DOMAIN,test.com,merge-node
  - DOMAIN-KEYWORD,facebook,merge-node
  - DOMAIN-KEYWORD,instagram,merge-node
  - IP-CIDR,8.8.8.0/24,merge-node
  - IP-CIDR,8.8.4.0/24,merge-node
  - IP-CIDR,10.0.0.0/8,merge-node
  - IP-CIDR,192.168.0.0/16,merge-node
  - IP-CIDR,127.0.0.0/8,merge-node
  - IP-CIDR,172.16.0.0/12,merge-node
  - IP-CIDR,224.0.0.0/4,merge-node
  - IP-CIDR,::1/128,merge-node
  - IP-CIDR,fc00::/7,merge-node
  - IP-CIDR,fe80::/10,merge-node
"#;
    let mut skips = Vec::new();
    let toml_out = convert_subscription(yaml.as_bytes(), &mut skips).unwrap();
    println!("{}", toml_out);

    // domain_suffix merged: google, youtube, github in one entry
    assert!(toml_out.contains("domain_suffix = [\n    \"google.com\",\n    \"youtube.com\",\n    \"github.com\"\n]"));
    // domain merged: example.com, test.com in one entry
    assert!(
        toml_out
            .contains("domain = [\n    \"example.com\",\n    \"test.com\"\n]")
    );
    // domain_keyword merged: facebook, instagram in one entry
    assert!(
        toml_out.contains(
            "domain_keyword = [\n    \"facebook\",\n    \"instagram\"\n]"
        )
    );
    // ip_cidr merged: only non-private ones (8.8.8.0/24, 8.8.4.0/24)
    assert!(
        toml_out
            .contains("ip_cidr = [\n    \"8.8.8.0/24\",\n    \"8.8.4.0/24\"\n]")
    );
    // private CIDRs NOT present in output
    assert!(!toml_out.contains("10.0.0.0/8"));
    assert!(!toml_out.contains("192.168.0.0/16"));
    assert!(!toml_out.contains("127.0.0.0/8"));
    assert!(!toml_out.contains("172.16.0.0/12"));
    assert!(!toml_out.contains("224.0.0.0/4"));
    assert!(!toml_out.contains("::1/128"));
    assert!(!toml_out.contains("fc00::/7"));
    assert!(!toml_out.contains("fe80::/10"));
}

// ---------------------------------------------------------------------------
// VLESS + REALITY subscription conversion (M3.3)
// ---------------------------------------------------------------------------

/// 32 bytes of 0x37 — a well-formed (base64) REALITY public key.
const REALITY_PBK: &str = "Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc=";

#[test]
fn test_vless_reality_uri_full_params() {
    let raw = format!(
        "vless://12345678-1234-1234-1234-123456789012@example.com:443\
         ?security=reality&pbk={REALITY_PBK}&sid=0123abcd\
         &sni=www.example.com&flow=xtls-rprx-vision&type=tcp#reality-node\n"
    );
    let mut skips = Vec::new();
    let toml_out = convert_subscription(raw.as_bytes(), &mut skips).unwrap();

    assert!(toml_out.contains("type = \"vless\""));
    assert!(toml_out.contains("tag = \"reality-node\""));
    assert!(toml_out.contains("server = \"example.com:443\""));
    assert!(
        toml_out.contains("password = \"12345678-1234-1234-1234-123456789012\"")
    );
    assert!(toml_out.contains("sni = \"www.example.com\""));
    assert!(toml_out.contains("flow = \"xtls-rprx-vision\""));
    assert!(toml_out.contains("[outbounds.reality]"));
    assert!(toml_out.contains(&format!("public_key = \"{REALITY_PBK}\"")));
    assert!(toml_out.contains("short_id = \"0123abcd\""));
    // REALITY is a raw TLS byte stream — no WS transport section.
    assert!(!toml_out.contains("[outbounds.transport]"));

    // Round-trip: the generated TOML loads as an anywhere config equivalent
    // to a handwritten one, and the reality params decode like the manual
    // example in docs/vless-reality-vision-port.md.
    let cfg = anywhere::config::Config::from_string(&toml_out).unwrap();
    let ob = &cfg.outbounds[0];
    assert_eq!(ob.type_, "vless");
    assert_eq!(ob.server.as_deref(), Some("example.com:443"));
    assert_eq!(ob.flow.as_deref(), Some("xtls-rprx-vision"));
    let params = ob.reality.as_ref().unwrap().parse().unwrap();
    assert_eq!(params.public_key, [0x37; 32]);
    assert_eq!(params.short_id, [0x01, 0x23, 0xab, 0xcd, 0, 0, 0, 0]);
}

#[test]
fn test_vless_reality_uri_without_flow() {
    // No flow: plain REALITY without Vision (legal Xray combination) — the
    // flow field must not be written.
    let raw = format!(
        "vless://12345678-1234-1234-1234-123456789012@example.com:443\
         ?security=reality&pbk={REALITY_PBK}&sid=ab#plain-reality\n"
    );
    let mut skips = Vec::new();
    let toml_out = convert_subscription(raw.as_bytes(), &mut skips).unwrap();

    assert!(toml_out.contains("[outbounds.reality]"));
    assert!(toml_out.contains("short_id = \"ab\""));
    assert!(!toml_out.contains("flow = "));

    let cfg = anywhere::config::Config::from_string(&toml_out).unwrap();
    assert!(cfg.outbounds[0].flow.is_none());
    assert!(cfg.outbounds[0].reality.is_some());
}

#[test]
fn test_vless_reality_uri_without_sid() {
    // sid omitted entirely = zero short id; rendered as an empty short_id so
    // the generated TOML still deserializes (RealityConfig requires it).
    let raw = format!(
        "vless://12345678-1234-1234-1234-123456789012@example.com:443\
         ?security=reality&pbk={REALITY_PBK}&type=tcp#no-sid\n"
    );
    let mut skips = Vec::new();
    let toml_out = convert_subscription(raw.as_bytes(), &mut skips).unwrap();

    assert!(toml_out.contains("short_id = \"\""));
    let cfg = anywhere::config::Config::from_string(&toml_out).unwrap();
    let params = cfg.outbounds[0].reality.as_ref().unwrap().parse().unwrap();
    assert_eq!(params.short_id, [0u8; 8]);
}

#[test]
fn test_vless_reality_uri_type_omitted() {
    // type= omitted defaults to tcp — reality still applies.
    let raw = format!(
        "vless://12345678-1234-1234-1234-123456789012@example.com:443\
         ?security=reality&pbk={REALITY_PBK}&sid=01#default-type\n"
    );
    let mut skips = Vec::new();
    let toml_out = convert_subscription(raw.as_bytes(), &mut skips).unwrap();
    assert!(toml_out.contains("[outbounds.reality]"));
}

#[test]
fn test_vless_reality_uri_invalid_pbk_skipped() {
    for bad in ["not-base64!!", "Nzc3Nzc3", ""] {
        let raw = format!(
            "vless://12345678-1234-1234-1234-123456789012@example.com:443\
             ?security=reality&pbk={bad}&sid=01&type=tcp#bad-pbk\n"
        );
        let mut skips = Vec::new();
        let result = convert_subscription(raw.as_bytes(), &mut skips);
        // Node skipped (no skip entry — same as other unparseable nodes);
        // nothing left → conversion errors out.
        assert!(result.is_err(), "pbk={bad:?} must be skipped");
    }
}

#[test]
fn test_vless_reality_uri_invalid_sid_skipped() {
    for bad in ["zz", "012", "00112233445566778899"] {
        let raw = format!(
            "vless://12345678-1234-1234-1234-123456789012@example.com:443\
             ?security=reality&pbk={REALITY_PBK}&sid={bad}&type=tcp#bad-sid\n"
        );
        let mut skips = Vec::new();
        let result = convert_subscription(raw.as_bytes(), &mut skips);
        assert!(result.is_err(), "sid={bad:?} must be skipped");
    }
}

#[test]
fn test_vless_reality_uri_type_ws_skipped() {
    // reality over WS is unsupported (anywhere rejects the combination).
    let raw = format!(
        "vless://12345678-1234-1234-1234-123456789012@example.com:443\
         ?security=reality&pbk={REALITY_PBK}&sid=01&type=ws#ws-reality\n"
    );
    let mut skips = Vec::new();
    let result = convert_subscription(raw.as_bytes(), &mut skips);
    assert!(result.is_err());
}

#[test]
fn test_vless_uri_flow_without_reality_skipped() {
    // flow without security=reality cannot be represented in anywhere.
    let raw = "vless://12345678-1234-1234-1234-123456789012@example.com:443\
               ?security=tls&flow=xtls-rprx-vision&type=tcp#tls-vision\n";
    let mut skips = Vec::new();
    let result = convert_subscription(raw.as_bytes(), &mut skips);
    assert!(result.is_err());
}

#[test]
fn test_vless_uri_ws_regression_unchanged() {
    // Existing vless ws URI behavior (no security param) is unchanged.
    let raw = "vless://12345678-1234-1234-1234-123456789012@example.com:443\
               ?type=ws&path=/vless&host=example.com&sni=example.com#ws-node\n";
    let mut skips = Vec::new();
    let toml_out = convert_subscription(raw.as_bytes(), &mut skips).unwrap();

    assert!(toml_out.contains("[outbounds.transport]"));
    assert!(toml_out.contains("type = \"ws\""));
    assert!(toml_out.contains("path = \"/vless\""));
    assert!(toml_out.contains("Host"));
    assert!(!toml_out.contains("[outbounds.reality]"));
    assert!(!toml_out.contains("flow = "));
}

#[test]
fn test_vless_uri_mixed_ws_and_reality() {
    // A plain-text node list with one ws and one reality node.
    let raw = format!(
        "vless://12345678-1234-1234-1234-123456789012@ws.example.com:443\
         ?type=ws&path=/ws#ws-node\n\
         vless://12345678-1234-1234-1234-123456789012@r.example.com:443\
         ?security=reality&pbk={REALITY_PBK}&sid=0123abcd\
         &sni=www.example.com&flow=xtls-rprx-vision&type=tcp#reality-node\n"
    );
    let mut skips = Vec::new();
    let toml_out = convert_subscription(raw.as_bytes(), &mut skips).unwrap();

    assert_eq!(toml_out.matches("[[outbounds]]").count(), 2);
    assert!(toml_out.contains("tag = \"ws-node\""));
    assert!(toml_out.contains("tag = \"reality-node\""));
    assert!(toml_out.contains("[outbounds.transport]"));
    assert!(toml_out.contains("[outbounds.reality]"));

    // The full converted output loads as an anywhere config.
    anywhere::config::Config::from_string(&toml_out).unwrap();
}

#[test]
fn test_clash_vless_reality() {
    let yaml = format!(
        r#"
proxies:
  - name: "clash-reality"
    type: vless
    server: r.example.com
    port: 443
    uuid: "12345678-1234-1234-1234-123456789012"
    flow: xtls-rprx-vision
    servername: www.example.com
    client-fingerprint: chrome
    reality-opts:
      public-key: "{REALITY_PBK}"
      short-id: "0123abcd"
"#
    );
    let mut skips = Vec::new();
    let toml_out = convert_subscription(yaml.as_bytes(), &mut skips).unwrap();

    assert!(toml_out.contains("tag = \"clash-reality\""));
    assert!(toml_out.contains("sni = \"www.example.com\""));
    assert!(toml_out.contains("flow = \"xtls-rprx-vision\""));
    assert!(toml_out.contains("fp = true"));
    assert!(toml_out.contains("[outbounds.reality]"));
    assert!(toml_out.contains(&format!("public_key = \"{REALITY_PBK}\"")));
    assert!(toml_out.contains("short_id = \"0123abcd\""));
    assert!(!toml_out.contains("[outbounds.transport]"));

    let cfg = anywhere::config::Config::from_string(&toml_out).unwrap();
    assert!(cfg.outbounds[0].reality.is_some());
}

#[test]
fn test_clash_vless_reality_unrepresentable_skipped() {
    // flow without reality-opts; reality-opts without public-key;
    // reality over ws — none of these can become a valid anywhere config.
    let yaml = r#"
proxies:
  - name: "flow-no-reality"
    type: vless
    server: a.example.com
    port: 443
    uuid: "12345678-1234-1234-1234-123456789012"
    flow: xtls-rprx-vision
  - name: "reality-no-pk"
    type: vless
    server: b.example.com
    port: 443
    uuid: "12345678-1234-1234-1234-123456789012"
    reality-opts:
      short-id: "01"
  - name: "reality-ws"
    type: vless
    server: c.example.com
    port: 443
    uuid: "12345678-1234-1234-1234-123456789012"
    network: ws
    reality-opts:
      public-key: "Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc="
      short-id: "01"
  - name: "reality-skip-cert"
    type: vless
    server: d.example.com
    port: 443
    uuid: "12345678-1234-1234-1234-123456789012"
    skip-cert-verify: true
    reality-opts:
      public-key: "Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc="
      short-id: "01"
"#;
    let mut skips = Vec::new();
    let result = convert_subscription(yaml.as_bytes(), &mut skips);
    // The Clash path renders zero proxies as an empty output (no error).
    let toml_out = result.unwrap();
    assert!(
        !toml_out.contains("[[outbounds]]"),
        "all four nodes must be skipped, got:\n{toml_out}"
    );
}

#[test]
fn test_singbox_vless_reality() {
    let json = format!(
        r#"{{"outbounds":[
            {{"type":"vless","tag":"sb-reality","server":"r.example.com",
               "server_port":443,
               "uuid":"12345678-1234-1234-1234-123456789012",
               "flow":"xtls-rprx-vision",
               "tls":{{"enabled":true,"server_name":"www.example.com",
                       "reality":{{"enabled":true,
                                   "public_key":"{REALITY_PBK}",
                                   "short_id":"0123abcd"}}}}}},
            {{"type":"vless","tag":"sb-ws","server":"ws.example.com",
               "server_port":443,
               "uuid":"12345678-1234-1234-1234-123456789012",
               "transport":{{"type":"ws","path":"/ws"}}}}
        ]}}"#
    );
    let mut skips = Vec::new();
    let toml_out = convert_subscription(json.as_bytes(), &mut skips).unwrap();

    assert!(toml_out.contains("tag = \"sb-reality\""));
    assert!(toml_out.contains("flow = \"xtls-rprx-vision\""));
    assert!(toml_out.contains("[outbounds.reality]"));
    assert!(toml_out.contains(&format!("public_key = \"{REALITY_PBK}\"")));
    assert!(toml_out.contains("short_id = \"0123abcd\""));
    // The ws sibling keeps its transport section.
    assert!(toml_out.contains("[outbounds.transport]"));

    let cfg = anywhere::config::Config::from_string(&toml_out).unwrap();
    assert_eq!(cfg.outbounds.len(), 2);
    assert!(cfg.outbounds[0].reality.is_some());
    assert!(cfg.outbounds[1].reality.is_none());
    assert!(cfg.outbounds[1].transport.is_some());
}

#[test]
fn test_singbox_vless_reality_unrepresentable_skipped() {
    let json = format!(
        r#"{{"outbounds":[
            {{"type":"vless","tag":"flow-no-reality","server":"a.example.com",
               "server_port":443,
               "uuid":"12345678-1234-1234-1234-123456789012",
               "flow":"xtls-rprx-vision",
               "tls":{{"enabled":true,"server_name":"a.example.com"}}}},
            {{"type":"vless","tag":"reality-insecure","server":"b.example.com",
               "server_port":443,
               "uuid":"12345678-1234-1234-1234-123456789012",
               "tls":{{"enabled":true,"insecure":true,
                       "reality":{{"enabled":true,
                                   "public_key":"{REALITY_PBK}",
                                   "short_id":"01"}}}}}},
            {{"type":"vless","tag":"reality-disabled","server":"c.example.com",
               "server_port":443,
               "uuid":"12345678-1234-1234-1234-123456789012",
               "tls":{{"enabled":true,
                       "reality":{{"enabled":false,
                                   "public_key":"{REALITY_PBK}"}}}}}}
        ]}}"#
    );
    let mut skips = Vec::new();
    let result = convert_subscription(json.as_bytes(), &mut skips);
    // flow-without-reality and reality+insecure are skipped; the
    // reality.enabled=false node falls back to plain TLS vless and survives.
    let toml_out = result.unwrap();
    assert!(!toml_out.contains("flow-no-reality"));
    assert!(!toml_out.contains("reality-insecure"));
    assert!(toml_out.contains("tag = \"reality-disabled\""));
    assert!(!toml_out.contains("[outbounds.reality]"));
}
