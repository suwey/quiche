use anywhere::subscription::convert_subscription;

#[test]
fn test_clash_yaml_parsing() {
    let yaml = std::fs::read_to_string("/tmp/test_clash.yaml").unwrap();
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
    assert!(toml_out.contains("password = \"12345678-1234-1234-1234-123456789012\""));
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
    assert!(toml_out.contains("password = \"12345678-1234-1234-1234-123456789012\""));
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
fn test_merge_and_skip() {
    let yaml = std::fs::read_to_string("/tmp/test_merge.yaml").unwrap();
    let mut skips = Vec::new();
    let toml_out = convert_subscription(yaml.as_bytes(), &mut skips).unwrap();
    println!("{}", toml_out);
    
    // domain_suffix merged: google, youtube, github in one entry
    assert!(toml_out.contains("domain_suffix = [\n    \"google.com\",\n    \"youtube.com\",\n    \"github.com\"\n]"));
    // domain merged: example.com, test.com in one entry
    assert!(toml_out.contains("domain = [\n    \"example.com\",\n    \"test.com\"\n]"));
    // domain_keyword merged: facebook, instagram in one entry
    assert!(toml_out.contains("domain_keyword = [\n    \"facebook\",\n    \"instagram\"\n]"));
    // ip_cidr merged: only non-private ones (8.8.8.0/24, 8.8.4.0/24)
    assert!(toml_out.contains("ip_cidr = [\n    \"8.8.8.0/24\",\n    \"8.8.4.0/24\"\n]"));
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
