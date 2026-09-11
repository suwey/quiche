use async_trait::async_trait;

use crate::inbound::Destination;
use crate::relay::PacketRelay;
use crate::relay::StreamRelay;

pub mod anytls;
pub mod common;
pub mod direct;
pub mod quic;
pub mod registry;
pub mod ssh;
pub mod urltest;

pub mod mless;
pub mod shadowsocks;
pub mod vless;
#[async_trait]
pub trait OutboundClient: Send + Sync {
    /// TCP-style dial. Returns a byte-stream relay.
    async fn dial(
        &self, dest: &Destination,
    ) -> Result<Box<dyn StreamRelay>, Box<dyn std::error::Error>>;

    /// UDP-style dial. `initial_dest` is the first packet's destination
    /// (routing hint); subsequent packets carry their own destinations via
    /// [`PacketRelay::write_packet`].
    ///
    /// Default returns an error — implementations override on demand.
    async fn dial_udp(
        &self, _initial_dest: &Destination,
    ) -> Result<Box<dyn PacketRelay>, Box<dyn std::error::Error>> {
        Err(crate::outbound::common::ERR_UDP_NOT_SUPPORTED.into())
    }

    /// Measure real end-to-end latency through this outbound.
    ///
    /// `url` is the full test address from the outbound's `url` config (e.g.
    /// `https://www.gstatic.com/generate_204`). The probe opens a stream to
    /// its host:port via [`Self::dial`], sends a request that provably
    /// elicits a response from the target (TLS ClientHello for https, a bare
    /// HTTP HEAD for http) and measures the time until the target's first
    /// response byte. This exercises the full data path — client → node →
    /// target → back — so pooled/multiplexed outbounds (anytls, vless,
    /// mless) report real latency instead of the near-zero duration of a
    /// pool acquire, and a node that accepts connections but cannot forward
    /// traffic reports as failed.
    ///
    /// Bare hosts without a scheme are treated as https (port 443).
    /// Returns `None` on failure (timeout, unreachable, target silent).
    /// Override to return `None` for outbounds that should not participate
    /// in latency testing (direct, quic, ssh).
    async fn test_latency(&self, url: &str) -> Option<u64> {
        let target = parse_probe_url(url)?;
        let dest: Destination = if target.host.contains(':') {
            format!("[{}]:{}", target.host, target.port)
        } else {
            format!("{}:{}", target.host, target.port)
        }
        .parse()
        .ok()?;
        let start = std::time::Instant::now();
        let mut relay = match self.dial(&dest).await {
            Ok(r) => r,
            Err(e) => {
                log::debug!("latency probe: dial {dest} failed: {e}");
                return None;
            },
        };

        let probe: Vec<u8> = if target.https {
            // A minimal ClientHello makes the TLS target answer with its
            // ServerHello. The handshake is never completed — we stop at
            // the first response byte, so no certificate validation runs.
            tls_client_hello(&target.host)
        } else {
            format!(
                "HEAD {} HTTP/1.0\r\nHost: {}\r\n\r\n",
                target.path, target.host
            )
            .into_bytes()
        };
        if let Err(e) = relay.write(&probe).await {
            log::debug!("latency probe: write {dest} failed: {e}");
            let _ = relay.shutdown().await;
            return None;
        }

        let mut buf = [0u8; 512];
        let answered = match tokio::time::timeout(
            TEST_PROBE_TIMEOUT,
            relay.read(&mut buf),
        )
        .await
        {
            Ok(Ok(n)) if n > 0 => true,
            Ok(Ok(_)) | Ok(Err(_)) | Err(_) => false,
        };
        let _ = relay.finish().await;

        if answered {
            Some(start.elapsed().as_millis() as u64)
        } else {
            log::debug!(
                "latency probe: no first byte from {dest} within {TEST_PROBE_TIMEOUT:?}"
            );
            None
        }
    }
}

/// The configured test URL, parsed for probing.
struct ProbeTarget {
    https: bool,
    host: String,
    port: u16,
    path: String,
}

/// Parse a test URL into its probe target.
///
/// Accepts `https://host[:port][/path]`, `http://host[:port][/path]`, and
/// bare hosts (treated as https:443 — the historical config default was a
/// bare `www.google.com`).
fn parse_probe_url(url: &str) -> Option<ProbeTarget> {
    let url = url.trim();
    let (https, rest) = if let Some(r) = url.strip_prefix("https://") {
        (true, r)
    } else if let Some(r) = url.strip_prefix("http://") {
        (false, r)
    } else {
        (true, url)
    };
    let (authority, path) = match rest.split_once('/') {
        Some((a, p)) => (a, format!("/{p}")),
        None => (rest, "/".to_string()),
    };
    let (host, port) = if let Some(rest) = authority.strip_prefix('[') {
        // [ipv6] or [ipv6]:port
        let (h, after) = rest.split_once(']')?;
        (h, after.strip_prefix(':'))
    } else {
        match authority.rsplit_once(':') {
            Some((h, p)) => (h, Some(p)),
            None => (authority, None),
        }
    };
    if host.is_empty() {
        return None;
    }
    let port = match port {
        Some(p) => p.parse().ok()?,
        None if https => 443,
        None => 80,
    };
    Some(ProbeTarget {
        https,
        host: host.trim_end_matches('.').to_ascii_lowercase(),
        port,
        path,
    })
}

/// How long the end-to-end latency probe waits for the target's first
/// response byte (includes dial + probe request + response).
const TEST_PROBE_TIMEOUT: std::time::Duration =
    std::time::Duration::from_secs(5);

/// Build a minimal but valid TLS ClientHello for `host` (TLS 1.2 record
/// wrapping a handshake that offers TLS 1.3/1.2).
///
/// Used by [`OutboundClient::test_latency`]: a real TLS server replies with
/// its ServerHello to this exact byte sequence, giving the probe something
/// to measure. Deliberately minimal — no ALPN, no session resumption, no
/// certificate handling (the handshake is aborted after the first reply).
fn tls_client_hello(host: &str) -> Vec<u8> {
    // Extensions.
    let mut ext = Vec::with_capacity(64);
    // server_name — RFC 6066 forbids SNI for IP literals, so omit it there.
    if host.parse::<std::net::IpAddr>().is_err() {
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        let sni_len = host.len();
        let list_len = sni_len + 3;
        ext.extend_from_slice(&[0x00, 0x00]);
        ext.extend_from_slice(&((list_len + 2) as u16).to_be_bytes());
        ext.extend_from_slice(&(list_len as u16).to_be_bytes());
        ext.push(0x00);
        ext.extend_from_slice(&(sni_len as u16).to_be_bytes());
        ext.extend_from_slice(host.as_bytes());
    }
    // supported_groups: x25519, secp256r1.
    ext.extend_from_slice(&[
        0x00, 0x0a, 0x00, 0x08, 0x00, 0x06, 0x00, 0x1d, 0x00, 0x17,
    ]);
    // ec_point_formats: uncompressed.
    ext.extend_from_slice(&[0x00, 0x0b, 0x00, 0x02, 0x01, 0x00]);
    // signature_algorithms: rsa_pss/ecdsa/rsa-pkcs1 common pairs.
    ext.extend_from_slice(&[
        0x00, 0x0d, 0x00, 0x12, 0x00, 0x10, 0x04, 0x03, 0x08, 0x04, 0x04,
        0x01, 0x05, 0x03, 0x08, 0x05, 0x05, 0x01, 0x08, 0x06, 0x06, 0x01,
    ]);
    // supported_versions: TLS 1.3, TLS 1.2.
    ext.extend_from_slice(&[
        0x00, 0x2b, 0x00, 0x05, 0x04, 0x03, 0x04, 0x03, 0x03,
    ]);

    // Handshake body: version + random + session_id + ciphers + compression
    // + extensions.
    let mut body = Vec::with_capacity(64 + ext.len());
    body.extend_from_slice(&[0x03, 0x03]); // client_version TLS 1.2
    let mut random = [0u8; 32];
    getrandom::fill(&mut random).expect("getrandom: system CSPRNG failed");
    body.extend_from_slice(&random);
    body.push(0x00); // session_id: empty
    // Cipher suites: TLS1.3-AES128GCM, ECDHE-RSA/ECDSA-AES128GCM,
    // ECDHE-RSA/ECDSA-AES256GCM, RSA-AES128GCM.
    let suites: [u8; 12] = [
        0x13, 0x01, 0xc0, 0x2f, 0xc0, 0x2b, 0xc0, 0x30, 0xc0, 0x2c, 0x00,
        0x9c,
    ];
    body.extend_from_slice(&(suites.len() as u16).to_be_bytes());
    body.extend_from_slice(&suites);
    body.extend_from_slice(&[0x01, 0x00]); // compression: null
    body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
    body.extend_from_slice(&ext);

    // Handshake message: type client_hello + 3-byte length + body.
    let mut hs = Vec::with_capacity(body.len() + 4);
    hs.push(0x01);
    hs.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
    hs.extend_from_slice(&body);

    // TLS record: handshake + legacy version + length.
    let mut rec = Vec::with_capacity(hs.len() + 5);
    rec.push(0x16);
    rec.extend_from_slice(&[0x03, 0x01]);
    rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
    rec.extend_from_slice(&hs);
    rec
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::Mutex;

    /// Relay that captures everything written to it and answers reads with
    /// a fixed response (or stays silent when `silent` is set).
    struct CapturedRelay {
        captured: Arc<Mutex<Vec<u8>>>,
        response: Vec<u8>,
        silent: bool,
    }

    #[async_trait]
    impl StreamRelay for CapturedRelay {
        async fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            if self.silent {
                std::future::pending::<()>().await;
            }
            let n = self.response.len().min(buf.len());
            buf[..n].copy_from_slice(&self.response[..n]);
            Ok(n)
        }

        async fn write(&mut self, buf: &[u8]) -> std::io::Result<()> {
            self.captured.lock().unwrap().extend_from_slice(buf);
            Ok(())
        }

        async fn shutdown(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    struct FakeClient {
        captured: Arc<Mutex<Vec<u8>>>,
        dest_seen: Arc<Mutex<String>>,
        silent: bool,
    }

    #[async_trait]
    impl OutboundClient for FakeClient {
        async fn dial(
            &self, dest: &Destination,
        ) -> Result<Box<dyn StreamRelay>, Box<dyn std::error::Error>> {
            *self.dest_seen.lock().unwrap() = dest.to_string();
            Ok(Box::new(CapturedRelay {
                captured: self.captured.clone(),
                response: vec![0x16, 0x03, 0x03, 0x00, 0x04, 1, 2, 3, 4],
                silent: self.silent,
            }))
        }
    }

    #[tokio::test(start_paused = true)]
    async fn probe_measures_first_byte_round_trip() {
        let captured = Arc::new(Mutex::new(Vec::new()));
        let client = FakeClient {
            captured: captured.clone(),
            dest_seen: Arc::new(Mutex::new(String::new())),
            silent: false,
        };
        let delay = client.test_latency("https://example.com").await;
        assert!(delay.is_some());

        // The probe must have sent a ClientHello carrying the SNI.
        let sent = captured.lock().unwrap().clone();
        assert_eq!(sent[0], 0x16);
        assert!(sent
            .windows(b"example.com".len())
            .any(|w| w == b"example.com"));
    }

    #[tokio::test(start_paused = true)]
    async fn probe_uses_configured_host_port_and_http_path() {
        let captured = Arc::new(Mutex::new(Vec::new()));
        let dest_seen = Arc::new(Mutex::new(String::new()));
        let client = FakeClient {
            captured: captured.clone(),
            dest_seen: dest_seen.clone(),
            silent: false,
        };
        let delay = client
            .test_latency("http://Example.com:8080/generate_204")
            .await;
        assert!(delay.is_some());
        assert_eq!(*dest_seen.lock().unwrap(), "example.com:8080");

        let sent = captured.lock().unwrap().clone();
        let sent = String::from_utf8(sent).unwrap();
        assert_eq!(
            sent,
            "HEAD /generate_204 HTTP/1.0\r\nHost: example.com\r\n\r\n"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn probe_fails_when_target_silent() {
        let client = FakeClient {
            captured: Arc::new(Mutex::new(Vec::new())),
            dest_seen: Arc::new(Mutex::new(String::new())),
            silent: true,
        };
        assert!(client.test_latency("https://example.com").await.is_none());
    }

    #[test]
    fn parse_probe_url_cases() {
        let t = parse_probe_url("https://www.gstatic.com/generate_204")
            .unwrap();
        assert!(t.https);
        assert_eq!(t.host, "www.gstatic.com");
        assert_eq!(t.port, 443);
        assert_eq!(t.path, "/generate_204");

        let t = parse_probe_url("http://a.b:8080").unwrap();
        assert!(!t.https);
        assert_eq!(t.host, "a.b");
        assert_eq!(t.port, 8080);
        assert_eq!(t.path, "/");

        // Bare host — the historical config default ("www.google.com") —
        // is treated as https:443.
        let t = parse_probe_url("www.google.com").unwrap();
        assert!(t.https);
        assert_eq!(t.host, "www.google.com");
        assert_eq!(t.port, 443);

        let t = parse_probe_url("[2001:db8::1]:443").unwrap();
        assert_eq!(t.host, "2001:db8::1");
        assert_eq!(t.port, 443);

        assert!(parse_probe_url("").is_none());
    }

    /// Type of the first TLS extension in the ClientHello record.
    fn first_ext_type(rec: &[u8]) -> Option<u16> {
        let b = &rec[9..];
        let mut p = 2 + 32; // client_version + random
        let sid = b[p] as usize;
        p += 1 + sid;
        let cs = u16::from_be_bytes([b[p], b[p + 1]]) as usize;
        p += 2 + cs;
        p += 1 + b[p] as usize; // compression methods
        let ext_len = u16::from_be_bytes([b[p], b[p + 1]]) as usize;
        p += 2;
        if ext_len == 0 {
            return None;
        }
        Some(u16::from_be_bytes([b[p], b[p + 1]]))
    }

    #[test]
    fn client_hello_structure() {
        // Domain: record/handshake lengths consistent, SNI present first.
        let rec = tls_client_hello("Example.COM.");
        assert_eq!(rec[0], 0x16);
        assert_eq!(rec.len(), 5 + u16::from_be_bytes([rec[3], rec[4]]) as usize);
        assert_eq!(rec[5], 0x01);
        let hs_len =
            ((rec[6] as usize) << 16) | ((rec[7] as usize) << 8) | rec[8] as usize;
        assert_eq!(rec.len(), 9 + hs_len);
        assert_eq!(first_ext_type(&rec), Some(0x0000)); // server_name
        assert!(rec.windows(11).any(|w| w == b"example.com"));

        // IP literal: SNI must be omitted (RFC 6066).
        let rec = tls_client_hello("1.2.3.4");
        assert_ne!(first_ext_type(&rec), Some(0x0000));
        assert_eq!(first_ext_type(&rec), Some(0x000a)); // supported_groups
    }

    /// Live end-to-end probe against a real TLS server. Ignored by default
    /// (needs network): run with
    /// `cargo test -p anywhere --lib -- outbound::tests::live --ignored`.
    #[tokio::test]
    #[ignore]
    async fn live_probe_real_tls_target() {
        struct RawTcpClient;

        #[async_trait]
        impl OutboundClient for RawTcpClient {
            async fn dial(
                &self, dest: &Destination,
            ) -> Result<Box<dyn StreamRelay>, Box<dyn std::error::Error>>
            {
                let addr = tokio::net::lookup_host(dest.to_string())
                    .await?
                    .next()
                    .ok_or("no address resolved")?;
                let stream = tokio::net::TcpStream::connect(addr).await?;
                Ok(Box::new(crate::relay::TcpRelay::new(stream)))
            }
        }

        let delay = RawTcpClient.test_latency("https://www.baidu.com").await;
        // A real TLS server must answer the minimal ClientHello.
        assert!(delay.is_some(), "real TLS target did not answer the probe");
        log::info!("live probe www.baidu.com:443 -> {delay:?}ms");
    }
}
