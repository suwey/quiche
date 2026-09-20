// SPDX-License-Identifier: BSD-2-Clause
// Copyright © The anywhere project contributors.

//! End-to-end interop: a real xray client (`flow=xtls-rprx-vision` over
//! TLS) → anywhere VLESS inbound → echo targets.
//!
//! Three targets exercise the whole stage-1 surface:
//! - a plain TCP echo (padding phase + the filter-quota End path — no
//!   inner TLS, so no Direct), multi-size round trips through the xray
//!   client's local socks entry;
//! - a TLS echo driven with a real inner TLS 1.3 session, so Vision sees
//!   genuine inner records: padding, ServerHello detection (EnableXtls),
//!   and the Direct raw-splice handoff in both directions;
//! - raw anywhere-protocol clients asserting the rejection matrix (UDP +
//!   flow, unknown flow, flow over non-1.3 TLS) and the deferred response
//!   header + frame loop without xray.
//!
//! The xray client binary is required: `$XRAY_BIN`, else `/tmp/xray`, else
//! it is built from `$XRAY_CORE_DIR` (default `~/xray-core`) with `go
//! build`. A missing toolchain fails loudly — the interop run is the
//! acceptance criterion, never silently skipped.

use std::io::Read;
use std::io::Write;
use std::net::Shutdown;
use std::net::TcpStream;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::process::Stdio;
use std::time::Duration;

use anywhere::inbound::Destination;
use anywhere::inbound::Inbound;
use anywhere::inbound::InboundConn;
use anywhere::inbound::vless::VlessInbound;
use anywhere::protocol::vless::VlessCommand;
use anywhere::protocol::vless::encode_request_bytes;
use anywhere::relay::TcpRelay;
use anywhere::relay::bidirectional_relay;
use boring::ssl::Ssl;
use boring::ssl::SslContextBuilder;
use boring::ssl::SslFiletype;
use boring::ssl::SslMethod;
use boring::ssl::SslStream;
use boring::ssl::SslVerifyMode;
use boring::ssl::SslVersion;

/// The test user's password — used directly as the VLESS UUID.
const TEST_UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";
/// Raw UUID bytes of [`TEST_UUID`] (framing helpers cannot use
/// `parse_uuid`, which is crate-private).
const TEST_UUID_BYTES: [u8; 16] = [
    0xb8, 0x31, 0x38, 0x1d, 0x63, 0x24, 0x4d, 0x53, 0xad, 0x4f, 0x8c, 0xda,
    0x48, 0xb3, 0x08, 0x11,
];
const FLOW_XRV: &str = "xtls-rprx-vision";

const IO_TIMEOUT: Duration = Duration::from_secs(30);

// ---------------------------------------------------------------------------
// Harness helpers
// ---------------------------------------------------------------------------

/// Generate a self-signed cert; every client connects with verification
/// disabled.
fn generate_cert(dir: &Path) -> (String, String) {
    let cert = dir.join("cert.pem");
    let key = dir.join("key.pem");
    let out = Command::new("openssl")
        .args([
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-subj",
            "/CN=127.0.0.1",
            "-days",
            "2",
            "-keyout",
            key.to_str().unwrap(),
            "-out",
            cert.to_str().unwrap(),
        ])
        .output()
        .expect("spawn openssl");
    assert!(
        out.status.success(),
        "openssl failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    (
        cert.to_string_lossy().into_owned(),
        key.to_string_lossy().into_owned(),
    )
}

/// Grab a free TCP port (small bind race, acceptable in tests).
fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// Block until something accepts on `port` (the inbound's / xray's listener
/// task binds asynchronously). Probe connections die in the handshake;
/// harmless.
async fn wait_listening(port: u16) {
    for _ in 0..200 {
        if tokio::net::TcpStream::connect(("127.0.0.1", port)).await.is_ok()
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("listener on {port} never came up");
}

fn temp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "anywhere-vless-xray-{tag}-{}-{}",
        std::process::id(),
        free_port()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Boot the VLESS inbound (TLS mode, Vision-capable) behind a minimal relay
/// loop that dials the requested destination; returns the listen port.
async fn setup_inbound(cert: &str, key: &str) -> u16 {
    let listen_port = free_port();
    let config: anywhere::config::Config =
        toml::from_str(&format!(
            r#"
[[users]]
name = "tester"
password = "{TEST_UUID}"

[[inbounds]]
type = "vless"
listen = "127.0.0.1:{listen_port}"
cert = "{cert}"
key = "{key}"
"#
        ))
        .expect("parse inbound config");

    let inbound = VlessInbound::from_config(
        &config.inbounds[0],
        config.passwords(),
    )
    .expect("vless inbound from config");
    tokio::spawn(run_relay_loop(inbound));
    wait_listening(listen_port).await;
    listen_port
}

/// Minimal proxy loop: accept `InboundConn::Tcp` and dial a plain TCP
/// upstream, mirroring what the runner's relay loop does.
async fn run_relay_loop(mut inbound: VlessInbound) {
    while let Some(conn) = inbound.accept().await {
        if let InboundConn::Tcp {
            destination,
            mut stream,
            ..
        } = conn
        {
            tokio::spawn(async move {
                match tokio::net::TcpStream::connect(destination.to_string())
                    .await
                {
                    Ok(sock) => {
                        let mut up = TcpRelay::new(sock);
                        bidirectional_relay(&mut *stream, &mut up).await;
                    },
                    Err(e) => {
                        log::warn!(
                            "relay: connect {destination} failed: {e}"
                        );
                        let _ = stream.shutdown().await;
                    },
                }
            });
        }
    }
}

/// Sequential plain echo server: read a chunk, write it back, until EOF.
async fn spawn_plain_echo() -> u16 {
    use tokio::io::AsyncReadExt as _;
    use tokio::io::AsyncWriteExt as _;

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 8192];
                loop {
                    match sock.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if sock.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        },
                    }
                }
            });
        }
    });
    port
}

/// Blocking TLS echo server (the Vision "target"): TLS 1.3 only, so the
/// inner stream is unambiguous for the Direct detection. Echoes per read.
fn spawn_tls_echo(cert: &str, key: &str) -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let mut builder = SslContextBuilder::new(SslMethod::tls())
        .expect("tls echo ctx builder");
    builder
        .set_min_proto_version(Some(SslVersion::TLS1_3))
        .unwrap();
    builder
        .set_max_proto_version(Some(SslVersion::TLS1_3))
        .unwrap();
    builder
        .set_certificate_file(cert, SslFiletype::PEM)
        .expect("tls echo cert");
    builder
        .set_private_key_file(key, SslFiletype::PEM)
        .expect("tls echo key");
    let ctx = builder.build();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { break };
            let ctx = ctx.clone();
            std::thread::spawn(move || {
                let Ok(ssl) = Ssl::new(&ctx) else { return };
                let Ok(mut tls) = SslStream::new(ssl, stream) else { return };
                if tls.accept().is_err() {
                    return;
                }
                let _ = tls
                    .get_mut()
                    .set_read_timeout(Some(IO_TIMEOUT));
                let mut buf = vec![0u8; 16 * 1024];
                loop {
                    match tls.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if tls.write_all(&buf[..n]).is_err() {
                                break;
                            }
                        },
                    }
                }
            });
        }
    });
    port
}

// ---------------------------------------------------------------------------
// xray client
// ---------------------------------------------------------------------------

/// Kill the xray child on drop (and on panic unwinding).
struct XrayGuard(std::process::Child);

impl Drop for XrayGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Locate (or build) the xray client binary: `$XRAY_BIN`, else `/tmp/xray`,
/// else `go build -o /tmp/xray ./main` inside `$XRAY_CORE_DIR` (default
/// `~/xray-core`).
fn xray_binary() -> PathBuf {
    if let Ok(bin) = std::env::var("XRAY_BIN") {
        return PathBuf::from(bin);
    }
    let bin = std::env::temp_dir().join("xray");
    if bin.exists() {
        return bin;
    }
    let core = std::env::var("XRAY_CORE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            PathBuf::from(std::env::var("HOME").expect("HOME for xray-core"))
                .join("xray-core")
        });
    let out = Command::new("go")
        .args(["build", "-o"])
        .arg(&bin)
        .arg("./main")
        .current_dir(&core)
        .output()
        .unwrap_or_else(|e| {
            panic!(
                "xray binary missing at {} and `go build` in {} failed to \
                 spawn: {e}. Build xray-core first or set XRAY_BIN.",
                bin.display(),
                core.display(),
            )
        });
    assert!(
        out.status.success(),
        "`go build -o {} ./main` in {} failed:\n{}",
        bin.display(),
        core.display(),
        String::from_utf8_lossy(&out.stderr)
    );
    bin
}

/// Hex SHA-256 fingerprint of the leaf certificate (xray strips colons and
/// hex-decodes `pinnedPeerCertSha256`, transport_security.go:364-379).
fn cert_sha256_hex(cert_path: &str) -> String {
    let out = Command::new("openssl")
        .args([
            "x509",
            "-in",
            cert_path,
            "-noout",
            "-fingerprint",
            "-sha256",
        ])
        .output()
        .expect("spawn openssl fingerprint");
    assert!(
        out.status.success(),
        "openssl fingerprint failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8_lossy(&out.stdout);
    let hex: String = text
        .split('=')
        .nth(1)
        .unwrap_or("")
        .chars()
        .filter(|c| c.is_ascii_hexdigit())
        .collect();
    assert_eq!(hex.len(), 64, "unexpected fingerprint shape: {text:?}");
    hex
}

/// Spawn the xray client: local socks entry on `socks_port`, VLESS outbound
/// with `flow=xtls-rprx-vision` over TLS (self-signed leaf, pinned by its
/// SHA-256 — xray 26.x removed `allowInsecure` in favor of
/// `pinnedPeerCertSha256`) to `vless_port`.
fn spawn_xray_client(
    socks_port: u16, vless_port: u16, cert: &str, dir: &Path,
) -> XrayGuard {
    let pin = cert_sha256_hex(cert);
    let config = format!(
        r#"{{
  "log": {{ "loglevel": "warning" }},
  "inbounds": [{{
    "listen": "127.0.0.1",
    "port": {socks_port},
    "protocol": "socks",
    "settings": {{ "udp": false }}
  }}],
  "outbounds": [{{
    "protocol": "vless",
    "settings": {{
      "vnext": [{{
        "address": "127.0.0.1",
        "port": {vless_port},
        "users": [{{
          "id": "{TEST_UUID}",
          "encryption": "none",
          "flow": "{FLOW_XRV}"
        }}]
      }}]
    }},
    "streamSettings": {{
      "network": "tcp",
      "security": "tls",
      "tlsSettings": {{
        "serverName": "127.0.0.1",
        "pinnedPeerCertSha256": "{pin}"
      }}
    }}
  }}]
}}"#
    );
    let path = dir.join("xray-client.json");
    std::fs::write(&path, config).expect("write xray client config");
    let child = Command::new(xray_binary())
        .args(["run", "-c"])
        .arg(&path)
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn xray client");
    XrayGuard(child)
}

/// SOCKS5 CONNECT (no auth) to 127.0.0.1:`port` through the xray client;
/// returns the tunneled stream.
fn socks5_connect(socks_port: u16, port: u16) -> TcpStream {
    let mut s = TcpStream::connect(("127.0.0.1", socks_port))
        .expect("tcp to xray socks");
    let _ = s.set_read_timeout(Some(IO_TIMEOUT));
    let _ = s.set_write_timeout(Some(IO_TIMEOUT));
    s.write_all(&[0x05, 0x01, 0x00]).expect("socks greeting");
    let mut resp = [0u8; 2];
    s.read_exact(&mut resp).expect("socks greeting reply");
    assert_eq!(resp, [0x05, 0x00], "socks greeting refused");
    let mut req = vec![0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1];
    req.extend_from_slice(&port.to_be_bytes());
    s.write_all(&req).expect("socks connect");
    let mut head = [0u8; 4];
    s.read_exact(&mut head).expect("socks connect reply");
    assert_eq!(head[1], 0x00, "socks CONNECT refused: {head:?}");
    let skip = match head[3] {
        0x01 => 6,
        0x04 => 18,
        0x03 => {
            let mut l = [0u8; 1];
            s.read_exact(&mut l).expect("socks domain length");
            1 + l[0] as usize + 2
        },
        other => panic!("socks atyp {other}"),
    };
    let mut rest = vec![0u8; skip];
    s.read_exact(&mut rest).expect("socks bind addr");
    s
}

/// Deterministic payload of `size` bytes.
fn payload(size: usize) -> Vec<u8> {
    (0..size).map(|i| (i * 7 % 251) as u8).collect()
}

// ---------------------------------------------------------------------------
// Tests — real xray client interop
// ---------------------------------------------------------------------------

/// Plain inner stream: padding phase, then the filter-quota End path (no
/// inner TLS → never Direct). Multi-size round trips through the xray
/// client's socks entry.
#[tokio::test(flavor = "multi_thread")]
async fn xray_vision_plain_echo_roundtrip() {
    let guard = tokio::time::timeout(Duration::from_secs(300), async {
        let tmp = temp_dir("plain");
        let (cert, key) = generate_cert(&tmp);
        let inbound_port = setup_inbound(&cert, &key).await;
        let echo_port = spawn_plain_echo().await;

        let socks_port = free_port();
        let xray = spawn_xray_client(socks_port, inbound_port, &cert, &tmp);
        wait_listening(socks_port).await;

        for size in [1usize, 64, 1500, 64 * 1024, 256 * 1024] {
            let mut sock = socks5_connect(socks_port, echo_port);
            let want = payload(size);
            sock.write_all(&want).expect("write through socks");
            let mut got = vec![0u8; size];
            sock.read_exact(&mut got).expect("read echo through socks");
            assert_eq!(got, want, "echo mismatch at {size} bytes");
            let _ = sock.shutdown(Shutdown::Both);
        }
        drop(xray);
    });
    guard.await.expect("xray plain echo roundtrip timed out");
}

/// TLS 1.3 inner stream: Vision padding, inner ServerHello detection, and
/// the Direct raw-splice handoff in both directions. The inner TLS session
/// doubles as an integrity oracle — any framing bug corrupts it.
#[tokio::test(flavor = "multi_thread")]
async fn xray_vision_tls_inner_direct_splice() {
    let _ = env_logger::try_init();
    let guard = tokio::time::timeout(Duration::from_secs(300), async {
        let tmp = temp_dir("tls");
        let (cert, key) = generate_cert(&tmp);
        let inbound_port = setup_inbound(&cert, &key).await;
        let echo_port = spawn_tls_echo(&cert, &key);

        let socks_port = free_port();
        let xray = spawn_xray_client(socks_port, inbound_port, &cert, &tmp);
        wait_listening(socks_port).await;

        for k in 0..2 {
            let sock = socks5_connect(socks_port, echo_port);
            // Inner TLS 1.3 client over the tunneled stream (target cert is
            // self-signed; the tunnel endpoints authenticate each other).
            let mut builder = SslContextBuilder::new(SslMethod::tls())
                .expect("inner ctx builder");
            builder.set_verify(SslVerifyMode::NONE);
            builder
                .set_min_proto_version(Some(SslVersion::TLS1_3))
                .unwrap();
            builder
                .set_max_proto_version(Some(SslVersion::TLS1_3))
                .unwrap();
            let ssl =
                Ssl::new(&builder.build()).expect("inner ssl");
            let mut tls = SslStream::new(ssl, sock).expect("inner stream");
            tls.connect()
                .unwrap_or_else(|e| panic!("inner tls handshake {k}: {e}"));

            // Escalating sizes: small (padding), record-boundary, and
            // multi-record (post-Direct splice) payloads.
            for size in [1usize, 1000, 16 * 1024 + 5, 100 * 1024, 1024 * 1024]
            {
                let want = payload(size);
                tls.write_all(&want)
                    .unwrap_or_else(|e| panic!("inner write {k}/{size}: {e}"));
                let mut got = vec![0u8; size];
                tls.read_exact(&mut got)
                    .unwrap_or_else(|e| panic!("inner read {k}/{size}: {e}"));
                assert_eq!(got, want, "inner echo mismatch {k}/{size} bytes");
            }
            drop(tls);
        }
        drop(xray);
    });
    guard.await.expect("xray tls inner roundtrip timed out");
}

// ---------------------------------------------------------------------------
// Tests — protocol-level rejection matrix and deferred header (no xray)
// ---------------------------------------------------------------------------

/// Outer TLS client to the inbound (verification off, optional version
/// ceiling for the TLS 1.2 case).
fn outer_tls_client(port: u16, max: Option<SslVersion>) -> SslStream<TcpStream> {
    let sock =
        TcpStream::connect(("127.0.0.1", port)).expect("tcp to inbound");
    let _ = sock.set_read_timeout(Some(IO_TIMEOUT));
    let _ = sock.set_write_timeout(Some(IO_TIMEOUT));
    let mut builder = SslContextBuilder::new(SslMethod::tls())
        .expect("outer ctx builder");
    builder.set_verify(SslVerifyMode::NONE);
    if let Some(max) = max {
        builder.set_max_proto_version(Some(max)).unwrap();
    }
    let ssl = Ssl::new(&builder.build()).expect("outer ssl");
    let mut tls = SslStream::new(ssl, sock).expect("outer stream");
    tls.connect().expect("outer tls handshake");
    tls
}

fn reject_dest() -> Destination {
    Destination::new(
        anywhere::inbound::Address::Ipv4([127, 0, 0, 1]),
        9999,
    )
}

/// Rejected flows get no response at all: the server closes before the
/// deferred response header is ever written.
#[tokio::test(flavor = "multi_thread")]
async fn vision_flow_rejections() {
    let guard = tokio::time::timeout(Duration::from_secs(120), async {
        let tmp = temp_dir("reject");
        let (cert, key) = generate_cert(&tmp);
        let inbound_port = setup_inbound(&cert, &key).await;

        let expect_eof = |name: &str, mut tls: SslStream<TcpStream>, req: Vec<u8>| {
            tls.write_all(&req).expect(name);
            let mut buf = [0u8; 2];
            let n = tls.read(&mut buf).expect("read after reject");
            assert_eq!(n, 0, "{name}: expected EOF, got {n} bytes");
        };

        // UDP + vision flow (inbound.go:557-558).
        let tls = outer_tls_client(inbound_port, None);
        expect_eof(
            "udp+flow",
            tls,
            encode_request_bytes(
                &TEST_UUID_BYTES,
                Some(FLOW_XRV),
                VlessCommand::Udp,
                &reject_dest(),
            ),
        );

        // Unknown flow (inbound.go:597-599).
        let tls = outer_tls_client(inbound_port, None);
        expect_eof(
            "unknown flow",
            tls,
            encode_request_bytes(
                &TEST_UUID_BYTES,
                Some("xtls-rprx-dark"),
                VlessCommand::Tcp,
                &reject_dest(),
            ),
        );

        // Vision over outer TLS 1.2 (inbound.go:571-574).
        let tls = outer_tls_client(inbound_port, Some(SslVersion::TLS1_2));
        expect_eof(
            "tls1.2+flow",
            tls,
            encode_request_bytes(
                &TEST_UUID_BYTES,
                Some(FLOW_XRV),
                VlessCommand::Tcp,
                &reject_dest(),
            ),
        );
    });
    guard.await.expect("vision flow rejection tests timed out");
}

/// Positive control without xray: a hand-framed Vision client gets the
/// response header coalesced into the first downlink frame and its content
/// echoed back through the padding machine.
#[tokio::test(flavor = "multi_thread")]
async fn vision_hand_framed_roundtrip() {
    let guard = tokio::time::timeout(Duration::from_secs(120), async {
        let tmp = temp_dir("hand");
        let (cert, key) = generate_cert(&tmp);
        let inbound_port = setup_inbound(&cert, &key).await;
        let echo_port = spawn_plain_echo().await;

        let mut tls = outer_tls_client(inbound_port, None);
        // Request + first (UUID-prefixed, long-padded) Vision frame in one
        // flush — the way clients write it.
        let content = b"hand framed vision probe".to_vec();
        let mut out = encode_request_bytes(
            &TEST_UUID_BYTES,
            Some(FLOW_XRV),
            VlessCommand::Tcp,
            &Destination::new(
                anywhere::inbound::Address::Ipv4([127, 0, 0, 1]),
                echo_port,
            ),
        );
        out.extend_from_slice(&TEST_UUID_BYTES);
        out.push(0x00); // PaddingContinue
        out.extend_from_slice(&(content.len() as u16).to_be_bytes());
        out.extend_from_slice(&900u16.to_be_bytes());
        out.extend_from_slice(&content);
        out.extend(std::iter::repeat_n(0u8, 900));
        tls.write_all(&out).expect("request + frame");

        // Response header rides with the first downlink frame.
        let mut head = [0u8; 2];
        tls.read_exact(&mut head).expect("response header");
        assert_eq!(head, [0x00, 0x00], "deferred VLESS response header");
        let mut uuid = [0u8; 16];
        tls.read_exact(&mut uuid).expect("frame uuid");
        assert_eq!(uuid, TEST_UUID_BYTES, "first frame carries the UUID");
        let mut fh = [0u8; 5];
        tls.read_exact(&mut fh).expect("frame header");
        assert_eq!(fh[0], 0x00, "padding continue");
        let clen = u16::from_be_bytes([fh[1], fh[2]]) as usize;
        let plen = u16::from_be_bytes([fh[3], fh[4]]) as usize;
        let mut echoed = vec![0u8; clen + plen];
        tls.read_exact(&mut echoed).expect("frame body");
        assert_eq!(&echoed[..clen], &content[..], "echoed content");
    });
    guard.await.expect("hand framed roundtrip timed out");
}
