// SPDX-License-Identifier: BSD-2-Clause
// Copyright © The anywhere project contributors.

//! End-to-end interop: XTLS REALITY server (phase 2).
//!
//! Dual interop against the REALITY inbound, both directions required for
//! acceptance:
//! - a real xray client (`security: "reality"`, utls fingerprint, Vision
//!   flow) → anywhere VLESS inbound → echo targets — plain TCP round trips
//!   and a real inner TLS 1.3 session driving the Vision Direct raw-splice;
//! - the anywhere vless outbound (`reality` + `flow`) → the same inbound —
//!   the per-connection Ed25519/HMAC certificate is verified by the
//!   anywhere client's boring verify callback;
//! - transparent fallback: unauthenticated bytes are spliced to `dest`
//!   (a local echo) instead of being answered, so a prober sees the
//!   camouflage site;
//! - the anywhere outbound refuses a server whose one-time certificate
//!   does not carry the expected HMAC.
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
use std::str::FromStr;
use std::time::Duration;

use anywhere::inbound::Destination;
use anywhere::inbound::Inbound;
use anywhere::inbound::InboundConn;
use anywhere::inbound::vless::VlessInbound;
use anywhere::outbound::OutboundClient;
use anywhere::outbound::vless::VlessOutboundClient;
use anywhere::relay::StreamRelay;
use anywhere::relay::TcpRelay;
use anywhere::relay::bidirectional_relay;
use anywhere::transport::reality_server::public_key_from_private;
use base64::Engine;
use boring::ssl::Ssl;
use boring::ssl::SslContextBuilder;
use boring::ssl::SslFiletype;
use boring::ssl::SslMethod;
use boring::ssl::SslStream;
use boring::ssl::SslVerifyMode;
use boring::ssl::SslVersion;

/// The test user's password — used directly as the VLESS UUID.
const TEST_UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";
const FLOW_XRV: &str = "xtls-rprx-vision";

/// The REALITY serverName (xray `serverName` / `[inbounds.reality]
/// server_names`) — a name, not the dial address, exactly like production.
const SNI: &str = "www.example.com";

/// Fixed REALITY X25519 keypair seed (x25519 clamps it the same way on both
/// xray and anywhere, so the derived public key is what `xray x25519` would
/// print for this private key).
const SERVER_PRIVATE_SEED: [u8; 32] = [
    0x35, 0x07, 0x9d, 0x8e, 0x44, 0x91, 0x0c, 0xb2, 0xa3, 0x5f, 0x61, 0x77,
    0x08, 0xdc, 0x29, 0xb4, 0x51, 0x6e, 0xf0, 0x83, 0x9a, 0xc5, 0x12, 0x7f,
    0x64, 0xbb, 0xd8, 0x21, 0x90, 0x4a, 0xe6, 0x33,
];
/// Accepted session_id short_id (hex).
const SHORT_ID: &str = "0123abcd";

const IO_TIMEOUT: Duration = Duration::from_secs(30);

// ---------------------------------------------------------------------------
// Harness helpers
// ---------------------------------------------------------------------------

/// base64url (no padding) — the `xray x25519` output convention.
fn b64url(bytes: &[u8]) -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    URL_SAFE_NO_PAD.encode(bytes)
}

/// The REALITY X25519 keypair as (private_key, public_key) base64url strings.
fn reality_keypair() -> (String, String) {
    let public = public_key_from_private(&SERVER_PRIVATE_SEED);
    (b64url(&SERVER_PRIVATE_SEED), b64url(&public))
}

/// Generate a self-signed cert (for the inner TLS echo server only — the
/// REALITY server signs its certificates dynamically).
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

fn temp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "anywhere-vless-reality-{tag}-{}-{}",
        std::process::id(),
        free_port()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Block until something accepts on `port` (the inbound's / xray's listener
/// task binds asynchronously). Probe connections die in the REALITY peek;
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

/// Sequential plain echo server: read a chunk, write it back, until EOF.
/// Doubles as the REALITY `dest`: unauthenticated connections are spliced
/// here and their bytes echoed straight back.
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

/// Boot the VLESS inbound in REALITY mode behind a minimal relay loop;
/// returns the listen port. `fallback_port` is the splice target
/// (`[inbounds.reality] dest`).
async fn setup_inbound(fallback_port: u16) -> u16 {
    let listen_port = free_port();
    let (private_key, _) = reality_keypair();
    let config: anywhere::config::Config =
        toml::from_str(&format!(
            r#"
[[users]]
name = "tester"
password = "{TEST_UUID}"

[[inbounds]]
type = "vless"
listen = "127.0.0.1:{listen_port}"

[inbounds.reality]
dest = "127.0.0.1:{fallback_port}"
server_names = ["{SNI}"]
private_key = "{private_key}"
short_ids = ["", "{SHORT_ID}"]
max_time_diff_ms = 60000
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

/// Spawn the xray client: local socks entry on `socks_port`, VLESS outbound
/// with `security: "reality"` (`fingerprint: chrome`, Vision flow) to
/// `vless_port`. The REALITY certificate is dynamic; no pinning is needed.
fn spawn_xray_reality_client(
    socks_port: u16, vless_port: u16, dir: &Path,
) -> XrayGuard {
    let (_, public_key) = reality_keypair();
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
      "security": "reality",
      "realitySettings": {{
        "show": false,
        "fingerprint": "chrome",
        "serverName": "{SNI}",
        "publicKey": "{public_key}",
        "shortId": "{SHORT_ID}",
        "spiderX": "/"
      }}
    }}
  }}]
}}"#
    );
    let path = dir.join("xray-reality-client.json");
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
// anywhere outbound (reality + flow)
// ---------------------------------------------------------------------------

/// Boot a matching anywhere vless outbound (`reality` section + Vision flow)
/// against the already-running inbound.
async fn setup_outbound(vless_port: u16) -> VlessOutboundClient {
    let (_, public_key) = reality_keypair();
    let config: anywhere::config::Config = toml::from_str(&format!(
        r#"
[[outbounds]]
type = "vless"
server = "127.0.0.1:{vless_port}"
password = "{TEST_UUID}"
sni = "{SNI}"
flow = "{FLOW_XRV}"
tls_fragment = false

[outbounds.reality]
public_key = "{public_key}"
short_id = "{SHORT_ID}"

[outbounds.xmux]
pool_size = 1
"#
    ))
    .expect("parse outbound config");

    VlessOutboundClient::from_config(vec![&config.outbounds[0]])
        .await
        .expect("vless outbound from config")
}

/// Write `payload` in 16 KB chunks (the real relay uses 16 KB chunks) and
/// verify the echo, then close the write side like the real relay loop.
async fn transfer_roundtrip(relay: &mut dyn StreamRelay, payload: Vec<u8>) {
    let expected = payload.len();
    for (i, chunk) in payload.chunks(16 * 1024).enumerate() {
        if let Err(e) = relay.write(chunk).await {
            panic!("write chunk {i}: {e}");
        }
    }
    let mut received = vec![0u8; expected];
    let mut got = 0usize;
    while got < expected {
        let n = relay
            .read(&mut received[got..])
            .await
            .unwrap_or_else(|e| panic!("read echo after {got}/{expected}: {e}"));
        assert!(n > 0, "echo EOF after {got}/{expected} bytes");
        got += n;
    }
    assert_eq!(received, payload);
    // Close the write side like the real relay loop does, so the server
    // relay finishes and the stream is cleaned up on both ends.
    relay.shutdown().await.expect("shutdown");
}

// ---------------------------------------------------------------------------
// Tests — real xray client interop (xray → anywhere REALITY + Vision)
// ---------------------------------------------------------------------------

/// Plain inner stream: padding phase, then the filter-quota End path (no
/// inner TLS → never Direct). Multi-size round trips through the xray
/// client's socks entry.
#[tokio::test(flavor = "multi_thread")]
async fn xray_reality_plain_echo_roundtrip() {
    let _ = env_logger::try_init();
    let guard = tokio::time::timeout(Duration::from_secs(300), async {
        let tmp = temp_dir("plain");
        let fallback_port = spawn_plain_echo().await;
        let inbound_port = setup_inbound(fallback_port).await;

        let socks_port = free_port();
        let xray = spawn_xray_reality_client(socks_port, inbound_port, &tmp);
        wait_listening(socks_port).await;

        for size in [1usize, 64, 1500, 64 * 1024, 256 * 1024] {
            let mut sock = socks5_connect(socks_port, fallback_port);
            let want = payload(size);
            sock.write_all(&want).expect("write through socks");
            let mut got = vec![0u8; size];
            sock.read_exact(&mut got).expect("read echo through socks");
            assert_eq!(got, want, "echo mismatch at {size} bytes");
            let _ = sock.shutdown(Shutdown::Both);
        }
        drop(xray);
    });
    guard.await.expect("xray reality plain echo roundtrip timed out");
}

/// TLS 1.3 inner stream: Vision padding, inner ServerHello detection, and
/// the Direct raw-splice handoff in both directions — now over the REALITY
/// transport. The inner TLS session doubles as an integrity oracle — any
/// framing bug corrupts it.
#[tokio::test(flavor = "multi_thread")]
async fn xray_reality_tls_inner_direct_splice() {
    let _ = env_logger::try_init();
    let guard = tokio::time::timeout(Duration::from_secs(300), async {
        let tmp = temp_dir("tls");
        let (cert, key) = generate_cert(&tmp);
        let fallback_port = spawn_plain_echo().await;
        let inbound_port = setup_inbound(fallback_port).await;
        let echo_port = spawn_tls_echo(&cert, &key);

        let socks_port = free_port();
        let xray = spawn_xray_reality_client(socks_port, inbound_port, &tmp);
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
            for size in [1usize, 1000, 16 * 1024 + 5, 100 * 1024] {
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
    guard.await.expect("xray reality tls inner roundtrip timed out");
}

// ---------------------------------------------------------------------------
// Tests — anywhere outbound (reality + flow) → anywhere inbound
// ---------------------------------------------------------------------------

/// The anywhere outbound (reality + Vision flow) against the anywhere
/// inbound: REALITY pre-handshake auth both ways, the per-connection
/// Ed25519/HMAC certificate verified by the anywhere client, VLESS request
/// + Vision framing and multi-size echo round trips, plus concurrent
/// streams.
#[tokio::test(flavor = "multi_thread")]
async fn anywhere_reality_roundtrip() {
    let _ = env_logger::try_init();
    let guard = tokio::time::timeout(Duration::from_secs(180), async {
        let fallback_port = spawn_plain_echo().await;
        let inbound_port = setup_inbound(fallback_port).await;
        let client = setup_outbound(inbound_port).await;
        let client = std::sync::Arc::new(client);

        // Fresh stream per size — crosses the padding stop boundary several
        // times, exercising the server-side Vision packet counter.
        let echo_port = fallback_port;
        let dest =
            Destination::from_str(&format!("127.0.0.1:{echo_port}")).unwrap();
        for size in [64usize, 4096, 256 * 1024] {
            let mut relay = client.dial(&dest).await.expect("dial");
            let payload = payload(size);
            transfer_roundtrip(relay.as_mut(), payload).await;
        }

        // Concurrent VLESS streams — each dial is its own REALITY connection.
        let mut tasks = Vec::new();
        for k in 0..4u32 {
            let client = client.clone();
            let dest = dest.clone();
            tasks.push(tokio::spawn(async move {
                let mut relay = client.dial(&dest).await.expect("dial");
                let payload: Vec<u8> =
                    (0..64 * 1024u32).map(|i| ((i + k * 31) % 251) as u8).collect();
                transfer_roundtrip(relay.as_mut(), payload).await;
            }));
        }
        for t in tasks {
            t.await.expect("stream task");
        }
    });
    guard.await.expect("anywhere reality roundtrip timed out");
}

// ---------------------------------------------------------------------------
// Tests — transparent fallback and one-time-certificate authentication
// ---------------------------------------------------------------------------

/// Unauthenticated bytes are spliced to `dest` byte-for-byte (xray
/// tls.go:271-286): a prober talking plain HTTP to the REALITY port gets
/// exactly the camouflage site's reply — here, the echo of its own probe —
/// and so does a well-formed TLS 1.3 ClientHello presenting the wrong SNI
/// (plan §5 acceptance item ⑥: wrong SNI/short_id falls back silently).
#[tokio::test(flavor = "multi_thread")]
async fn unauthenticated_connections_fall_back_to_dest() {
    let _ = env_logger::try_init();
    let guard = tokio::time::timeout(Duration::from_secs(120), async {
        let fallback_port = spawn_plain_echo().await;
        let inbound_port = setup_inbound(fallback_port).await;

        // A complete ClientHello: TLS 1.3 offered, 32-byte session_id (no
        // REALITY payload), but an SNI outside server_names.
        let mut body = vec![0x03u8, 0x03];
        body.extend_from_slice(&[0x5a; 32]); // random
        body.push(32);
        body.extend_from_slice(&[0xa5; 32]); // session_id
        body.extend_from_slice(&2u16.to_be_bytes());
        body.extend_from_slice(&0x1301u16.to_be_bytes());
        body.push(1); // compression methods
        body.push(0);
        let sni = b"wrong.example.com";
        let mut sni_ext = vec![0u8]; // host_name type
        sni_ext.extend_from_slice(&(sni.len() as u16).to_be_bytes());
        sni_ext.extend_from_slice(sni);
        let mut sni_list = (sni_ext.len() as u16).to_be_bytes().to_vec();
        sni_list.extend_from_slice(&sni_ext);
        let mut exts = vec![];
        exts.extend_from_slice(&0u16.to_be_bytes());
        exts.extend_from_slice(&(sni_list.len() as u16).to_be_bytes());
        exts.extend_from_slice(&sni_list);
        exts.extend_from_slice(&43u16.to_be_bytes()); // supported_versions
        exts.extend_from_slice(&3u16.to_be_bytes());
        exts.push(2);
        exts.extend_from_slice(&0x0304u16.to_be_bytes());
        body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        body.extend_from_slice(&exts);
        let mut wrong_sni_hello = vec![0x16u8, 0x03, 0x01];
        // Record payload = 1-byte handshake type + 3-byte length + body.
        wrong_sni_hello
            .extend_from_slice(&((body.len() + 4) as u16).to_be_bytes());
        wrong_sni_hello.push(0x01); // handshake: ClientHello
        wrong_sni_hello.extend_from_slice(&[
            (body.len() >> 16) as u8,
            (body.len() >> 8) as u8,
            body.len() as u8,
        ]);
        wrong_sni_hello.extend_from_slice(&body);

        for probe in [
            &b"GET / HTTP/1.1\r\nHost: prober\r\n\r\n"[..],
            // Complete CCS record: not a ClientHello flight at all.
            &b"\x14\x03\x03\x00\x01\x01"[..],
            &wrong_sni_hello[..],
        ] {
            let mut sock =
                TcpStream::connect(("127.0.0.1", inbound_port))
                    .expect("tcp to inbound");
            let _ = sock.set_read_timeout(Some(IO_TIMEOUT));
            let _ = sock.set_write_timeout(Some(IO_TIMEOUT));
            sock.write_all(probe).expect("write probe");
            let mut got = vec![0u8; probe.len()];
            sock.read_exact(&mut got).expect("read splice echo");
            assert_eq!(got, probe, "fallback splice must echo dest bytes");
            let _ = sock.shutdown(Shutdown::Both);
        }
    });
    guard.await.expect("fallback splice test timed out");
}

/// The anywhere client authenticates the server's one-time certificate
/// (HMAC-SHA512(AuthKey, ed25519 pub) == signature): an outbound keyed with
/// a different REALITY public key must fail the handshake instead of
/// silently connecting.
#[tokio::test(flavor = "multi_thread")]
async fn outbound_rejects_wrong_reality_key() {
    let _ = env_logger::try_init();
    let guard = tokio::time::timeout(Duration::from_secs(120), async {
        let fallback_port = spawn_plain_echo().await;
        let inbound_port = setup_inbound(fallback_port).await;

        // A valid base64 X25519 key, but not the server's.
        let wrong_public = b64url(&[0x11u8; 32]);
        let config: anywhere::config::Config = toml::from_str(&format!(
            r#"
[[outbounds]]
type = "vless"
server = "127.0.0.1:{inbound_port}"
password = "{TEST_UUID}"
sni = "{SNI}"
flow = "{FLOW_XRV}"
tls_fragment = false

[outbounds.reality]
public_key = "{wrong_public}"
short_id = "{SHORT_ID}"
"#
        ))
        .expect("parse outbound config");
        let client = VlessOutboundClient::from_config(vec![&config.outbounds[0]])
            .await
            .expect("vless outbound from config");

        let dest =
            Destination::from_str(&format!("127.0.0.1:{fallback_port}"))
                .unwrap();
        match client.dial(&dest).await {
            Ok(mut relay) => {
                let _ = relay.shutdown().await;
                panic!("wrong-key dial must fail");
            },
            Err(err) => log::debug!("wrong-key dial error: {err}"),
        }
    });
    guard.await.expect("wrong reality key test timed out");
}
