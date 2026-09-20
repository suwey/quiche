// SPDX-License-Identifier: BSD-2-Clause
// Copyright © The anywhere project contributors.

//! End-to-end loopback test: vless outbound → vless inbound → echo.
//!
//! Boots a real [`VlessInbound`] (optional TLS accept + ws upgrade + VLESS
//! request parse + UUID auth + relay loop) and drives it with a real
//! [`VlessOutboundClient`], so the ws handshake compatibility between the
//! ws client transport and the inbound's ws server framing, the VLESS
//! request encoding, and the UDP ([2-byte BE length]+[packet]) framing are
//! all exercised over an actual connection.

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

/// The test user's password — used directly as the VLESS UUID, exactly like
/// the outbound does.
const TEST_UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";

/// Generate a self-signed cert; the outbound connects with `insecure = true`.
fn generate_cert(dir: &std::path::Path) -> (String, String) {
    let cert = dir.join("cert.pem");
    let key = dir.join("key.pem");
    let out = std::process::Command::new("openssl")
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

/// Sequential echo server: read a chunk, write it back, until EOF.
async fn spawn_echo_server() -> u16 {
    use tokio::io::AsyncReadExt;
    use tokio::io::AsyncWriteExt;

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

/// Minimal proxy loop: accept `InboundConn`s and dial a plain TCP/UDP
/// upstream, mirroring what the runner's relay loop does.
///
/// `udp_upstream` is a harness NAT: the vless outbound only dials udp/53
/// (its DNS-only contract), so a UDP echo test routes every upstream send
/// to the echo socket's real (ephemeral) address instead of the :53 the
/// client insisted on.
async fn run_relay_loop(
    mut inbound: impl Inbound + 'static, udp_upstream: Option<String>,
) {
    while let Some(conn) = inbound.accept().await {
        match conn {
            InboundConn::Tcp {
                destination,
                mut stream,
                ..
            } => {
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
                                "loopback relay: connect {destination} failed: {e}"
                            );
                            let _ = stream.shutdown().await;
                        },
                    }
                });
            },
            InboundConn::Udp {
                initial_destination,
                mut packet,
                ..
            } => {
                let udp_upstream = udp_upstream.clone();
                tokio::spawn(async move {
                    let Some(upstream) = udp_upstream else {
                        let _ = packet.close().await;
                        return;
                    };
                    let Ok(sock) =
                        tokio::net::UdpSocket::bind("127.0.0.1:0").await
                    else {
                        let _ = packet.close().await;
                        return;
                    };
                    let _ = initial_destination; // NATed to `upstream`
                    let mut up_buf = vec![0u8; 65535];
                    let mut down_buf = vec![0u8; 65535];
                    loop {
                        tokio::select! {
                            r = packet.read_packet(&mut up_buf) => match r {
                                Ok((0, _)) | Err(_) => break,
                                Ok((n, _dest)) => {
                                    if sock.send_to(&up_buf[..n], &upstream)
                                        .await
                                        .is_err()
                                    {
                                        break;
                                    }
                                },
                            },
                            r = sock.recv_from(&mut down_buf) => match r {
                                Ok((n, _from)) => {
                                    if packet
                                        .write_packet(
                                            &down_buf[..n],
                                            &initial_destination,
                                        )
                                        .await
                                        .is_err()
                                    {
                                        break;
                                    }
                                },
                                Err(_) => break,
                            },
                        }
                    }
                    let _ = packet.close().await;
                });
            },
        }
    }
}

/// Block until something accepts on `port` (the inbound's listener task
/// binds asynchronously). The probe connection dies in the handshake;
/// harmless.
async fn wait_listening(port: u16) {
    for _ in 0..100 {
        if tokio::net::TcpStream::connect(("127.0.0.1", port)).await.is_ok()
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("listener on {port} never came up");
}

/// Boot a vless inbound + relay loop and return a matching outbound client.
///
/// `plain = false`: TLS (self-signed cert) + ws on `/ws`, the inbound
/// requires `Host: localhost`. `plain = true`: plaintext ws on `/plain`
/// (outbound `sni = ""` skips TLS, as in `build_ws_async`), the inbound
/// requires `Host: 127.0.0.1`.
async fn setup(
    udp_upstream: Option<String>, plain: bool,
) -> VlessOutboundClient {
    let _ = env_logger::try_init();
    let tmp = std::env::temp_dir().join(format!(
        "anywhere-vless-loopback-{}-{}",
        std::process::id(),
        free_port()
    ));
    std::fs::create_dir_all(&tmp).unwrap();

    let listen_port = free_port();
    let (inbound_toml, outbound_toml) = if plain {
        (
            format!(
                r#"
[[inbounds]]
type = "vless"
listen = "127.0.0.1:{listen_port}"

[inbounds.transport]
type = "ws"

[inbounds.transport.ws]
path = "/plain"
headers = {{ Host = "127.0.0.1" }}
"#
            ),
            format!(
                r#"
[[outbounds]]
type = "vless"
server = "127.0.0.1:{listen_port}"
password = "{TEST_UUID}"
sni = ""
tls_fragment = false

[outbounds.transport]
type = "ws"

[outbounds.transport.ws]
path = "/plain"
headers = {{ Host = "127.0.0.1" }}

[outbounds.xmux]
pool_size = 1
"#
            ),
        )
    } else {
        let (cert, key) = generate_cert(&tmp);
        (
            format!(
                r#"
[[inbounds]]
type = "vless"
listen = "127.0.0.1:{listen_port}"
cert = "{cert}"
key = "{key}"

[inbounds.transport]
type = "ws"

[inbounds.transport.ws]
path = "/ws"
headers = {{ Host = "localhost" }}
"#
            ),
            format!(
                r#"
[[outbounds]]
type = "vless"
server = "127.0.0.1:{listen_port}"
password = "{TEST_UUID}"
sni = "localhost"
insecure = true
tls_fragment = false

[outbounds.transport]
type = "ws"

[outbounds.transport.ws]
path = "/ws"

[outbounds.xmux]
pool_size = 1
"#
            ),
        )
    };

    let config: anywhere::config::Config = toml::from_str(&format!(
        r#"
[[users]]
name = "tester"
password = "{TEST_UUID}"

{inbound_toml}

{outbound_toml}
"#
    ))
    .unwrap();

    let inbound = VlessInbound::from_config(
        &config.inbounds[0],
        config.passwords(),
    )
    .expect("vless inbound from config");
    tokio::spawn(run_relay_loop(inbound, udp_upstream));
    wait_listening(listen_port).await;

    let client = VlessOutboundClient::from_config(vec![&config.outbounds[0]])
        .await
        .expect("vless outbound from config");
    client
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
    relay.shutdown().await.expect("shutdown");
}

#[tokio::test(flavor = "multi_thread")]
async fn ws_tls_tcp_roundtrip() {
    let guard = tokio::time::timeout(Duration::from_secs(120), async {
        let client = setup(None, false).await;
        let client = std::sync::Arc::new(client);
        let echo_port = spawn_echo_server().await;
        let dest =
            Destination::from_str(&format!("127.0.0.1:{echo_port}")).unwrap();

        for size in [64usize, 4096, 256 * 1024] {
            let mut relay = client.dial(&dest).await.expect("dial");
            let payload: Vec<u8> =
                (0..size).map(|i| (i * 7 % 251) as u8).collect();
            transfer_roundtrip(relay.as_mut(), payload).await;
        }

        // Concurrent VLESS streams — each dial is its own TCP connection.
        let mut tasks = Vec::new();
        for k in 0..4u32 {
            let client = client.clone();
            let dest = dest.clone();
            tasks.push(tokio::spawn(async move {
                let mut relay = client.dial(&dest).await.expect("dial");
                let payload: Vec<u8> = (0..64 * 1024u32)
                    .map(|i| ((i + k * 31) % 251) as u8)
                    .collect();
                transfer_roundtrip(relay.as_mut(), payload).await;
            }));
        }
        for t in tasks {
            t.await.expect("stream task");
        }
    });
    guard.await.expect("ws_tls_tcp_roundtrip timed out");
}

#[tokio::test(flavor = "multi_thread")]
async fn ws_plain_tcp_roundtrip() {
    let guard = tokio::time::timeout(Duration::from_secs(60), async {
        let client = setup(None, true).await;
        let echo_port = spawn_echo_server().await;
        let dest =
            Destination::from_str(&format!("127.0.0.1:{echo_port}")).unwrap();

        let mut relay = client.dial(&dest).await.expect("dial");
        let payload: Vec<u8> =
            (0..128 * 1024).map(|i| (i * 13 % 253) as u8).collect();
        transfer_roundtrip(relay.as_mut(), payload).await;
    });
    guard.await.expect("ws_plain_tcp_roundtrip timed out");
}

#[tokio::test(flavor = "multi_thread")]
async fn ws_udp_roundtrip() {
    let guard = tokio::time::timeout(Duration::from_secs(60), async {
        let echo = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            let mut buf = [0u8; 65535];
            loop {
                let Ok((n, from)) = echo.recv_from(&mut buf).await else {
                    break;
                };
                let _ = echo.send_to(&buf[..n], from).await;
            }
        });

        let client = setup(Some(echo_addr), false).await;

        // The vless outbound only allows udp/53; the harness NAT maps :53 to
        // the echo socket's ephemeral port.
        let dest = Destination::from_str("127.0.0.1:53").unwrap();

        let mut relay = None;
        for _ in 0..50 {
            match client.dial_udp(&dest).await {
                Ok(r) => {
                    relay = Some(r);
                    break;
                },
                Err(_) => {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                },
            }
        }
        let mut relay = relay.expect("dial_udp after retries");

        for k in 0..8u32 {
            let msg = format!("datagram-{k}").into_bytes();
            relay.write_packet(&msg, &dest).await.expect("write_packet");
            let mut buf = vec![0u8; 4096];
            let (n, _got_dest) =
                relay.read_packet(&mut buf).await.expect("read_packet");
            assert!(n > 0, "empty datagram");
            assert_eq!(&buf[..n], &msg);
        }
        let _ = relay.close().await;
    });
    guard.await.expect("ws_udp_roundtrip timed out");
}
