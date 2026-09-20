// SPDX-License-Identifier: BSD-2-Clause
// Copyright © The anywhere project contributors.

//! End-to-end loopback test: anytls outbound → anytls inbound → echo.
//!
//! Boots a real [`AnytlsInbound`] (TLS accept + auth + session loop) and
//! drives it with a real [`AnyTlsOutboundClient`], so the blocking session
//! loop, settings negotiation, padding writes, stream multiplexing and the
//! UoT (UDP-over-TCP) path are all exercised over an actual TLS connection.

use std::str::FromStr;
use std::time::Duration;

use anywhere::inbound::Destination;
use anywhere::inbound::Inbound;
use anywhere::inbound::InboundConn;
use anywhere::inbound::anytls::AnytlsInbound;
use anywhere::outbound::OutboundClient;
use anywhere::outbound::anytls::AnyTlsOutboundClient;
use anywhere::relay::StreamRelay;
use anywhere::relay::TcpRelay;
use anywhere::relay::bidirectional_relay;

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
async fn run_relay_loop(mut inbound: AnytlsInbound) {
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
                tokio::spawn(async move {
                    let Ok(sock) =
                        tokio::net::UdpSocket::bind("127.0.0.1:0").await
                    else {
                        let _ = packet.close().await;
                        return;
                    };
                    let mut up_buf = vec![0u8; 65535];
                    let mut down_buf = vec![0u8; 65535];
                    loop {
                        tokio::select! {
                            r = packet.read_packet(&mut up_buf) => match r {
                                Ok((0, _)) | Err(_) => break,
                                Ok((n, dest)) => {
                                    if sock
                                        .send_to(&up_buf[..n], dest.to_string())
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
/// binds asynchronously). The probe connection dies in TLS accept; harmless.
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

async fn setup() -> AnyTlsOutboundClient {
    setup_with_padding(None).await
}

/// Like [`setup`], but with an optional inbound `padding_scheme` (raw
/// scheme text) installed on the server side.
async fn setup_with_padding(
    padding_scheme: Option<&str>,
) -> AnyTlsOutboundClient {
    let _ = env_logger::try_init();
    let tmp = std::env::temp_dir().join(format!(
        "anywhere-anytls-loopback-{}-{}",
        std::process::id(),
        free_port()
    ));
    std::fs::create_dir_all(&tmp).unwrap();
    let (cert, key) = generate_cert(&tmp);

    let listen_port = free_port();
    let padding_line = padding_scheme
        .map(|s| format!("padding_scheme = {s:?}"))
        .unwrap_or_default();
    let config: anywhere::config::Config = toml::from_str(&format!(
        r#"
[[users]]
name = "tester"
password = "hunter2"

[[inbounds]]
type = "anytls"
listen = "127.0.0.1:{listen_port}"
cert = "{cert}"
key = "{key}"
{padding_line}

[[outbounds]]
type = "anytls"
server = "127.0.0.1:{listen_port}"
password = "hunter2"
sni = "localhost"
insecure = true
tls_fragment = false
"#
    ))
    .unwrap();

    let inbound = AnytlsInbound::from_config(
        &config.inbounds[0],
        vec!["hunter2".to_string()],
    )
    .expect("anytls inbound from config");
    tokio::spawn(run_relay_loop(inbound));
    wait_listening(listen_port).await;

    let client = AnyTlsOutboundClient::from_config(vec![&config.outbounds[0]])
        .await
        .expect("anytls outbound from config");
    client
}

/// Write `payload` in 16 KB chunks (the frame limit is 64 KB; the real
/// relay uses [`anywhere::relay`] 16 KB chunks) and verify the echo.
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

#[tokio::test(flavor = "multi_thread")]
async fn tcp_streams_roundtrip() {
    let guard = tokio::time::timeout(Duration::from_secs(120), async {
        let client = setup().await;
        let client = std::sync::Arc::new(client);
        let echo_port = spawn_echo_server().await;
        let dest =
            Destination::from_str(&format!("127.0.0.1:{echo_port}")).unwrap();

        // Fresh stream per size — crosses the padding stop boundary
        // (8 TLS writes) several times, exercising the server-side
        // packet counter.
        for size in [64usize, 4096, 256 * 1024] {
            let mut relay = client.dial(&dest).await.expect("dial");
            let payload: Vec<u8> =
                (0..size).map(|i| (i * 7 % 251) as u8).collect();
            transfer_roundtrip(relay.as_mut(), payload).await;
        }

        // Concurrent streams multiplexed onto the shared session.
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
    guard.await.expect("tcp_streams_roundtrip timed out");
}

#[tokio::test(flavor = "multi_thread")]
async fn uot_udp_roundtrip() {
    let guard = tokio::time::timeout(Duration::from_secs(60), async {
        let client = setup().await;

        let echo = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let echo_port = echo.local_addr().unwrap().port();
        tokio::spawn(async move {
            let mut buf = [0u8; 65535];
            loop {
                let Ok((n, from)) = echo.recv_from(&mut buf).await else {
                    break;
                };
                let _ = echo.send_to(&buf[..n], from).await;
            }
        });

        let dest =
            Destination::from_str(&format!("127.0.0.1:{echo_port}")).unwrap();

        // dial_udp retries: same listener-startup race as TCP.
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
            let (n, got_dest) =
                relay.read_packet(&mut buf).await.expect("read_packet");
            assert!(n > 0, "empty datagram");
            assert_eq!(&buf[..n], &msg);
            assert_eq!(got_dest.port, echo_port);
        }
        let _ = relay.close().await;
    });
    guard.await.expect("uot_udp_roundtrip timed out");
}

/// A server with a custom `padding_scheme` must push its raw scheme text to
/// a client that starts on the default scheme (CMD_UPDATE_PADDING_SCHEME,
/// sing-anytls session.go:271-283); the outbound applies it to its
/// process-wide padding cache, and relayed traffic round-trips under the
/// new scheme.
#[tokio::test(flavor = "multi_thread")]
async fn custom_padding_scheme_pushed_to_client() {
    let guard = tokio::time::timeout(Duration::from_secs(120), async {
        let scheme = "stop=4\n0=30-30\n1=50-80\n";
        let client =
            std::sync::Arc::new(setup_with_padding(Some(scheme)).await);
        let echo_port = spawn_echo_server().await;
        let dest =
            Destination::from_str(&format!("127.0.0.1:{echo_port}")).unwrap();

        // The outbound starts on the default scheme and reports its md5 in
        // the settings frame. That frame only goes out with the FIRST dial
        // (packet #1 = settings + SYN+PSH combined write), so the update
        // poll runs after the first dial below.
        let expected_md5 = anywhere::protocol::anytls::PaddingFactory::md5_hex(
            scheme.as_bytes(),
        );
        // Fresh stream per size; the server answers the md5 mismatch with a
        // scheme update, which the outbound stores in its process-wide
        // padding cache. Traffic then relays under the pushed scheme.
        for (i, size) in [64usize, 128 * 1024].into_iter().enumerate() {
            let mut relay = client.dial(&dest).await.expect("dial");
            if i == 0 {
                let mut updated = false;
                for _ in 0..100 {
                    if client.cached_padding_md5() == expected_md5 {
                        updated = true;
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
                assert!(
                    updated,
                    "outbound never applied the server's padding scheme update"
                );
            }
            let payload: Vec<u8> =
                (0..size).map(|i| (i * 7 % 251) as u8).collect();
            transfer_roundtrip(relay.as_mut(), payload).await;
        }
    });
    guard.await.expect("custom_padding_scheme_pushed_to_client timed out");
}
