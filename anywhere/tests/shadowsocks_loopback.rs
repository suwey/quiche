// SPDX-License-Identifier: BSD-2-Clause
// Copyright © The anywhere project contributors.

//! End-to-end loopback test: shadowsocks (2022) outbound → inbound → echo.
//!
//! Boots a real [`ShadowsocksInbound`] (TCP 握手 + UDP 会话分发) and drives it
//! with a real [`ShadowsocksOutboundClient`], covering all three 2022 methods,
//! the early-data split, top-level `[[users]]` credential sharing (含非 PSK
//! 密码跳过与逐 PSK 多用户识别) and wrong-PSK rejection.

use std::str::FromStr;
use std::time::Duration;

use anywhere::config::Config;
use anywhere::inbound::Destination;
use anywhere::inbound::Inbound;
use anywhere::inbound::InboundConn;
use anywhere::inbound::shadowsocks::ShadowsocksInbound;
use anywhere::outbound::OutboundClient;
use anywhere::outbound::shadowsocks::ShadowsocksOutboundClient;
use anywhere::relay::StreamRelay;
use anywhere::relay::TcpRelay;
use anywhere::relay::UdpRelay;
use anywhere::relay::bidirectional_packet_relay;
use anywhere::relay::bidirectional_relay;

fn b64(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(data)
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

/// Echo UDP server: reply each datagram from where it came.
async fn spawn_udp_echo_server() -> u16 {
    let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = sock.local_addr().unwrap().port();
    tokio::spawn(async move {
        let mut buf = [0u8; 65535];
        loop {
            let Ok((n, from)) = sock.recv_from(&mut buf).await else {
                break;
            };
            let _ = sock.send_to(&buf[..n], from).await;
        }
    });
    port
}

/// Minimal proxy loop: accept `InboundConn`s and dial a plain TCP/UDP
/// upstream, mirroring what the runner's relay loop does.
async fn run_relay_loop(mut inbound: ShadowsocksInbound) {
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
                    // 不 connect：UdpRelay 走 send_to（已连接 socket 上
                    // send_to 会报 EISCONN）。
                    let _ = &initial_destination;
                    let mut up = UdpRelay::new(sock);
                    bidirectional_packet_relay(
                        &mut *packet,
                        &mut up,
                        Duration::from_secs(10),
                    )
                    .await;
                });
            },
        }
    }
}

/// Block until something accepts on `port` (the inbound's listener task
/// binds asynchronously). The probe connection dies in the SS handshake;
/// harmless.
async fn wait_listening(port: u16) {
    for _ in 0..100 {
        if tokio::net::TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("listener on {port} never came up");
}

/// Boot an SS2022 inbound + outbound pair. 用户凭据走顶层 `[[users]]`
/// （`users_toml` 为其原始 TOML 片段，可含非 PSK 密码）；`client_password`
/// 是 outbound 侧使用的单个 PSK。
async fn setup(
    method: &str, users_toml: &str, client_password: &str,
) -> ShadowsocksOutboundClient {
    let _ = env_logger::try_init();
    let listen_port = free_port();
    let config: Config = toml::from_str(&format!(
        r#"
{users_toml}
[[inbounds]]
type = "shadowsocks"
listen = "127.0.0.1:{listen_port}"
method = "{method}"

[[outbounds]]
type = "shadowsocks"
server = "127.0.0.1:{listen_port}"
method = "{method}"
password = "{client_password}"
"#
    ))
    .expect("parse loopback config");

    let inbound = ShadowsocksInbound::from_config(
        &config.inbounds[0],
        config.passwords(),
    )
    .expect("ss inbound");
    tokio::spawn(run_relay_loop(inbound));
    wait_listening(listen_port).await;

    ShadowsocksOutboundClient::from_config(&config.outbounds[0])
        .await
        .expect("ss outbound")
}

async fn tcp_roundtrip(relay: &mut dyn StreamRelay, payload: Vec<u8>) {
    let expected = payload.len();
    relay.write(&payload).await.expect("write");
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
async fn tcp_roundtrip_all_methods() {
    let guard = tokio::time::timeout(Duration::from_secs(120), async {
        let echo_port = spawn_echo_server().await;
        let dest =
            Destination::from_str(&format!("127.0.0.1:{echo_port}")).unwrap();

        for (method, ksl) in [
            ("2022-blake3-aes-128-gcm", 16usize),
            ("2022-blake3-aes-256-gcm", 32usize),
            ("2022-blake3-chacha20-poly1305", 32usize),
        ] {
            let psk = b64(&vec![0x42u8; ksl]);
            let users_toml = format!(
                "[[users]]\nname = \"alice\"\npassword = \"{psk}\"\n"
            );
            let client = setup(method, &users_toml, &psk).await;
            // 64B：单块；40KB：超过请求缓冲 → early data + 数据分块。
            for size in [64usize, 40 * 1024] {
                let mut relay = client.dial(&dest).await.expect("dial");
                let payload: Vec<u8> =
                    (0..size).map(|i| (i * 7 % 251) as u8).collect();
                tcp_roundtrip(relay.as_mut(), payload).await;
            }
        }
    });
    guard.await.expect("tcp_roundtrip_all_methods timed out");
}

#[tokio::test(flavor = "multi_thread")]
async fn udp_roundtrip() {
    let guard = tokio::time::timeout(Duration::from_secs(60), async {
        let echo_port = spawn_udp_echo_server().await;
        let dest =
            Destination::from_str(&format!("127.0.0.1:{echo_port}")).unwrap();

        for (method, ksl) in [
            ("2022-blake3-aes-256-gcm", 32usize),
            ("2022-blake3-chacha20-poly1305", 32usize),
        ] {
            let psk = b64(&vec![0x77u8; ksl]);
            let users_toml = format!(
                "[[users]]\nname = \"alice\"\npassword = \"{psk}\"\n"
            );
            let client = setup(method, &users_toml, &psk).await;

            // UDP dispatcher 异步绑定，重试 dial_udp。
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
        }
    });
    guard.await.expect("udp_roundtrip timed out");
}

/// 与 outbound 同构的多段 password：用户条目 "iPSK:用户PSK"，客户端
/// password 填同样的串（EIH 链识别 + 末段会话密钥）。
#[tokio::test(flavor = "multi_thread")]
async fn multi_segment_password_works() {
    let guard = tokio::time::timeout(Duration::from_secs(60), async {
        let echo_port = spawn_echo_server().await;
        let dest =
            Destination::from_str(&format!("127.0.0.1:{echo_port}")).unwrap();

        let password =
            format!("{}:{}", b64(&vec![0x11u8; 32]), b64(&vec![0x22u8; 32]));
        let users_toml = format!(
            "[[users]]\nname = \"bob\"\npassword = \"{password}\"\n"
        );
        let client =
            setup("2022-blake3-aes-256-gcm", &users_toml, &password).await;

        let mut relay = client.dial(&dest).await.expect("dial");
        let payload: Vec<u8> = (0..64 * 1024u32).map(|i| (i % 251) as u8).collect();
        tcp_roundtrip(relay.as_mut(), payload).await;

        // UDP 同样按末段 PSK 会话往返。
        let udp_port = spawn_udp_echo_server().await;
        let udp_dest =
            Destination::from_str(&format!("127.0.0.1:{udp_port}")).unwrap();
        let mut relay = None;
        for _ in 0..50 {
            match client.dial_udp(&udp_dest).await {
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
        let msg = b"multi-segment udp datagram";
        relay.write_packet(msg, &udp_dest).await.expect("write_packet");
        let mut buf = vec![0u8; 4096];
        let (n, got_dest) =
            relay.read_packet(&mut buf).await.expect("read_packet");
        assert_eq!(&buf[..n], msg);
        assert_eq!(got_dest.port, udp_port);
    });
    guard.await.expect("multi_segment_password_works timed out");
}

/// 与其他 inbound 共用顶层 users：非 PSK 密码被跳过，PSK 用户不受影响。
#[tokio::test(flavor = "multi_thread")]
async fn mixed_users_skip_non_psk_passwords() {
    let guard = tokio::time::timeout(Duration::from_secs(60), async {
        let echo_port = spawn_echo_server().await;
        let dest =
            Destination::from_str(&format!("127.0.0.1:{echo_port}")).unwrap();

        let psk = b64(&vec![0x33u8; 32]);
        let users_toml = format!(
            "[[users]]\nname = \"anytls-user\"\npassword = \"hunter2\"\n\
             [[users]]\nname = \"ss-user\"\npassword = \"{psk}\"\n"
        );
        let client =
            setup("2022-blake3-aes-256-gcm", &users_toml, &psk).await;

        let mut relay = client.dial(&dest).await.expect("dial");
        let payload: Vec<u8> = (0..16 * 1024u32).map(|i| (i % 251) as u8).collect();
        tcp_roundtrip(relay.as_mut(), payload).await;
    });
    guard.await.expect("mixed_users_skip_non_psk_passwords timed out");
}

/// 错误 PSK：客户端握手写出后，服务端拒绝并关闭，客户端首读失败。
#[tokio::test(flavor = "multi_thread")]
async fn wrong_psk_rejected() {
    let guard = tokio::time::timeout(Duration::from_secs(60), async {
        let echo_port = spawn_echo_server().await;
        let dest =
            Destination::from_str(&format!("127.0.0.1:{echo_port}")).unwrap();

        let server_psk = b64(&vec![0x42u8; 32]);
        let wrong_psk = b64(&vec![0x00u8; 32]);
        let users_toml = format!(
            "[[users]]\nname = \"alice\"\npassword = \"{server_psk}\"\n"
        );
        let client =
            setup("2022-blake3-aes-256-gcm", &users_toml, &wrong_psk).await;

        let mut relay = client.dial(&dest).await.expect("dial");
        relay.write(b"hello").await.expect("handshake write");
        let mut buf = vec![0u8; 128];
        assert!(
            relay.read(&mut buf).await.is_err(),
            "read must fail: server rejected the wrong PSK"
        );
    });
    guard.await.expect("wrong_psk_rejected timed out");
}

/// 顶层 users 里一个可用 PSK 都没有 → inbound 不启动。
#[tokio::test]
async fn no_valid_psk_inbound_not_started() {
    let config: Config = toml::from_str(
        r#"
[[users]]
name = "anytls-user"
password = "hunter2"

[[inbounds]]
type = "shadowsocks"
listen = "127.0.0.1:18388"
method = "2022-blake3-aes-256-gcm"
"#,
    )
    .unwrap();
    assert!(
        ShadowsocksInbound::from_config(&config.inbounds[0], config.passwords())
            .is_none(),
        "no usable PSK must prevent startup"
    );
}
