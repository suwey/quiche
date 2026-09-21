// SPDX-License-Identifier: BSD-2-Clause
// Copyright © The anywhere project contributors.

//! Network smoke test: REALITY ServerHello borrowing against a real target
//! site (cloudflare.com:8443 — 本机网络在 443 端口上有拒绝 TLS 1.3 的中间盒,
//! 8443 不受影响). Requires outbound network access; not part of the
//! default offline suite.

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
use anywhere::transport::reality_server;
use anywhere::transport::reality_server::public_key_from_private;
use base64::Engine;

const TARGET: &str = "cloudflare.com:8443";
const SNI: &str = "cloudflare.com";
const TEST_UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";

#[tokio::test(flavor = "multi_thread")]
async fn borrow_from_real_site() {
    let _ = env_logger::try_init();
    let guard = tokio::time::timeout(Duration::from_secs(60), async {
        let private_key: [u8; 32] = std::array::from_fn(|i| (i * 7 + 3) as u8);
        let public_key = public_key_from_private(&private_key);
        let public_key_b64 =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(public_key);
        let psk_b64 =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(private_key);

        let listen_port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let echo_port = spawn_echo().await;
        let config: anywhere::config::Config = toml::from_str(&format!(
            r#"
[[users]]
name = "tester"
password = "{TEST_UUID}"

[[inbounds]]
type = "vless"
listen = "127.0.0.1:{listen_port}"

[inbounds.reality]
dest = "{TARGET}"
server_names = ["{SNI}"]
private_key = "{psk_b64}"
short_ids = [""]

[[outbounds]]
type = "vless"
server = "127.0.0.1:{listen_port}"
password = "{TEST_UUID}"
sni = "{SNI}"
flow = "xtls-rprx-vision"
tls_fragment = false

[outbounds.reality]
public_key = "{public_key_b64}"
short_id = ""
"#
        ))
        .unwrap();

        let inbound = VlessInbound::from_config(
            &config.inbounds[0],
            config.passwords(),
        )
        .expect("reality inbound");
        tokio::spawn(async move {
            let mut inbound = inbound;
            while let Some(conn) = inbound.accept().await {
                if let InboundConn::Tcp {
                    destination,
                    mut stream,
                    ..
                } = conn
                {
                    tokio::spawn(async move {
                        match tokio::net::TcpStream::connect(
                            destination.to_string(),
                        )
                        .await
                        {
                            Ok(up) => {
                                let mut up = TcpRelay::new(up);
                                bidirectional_relay(&mut *stream, &mut up)
                                    .await;
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
        });

        let client = VlessOutboundClient::from_config(vec![&config.outbounds[0]])
            .await
            .expect("reality outbound");

        // 回环：client → reality 隧道 → 本地 echo。
        let dest =
            Destination::from_str(&format!("127.0.0.1:{echo_port}")).unwrap();
        let mut relay = client.dial(&dest).await.expect("dial");
        let payload: Vec<u8> =
            (0..16 * 1024u32).map(|i| (i % 251) as u8).collect();
        relay.write(&payload).await.expect("write");
        let mut received = vec![0u8; payload.len()];
        let mut got = 0usize;
        while got < received.len() {
            let n = relay.read(&mut received[got..]).await.expect("read echo");
            assert!(n > 0);
            got += n;
        }
        assert_eq!(received, payload);
        relay.shutdown().await.unwrap();

        let cipher = reality_server::LAST_APPLIED_BORROW.load(
            std::sync::atomic::Ordering::Relaxed,
        );
        assert_ne!(
            cipher, 0,
            "baidu's ServerHello suite must have been borrowed"
        );
        log::info!("borrowed from {TARGET}: cipher suite {cipher:#06x}");
    });
    guard.await.expect("baidu smoke timed out");
}

async fn spawn_echo() -> u16 {
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
