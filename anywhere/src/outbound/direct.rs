use std::io;
use std::net::ToSocketAddrs;
use std::time::Duration;

use async_trait::async_trait;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio::net::UdpSocket;
use tokio::time::Instant;
#[allow(unused)]
use tokio::time::timeout;
use tokio::time::timeout_at;

use crate::inbound::Address;
use crate::inbound::Destination;
use crate::obfuscation::fragment::AsyncFragmentStream;
use crate::outbound::OutboundClient;
use crate::outbound::common::bind_udp_bypass;
use crate::outbound::common::connect_tcp_bypass;
use crate::relay::PacketRelay;
use crate::relay::StreamRelay;
use crate::relay::TcpRelay;
use crate::tlsfragment::FragmentConfig;

const DIRECT_UDP_IDLE_TIMEOUT: Duration = Duration::from_secs(60);

pub struct DirectOutboundClient {
    /// TLS ClientHello fragmentation config (from `[common].tls_fragment`).
    /// When enabled, the first write to each direct TCP connection is
    /// inspected; if it is a TLS ClientHello, it is split into multiple
    /// segments with delays to evade DPI SNI matching.
    tls_fragment: Option<FragmentConfig>,
}

impl Default for DirectOutboundClient {
    fn default() -> Self {
        Self { tls_fragment: None }
    }
}

impl DirectOutboundClient {
    pub fn new(tls_fragment: Option<FragmentConfig>) -> Self {
        Self { tls_fragment }
    }
}

/// TCP relay with TLS ClientHello fragmentation on the first write.
///
/// Wraps [`AsyncFragmentStream`] around a tokio `TcpStream`. The fragment
/// stream inspects the first write; if it detects a TLS ClientHello it splits
/// it into multiple segments, otherwise all I/O passes through unchanged.
struct FragmentTcpRelay(AsyncFragmentStream<tokio::net::TcpStream>);

#[async_trait]
impl StreamRelay for FragmentTcpRelay {
    async fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf).await
    }

    async fn write(&mut self, buf: &[u8]) -> io::Result<()> {
        self.0.write_all(buf).await
    }

    async fn shutdown(&mut self) -> io::Result<()> {
        self.0.shutdown().await
    }

    async fn reset(&mut self) {
        // Set SO_LINGER with timeout 0 so close() sends RST instead of FIN.
        use socket2::SockRef;
        let sock_ref = SockRef::from(self.0.get_ref());
        let _ = sock_ref.set_linger(Some(Duration::ZERO));
        let _ = self.0.shutdown().await;
    }
}

struct DirectUdpRelay {
    socket: UdpSocket,
    peer: Destination,
    last_activity: Instant,
    idle_timeout: Duration,
}

impl DirectUdpRelay {
    fn new(socket: UdpSocket, peer: Destination, idle_timeout: Duration) -> Self {
        let now = Instant::now();
        Self {
            socket,
            peer,
            last_activity: now,
            idle_timeout,
        }
    }

    fn next_deadline(&self) -> Instant {
        self.last_activity + self.idle_timeout
    }
}

#[async_trait]
impl PacketRelay for DirectUdpRelay {
    async fn read_packet(
        &mut self, buf: &mut [u8],
    ) -> io::Result<(usize, Destination)> {
        // connect()'ed socket: kernel only delivers packets from the peer.
        match timeout_at(self.next_deadline(), self.socket.recv(buf)).await {
            Ok(Ok(n)) => {
                self.last_activity = Instant::now();
                Ok((n, self.peer.clone()))
            },
            Ok(Err(e)) => Err(e),
            Err(_) => Ok((0, Destination::new(Address::Ipv4([0, 0, 0, 0]), 0))),
        }
    }

    async fn write_packet(
        &mut self, buf: &[u8], _dest: &Destination,
    ) -> io::Result<()> {
        // connect()'ed socket: send() always goes to the fixed peer.
        self.socket.send(buf).await?;
        self.last_activity = Instant::now();
        Ok(())
    }

    async fn close(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Resolve a "host:port" string into a [`SocketAddr`], trying DNS lookup when
/// the host is a domain name (rather than a raw IP).
fn resolve_addr(hostport: &str) -> std::io::Result<std::net::SocketAddr> {
    hostport.parse().or_else(|_| {
        hostport.to_socket_addrs()?.next().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "no address resolved",
            )
        })
    })
}

#[async_trait]
impl OutboundClient for DirectOutboundClient {
    async fn dial(
        &self, dest: &Destination,
    ) -> Result<Box<dyn StreamRelay>, Box<dyn std::error::Error>> {
        let addr = if let Some(ip) = dest.resolved_ip {
            std::net::SocketAddr::new(ip, dest.port)
        } else {
            match &dest.address {
                Address::Ipv4(o) => std::net::SocketAddr::new(
                    std::net::IpAddr::V4(std::net::Ipv4Addr::from(*o)),
                    dest.port,
                ),
                Address::Ipv6(o) => std::net::SocketAddr::new(
                    std::net::IpAddr::V6(std::net::Ipv6Addr::from(*o)),
                    dest.port,
                ),
                Address::Domain(_) => {
                    let s = dest.to_string();
                    tokio::task::spawn_blocking(move || resolve_addr(&s))
                        .await
                        .map_err(|e| {
                            Box::<dyn std::error::Error>::from(format!(
                                "spawn_blocking join error: {e}"
                            ))
                        })??
                },
            }
        };
        let stream = connect_tcp_bypass(addr).await?;
        log::info!("direct outbound connected to {addr}");
        if let Some(ref config) = self.tls_fragment {
            let frag_stream = AsyncFragmentStream::new(stream, Some(config));
            Ok(Box::new(FragmentTcpRelay(frag_stream)))
        } else {
            Ok(Box::new(TcpRelay::new(stream)))
        }
    }

    async fn dial_udp(
        &self, initial_dest: &Destination,
    ) -> Result<Box<dyn PacketRelay>, Box<dyn std::error::Error>> {
        let bind_addr: std::net::SocketAddr = "0.0.0.0:0".parse().unwrap();
        let socket = bind_udp_bypass(bind_addr).await?;
        // connect() the socket to the target so the kernel only accepts
        // packets from that peer — prevents UDP reflection attacks.
        let peer_addr: std::net::SocketAddr =
            if let Some(ip) = initial_dest.resolved_ip {
                std::net::SocketAddr::new(ip, initial_dest.port)
            } else {
                match &initial_dest.address {
                    Address::Ipv4(o) => std::net::SocketAddr::new(
                        std::net::IpAddr::V4(std::net::Ipv4Addr::from(*o)),
                        initial_dest.port,
                    ),
                    Address::Ipv6(o) => std::net::SocketAddr::new(
                        std::net::IpAddr::V6(std::net::Ipv6Addr::from(*o)),
                        initial_dest.port,
                    ),
                    Address::Domain(_) => {
                        let s = initial_dest.to_string();
                        tokio::task::spawn_blocking(move || resolve_addr(&s))
                            .await
                            .map_err(|e| {
                                Box::<dyn std::error::Error>::from(format!(
                                    "spawn_blocking join error: {e}"
                                ))
                            })??
                    },
                }
            };
        socket.connect(peer_addr).await?;
        log::debug!("direct udp connected to {peer_addr}");
        Ok(Box::new(DirectUdpRelay::new(
            socket,
            initial_dest.clone(),
            DIRECT_UDP_IDLE_TIMEOUT,
        )))
    }

    async fn test_latency(&self, _url: &str) -> Option<u64> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inbound::Address;
    use tokio::time::sleep;

    #[tokio::test]
    async fn direct_udp_read_exits_after_idle_timeout() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer = Destination::new(Address::Ipv4([127, 0, 0, 1]), 0);
        let mut relay =
            DirectUdpRelay::new(socket, peer, Duration::from_millis(10));
        let mut buf = [0; 64];

        let (n, _) = relay.read_packet(&mut buf).await.unwrap();

        assert_eq!(n, 0);
    }

    #[tokio::test]
    async fn direct_udp_write_refreshes_idle_deadline() {
        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let dest = Destination::new(
            Address::Ipv4(
                receiver
                    .local_addr()
                    .unwrap()
                    .ip()
                    .to_string()
                    .parse::<std::net::Ipv4Addr>()
                    .unwrap()
                    .octets(),
            ),
            receiver.local_addr().unwrap().port(),
        );
        socket
            .connect(receiver.local_addr().unwrap())
            .await
            .unwrap();
        let mut relay =
            DirectUdpRelay::new(socket, dest.clone(), Duration::from_millis(40));

        sleep(Duration::from_millis(25)).await;
        relay.write_packet(b"ping", &dest).await.unwrap();
        sleep(Duration::from_millis(25)).await;
        let mut buf = [0; 64];
        let result =
            timeout(Duration::from_millis(5), relay.read_packet(&mut buf)).await;

        assert!(result.is_err());
    }
}
