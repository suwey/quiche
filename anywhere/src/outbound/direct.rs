use std::io;
use std::net::ToSocketAddrs;
use std::time::Duration;

use async_trait::async_trait;
use tokio::net::UdpSocket;
use tokio::time::Instant;
use tokio::time::timeout;
use tokio::time::timeout_at;

use crate::inbound::Address;
use crate::inbound::Destination;
use crate::outbound::OutboundClient;
use crate::outbound::common::bind_udp_bypass;
use crate::outbound::common::connect_tcp_bypass;
use crate::relay::PacketRelay;
use crate::relay::StreamRelay;
use crate::relay::TcpRelay;

const DIRECT_UDP_IDLE_TIMEOUT: Duration = Duration::from_secs(60);

pub struct DirectOutboundClient;

struct DirectUdpRelay {
    socket: UdpSocket,
    last_activity: Instant,
    idle_timeout: Duration,
}

impl DirectUdpRelay {
    fn new(socket: UdpSocket, idle_timeout: Duration) -> Self {
        let now = Instant::now();
        Self {
            socket,
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
        match timeout_at(self.next_deadline(), self.socket.recv_from(buf)).await {
            Ok(Ok((n, addr))) => {
                self.last_activity = Instant::now();
                let dest: Destination =
                    addr.to_string().parse().map_err(|_| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            "invalid UDP source address",
                        )
                    })?;
                Ok((n, dest))
            },
            Ok(Err(e)) => Err(e),
            Err(_) => Ok((0, Destination::new(Address::Ipv4([0, 0, 0, 0]), 0))),
        }
    }

    async fn write_packet(
        &mut self, buf: &[u8], dest: &Destination,
    ) -> io::Result<()> {
        let addr: std::net::SocketAddr =
            dest.to_string().parse().map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "invalid destination address",
                )
            })?;
        self.socket.send_to(buf, addr).await?;
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
                Address::Domain(_) => resolve_addr(&dest.to_string())?,
            }
        };
        let stream = connect_tcp_bypass(addr).await?;
        log::info!("direct outbound connected to {addr}");
        Ok(Box::new(TcpRelay::new(stream)))
    }

    async fn dial_udp(
        &self, _initial_dest: &Destination,
    ) -> Result<Box<dyn PacketRelay>, Box<dyn std::error::Error>> {
        let bind_addr: std::net::SocketAddr = "0.0.0.0:0".parse().unwrap();
        let socket = bind_udp_bypass(bind_addr).await?;
        log::info!("direct udp outbound ready");
        Ok(Box::new(DirectUdpRelay::new(
            socket,
            DIRECT_UDP_IDLE_TIMEOUT,
        )))
    }

    async fn test_latency(&self, host: &str, port: u16) -> Option<u64> {
        let std_addr = resolve_addr(&format!("{host}:{port}")).ok()?;
        let start = Instant::now();
        match timeout(
            std::time::Duration::from_secs(5),
            connect_tcp_bypass(std_addr),
        )
        .await
        {
            Ok(Ok(stream)) => {
                let elapsed = start.elapsed().as_millis() as u64;
                let _ = stream
                    .into_std()
                    .map(|s| s.shutdown(std::net::Shutdown::Both));
                Some(elapsed)
            },
            _ => None,
        }
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
        let mut relay = DirectUdpRelay::new(socket, Duration::from_millis(10));
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
        let mut relay = DirectUdpRelay::new(socket, Duration::from_millis(40));

        sleep(Duration::from_millis(25)).await;
        relay.write_packet(b"ping", &dest).await.unwrap();
        sleep(Duration::from_millis(25)).await;
        let mut buf = [0; 64];
        let result =
            timeout(Duration::from_millis(5), relay.read_packet(&mut buf)).await;

        assert!(result.is_err());
    }
}
