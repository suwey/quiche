use std::fmt;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::str::FromStr;

use async_trait::async_trait;

use crate::relay::PacketRelay;
use crate::relay::StreamRelay;

pub mod anytls;
pub mod quic;
pub mod socks5;
pub mod tun;

// ---------------------------------------------------------------------------
// Address / Destination / Network
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Address {
    Domain(String),
    Ipv4([u8; 4]),
    Ipv6([u8; 16]),
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Address::Domain(d) => f.write_str(d),
            Address::Ipv4(o) => write!(f, "{}", Ipv4Addr::from(*o)),
            Address::Ipv6(o) => write!(f, "{}", Ipv6Addr::from(*o)),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Destination {
    pub address: Address,
    pub port: u16,
    /// When `address` is a domain resolved from an IP (via reverse cache),
    /// this holds the original IP so outbound `dial()` can connect directly
    /// without a blocking DNS resolution.
    pub resolved_ip: Option<std::net::IpAddr>,
}

impl Destination {
    pub fn new(address: Address, port: u16) -> Self {
        Self {
            address,
            port,
            resolved_ip: None,
        }
    }

    pub fn with_resolved(
        address: Address, port: u16, ip: std::net::IpAddr,
    ) -> Self {
        Self {
            address,
            port,
            resolved_ip: Some(ip),
        }
    }
}

impl fmt::Display for Destination {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.address {
            Address::Ipv6(o) => {
                write!(f, "[{}]:{}", Ipv6Addr::from(*o), self.port)
            },
            _ => write!(f, "{}:{}", self.address, self.port),
        }
    }
}

impl FromStr for Destination {
    type Err = String;

    /// Parses "host:port", "[ipv6]:port", "ipv4:port", or "domain:port".
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (host, port_str) = if let Some(rest) = s.strip_prefix('[') {
            let (h, rest) = rest
                .split_once(']')
                .ok_or_else(|| format!("unclosed bracket: {s}"))?;
            let p = rest
                .strip_prefix(':')
                .ok_or_else(|| format!("missing port: {s}"))?;
            (h, p)
        } else {
            s.rsplit_once(':')
                .ok_or_else(|| format!("missing port: {s}"))?
        };

        let port: u16 = port_str
            .parse()
            .map_err(|_| format!("invalid port: {port_str}"))?;

        let address = if let Ok(ip) = host.parse::<Ipv4Addr>() {
            Address::Ipv4(ip.octets())
        } else if let Ok(ip) = host.parse::<Ipv6Addr>() {
            Address::Ipv6(ip.octets())
        } else {
            if host.is_empty() {
                return Err(format!("empty host: {s}"));
            }
            Address::Domain(host.to_string())
        };

        Ok(Destination::new(address, port))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Network {
    Tcp,
    Udp,
}

impl fmt::Display for Network {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Network::Tcp => f.write_str("tcp"),
            Network::Udp => f.write_str("udp"),
        }
    }
}

// ---------------------------------------------------------------------------
// InboundConn
// ---------------------------------------------------------------------------

pub enum InboundConn {
    Tcp {
        destination: Destination,
        stream: Box<dyn StreamRelay>,
        source: std::net::SocketAddr,
        type_: String,
        /// Whether to sniff TLS SNI / HTTP Host from the stream before
        /// rule matching. Only true for TUN inbounds.
        sniff: bool,
    },
    Udp {
        initial_destination: Destination,
        packet: Box<dyn PacketRelay>,
        source: std::net::SocketAddr,
        type_: String,
    },
}

impl InboundConn {
    pub fn destination(&self) -> &Destination {
        match self {
            InboundConn::Tcp { destination, .. } => destination,
            InboundConn::Udp {
                initial_destination,
                ..
            } => initial_destination,
        }
    }

    pub fn network(&self) -> Network {
        match self {
            InboundConn::Tcp { .. } => Network::Tcp,
            InboundConn::Udp { .. } => Network::Udp,
        }
    }

    pub fn source(&self) -> &std::net::SocketAddr {
        match self {
            InboundConn::Tcp { source, .. } => source,
            InboundConn::Udp { source, .. } => source,
        }
    }

    pub fn type_name(&self) -> &str {
        match self {
            InboundConn::Tcp { type_, .. } => type_,
            InboundConn::Udp { type_, .. } => type_,
        }
    }

    /// Returns true if this connection should be sniffed (TUN TCP).
    pub fn should_sniff(&self) -> bool {
        match self {
            InboundConn::Tcp { sniff, .. } => *sniff,
            _ => false,
        }
    }
}

#[async_trait]
pub trait Inbound: Send {
    /// Accept a new connection. Returns None when shut down.
    async fn accept(&mut self) -> Option<InboundConn>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ipv4() {
        let d: Destination = "127.0.0.1:443".parse().unwrap();
        assert_eq!(d.address, Address::Ipv4([127, 0, 0, 1]));
        assert_eq!(d.port, 443);
        assert_eq!(d.to_string(), "127.0.0.1:443");
    }

    #[test]
    fn parse_ipv6_bracketed() {
        let d: Destination = "[::1]:80".parse().unwrap();
        assert_eq!(
            d.address,
            Address::Ipv6(std::net::Ipv6Addr::LOCALHOST.octets())
        );
        assert_eq!(d.port, 80);
        assert_eq!(d.to_string(), "[::1]:80");
    }

    #[test]
    fn parse_domain() {
        let d: Destination = "example.com:443".parse().unwrap();
        assert_eq!(d.address, Address::Domain("example.com".into()));
        assert_eq!(d.port, 443);
        assert_eq!(d.to_string(), "example.com:443");
    }

    #[test]
    fn parse_invalid_port() {
        assert!("example.com:abc".parse::<Destination>().is_err());
    }

    #[test]
    fn parse_missing_port() {
        assert!("example.com".parse::<Destination>().is_err());
    }
}
