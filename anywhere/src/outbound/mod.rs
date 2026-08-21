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
pub mod vless;
pub mod shadowsocks;
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

    /// Measure real proxy latency by dialing `host:port` through this outbound
    /// and measuring connection establishment time.
    ///
    /// Returns `None` on failure (timeout, unreachable, etc.).
    /// Override to return `None` for outbounds that should not participate in
    /// latency testing (direct, quic, ssh).
    async fn test_latency(&self, host: &str, port: u16) -> Option<u64> {
        let dest: Destination = format!("{host}:{port}").parse().ok()?;
        let start = std::time::Instant::now();
        self.dial(&dest).await.ok()?;
        Some(start.elapsed().as_millis() as u64)
    }
}
