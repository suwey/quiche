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

pub mod vless;
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
        Err("UDP not supported by this outbound".into())
    }

    /// Measure round-trip latency to `host:port` by creating a fresh connection
    /// and immediately tearing it down.
    ///
    /// Returns `None` on failure (timeout, unreachable, etc.).
    /// Default returns `None` — implementations override on demand.
    async fn test_latency(&self, _host: &str, _port: u16) -> Option<u64> {
        None
    }
}
