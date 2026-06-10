//! TUN device I/O handler loop.
//!
//! Reads raw IP packets from the TUN device, classifies them as TCP or UDP,
//! applies NAT (forward path) or un-NAT (reverse path) for TCP, and
//! dispatches UDP connections through the channel.
//!
//! UDP flows are tracked by 5-tuple so multiple datagrams (QUIC, DNS, etc.)
//! reuse the same outbound relay.

use std::collections::HashMap;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

use async_trait::async_trait;
use tokio::sync::Mutex;
use tokio::sync::mpsc;
use tun::AsyncDevice;

use crate::dns::DnsHijack;
use crate::inbound::Address;
use crate::inbound::Destination;
use crate::inbound::InboundConn;
use crate::inbound::tun::nat::TCPNat;
use crate::inbound::tun::packet::IpPacket;
use crate::inbound::tun::packet::IpPacketMeta;
use crate::inbound::tun::packet::{
    self,
};
use crate::inbound::tun::reverse_dns::ReverseDnsCache;
use crate::relay::PacketRelay;

const UDP_SESSION_TIMEOUT: Duration = Duration::from_secs(30);
const UDP_SESSION_CLEANUP_INTERVAL: Duration = Duration::from_secs(30);
const TUN_BACKPRESSURE_MAX: Duration = Duration::from_secs(1);
const TUN_BACKPRESSURE_STEP: Duration = Duration::from_millis(10);

// =========================================================================
// UDP Session Table
// =========================================================================

/// Key for the UDP session table: (src_ip, dst_ip, dst_port).
///
/// src_port is intentionally excluded so that QUIC connections (which
/// rotate source ports per packet) reuse the same relay + outbound
/// socket instead of creating a new one for every packet. The relay
/// updates resp_dst_port on each subsequent packet so responses are
/// delivered to the correct source port.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct UdpSessionKey {
    src_ip: IpAddr,
    dst_ip: IpAddr,
    dst_port: u16,
}

impl UdpSessionKey {
    fn from_meta(meta: &IpPacketMeta) -> Self {
        Self {
            src_ip: meta.src_ip,
            dst_ip: meta.dst_ip,
            dst_port: meta.dst_port,
        }
    }
}

struct UdpSession {
    /// Sender for forwarding subsequent datagrams to the relay task.
    /// Payload is (data, latest_client_port) so the relay can update its
    /// response destination port when QUIC rotates source ports.
    tx: mpsc::Sender<(Vec<u8>, u16)>,
    /// Last activity timestamp (for idle timeout).
    last_activity: Instant,
}

/// Table of active UDP sessions keyed by 5-tuple.
struct UdpSessionTable {
    sessions: HashMap<UdpSessionKey, UdpSession>,
    timeout: Duration,
}

impl UdpSessionTable {
    fn new(timeout: Duration) -> Self {
        Self {
            sessions: HashMap::new(),
            timeout,
        }
    }

    /// Remove all expired sessions. Returns the number of expired sessions
    /// removed (for logging).
    fn cleanup(&mut self) -> usize {
        let now = Instant::now();
        let timeout = self.timeout;
        let expired: Vec<UdpSessionKey> = self
            .sessions
            .iter()
            .filter(|(_, s)| now.duration_since(s.last_activity) > timeout)
            .map(|(k, _)| k.clone())
            .collect();
        let n = expired.len();
        for k in expired {
            self.sessions.remove(&k);
        }
        n
    }
}

/// Shared TUN writer for use by the handler and UDP relays.
#[derive(Clone)]
pub struct TunWriter {
    inner: Arc<AsyncDevice>,
}

impl TunWriter {
    pub fn new(device: Arc<AsyncDevice>) -> Self {
        Self { inner: device }
    }

    pub async fn write(&self, buf: &[u8]) -> std::io::Result<usize> {
        self.inner.send(buf).await
    }
}

/// Run the TUN I/O handler loop.
///
/// Reads packets from the TUN device, applies NAT/un-NAT for TCP,
/// and sends UDP connections through the channel.
/// All `tun.send()` calls go through a dedicated writer task so the
/// reader never blocks.
pub async fn run_tun_handler(
    tun: Arc<AsyncDevice>, tun_addr: IpAddr, nat: Arc<Mutex<TCPNat>>,
    listener_port: u16, conn_tx: mpsc::Sender<InboundConn>,
    dns_hijack: Option<Arc<DnsHijack>>,
    reverse_dns: Option<Arc<ReverseDnsCache>>,
) {
    let writer = TunWriter::new(tun.clone());

    // UDP session table — same 5-tuple reuses the same outbound relay.
    let mut udp_sessions = UdpSessionTable::new(UDP_SESSION_TIMEOUT);
    let mut last_cleanup = Instant::now();

    let mut buf = vec![0u8; 65535]; // Max IP packet size

    // Backpressure: when conn_tx is full (system under load / fd exhausted),
    // back off reading from TUN to let the kernel throttle retransmits
    // instead of creating a positive feedback loop.
    let mut backoff = Duration::ZERO;
    const MAX_BACKOFF: Duration = TUN_BACKPRESSURE_MAX;
    const BACKOFF_STEP: Duration = TUN_BACKPRESSURE_STEP;

    log::info!(
        "TUN handler started on {tun_addr}, listener port {listener_port}"
    );

    loop {
        // Apply backpressure sleep before reading the next packet.
        if !backoff.is_zero() {
            tokio::time::sleep(backoff).await;
        }

        let n = match tun.recv(&mut buf).await {
            Ok(n) => n,
            Err(e) => {
                log::error!("TUN read error: {e}");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            },
        };

        let Some(pkt) = packet::classify(&buf[..n]) else {
            continue;
        };

        match pkt {
            IpPacket::Tcp(meta) => {
                handle_tcp_packet(
                    &mut buf[..n],
                    &meta,
                    &tun_addr,
                    listener_port,
                    &nat,
                    &tun,
                )
                .await;
            },
            IpPacket::Udp(meta) => {
                if meta.dst_port == 53 {
                    if let Some(ref dns) = dns_hijack {
                        let l4_off = meta.l4_offset;
                        let udp_hdr_end = l4_off + 8;
                        if udp_hdr_end < meta.total_len {
                            let payload =
                                buf[udp_hdr_end..meta.total_len].to_vec();
                            let dns = dns.clone();
                            let src_ip = meta.src_ip;
                            let src_port = meta.src_port;
                            let dst_ip = meta.dst_ip;
                            let dst_port = meta.dst_port;
                            tokio::spawn(async move {
                                dns.handle_query(
                                    &payload, src_ip, src_port, dst_ip, dst_port,
                                )
                                .await;
                            });
                            continue;
                        }
                    }
                }
                let dropped = handle_udp_packet(
                    &buf[..n],
                    &meta,
                    &tun_addr,
                    &conn_tx,
                    &writer,
                    &mut udp_sessions,
                    &reverse_dns,
                )
                .await;

                // Backpressure: when packets are being dropped (channel full),
                // increase backoff to throttle the read loop. This prevents a
                // retransmit storm when the system can't keep up (e.g. fd
                // exhaustion, outbound failures).
                if dropped {
                    backoff = (backoff + BACKOFF_STEP).min(MAX_BACKOFF);
                } else {
                    // Successful dispatch — reduce backoff gradually.
                    backoff = backoff.saturating_sub(BACKOFF_STEP);
                }
            },
            IpPacket::Other => {
                // Silently drop non-TCP/UDP (ICMP, etc.)
            },
        }

        // Periodic cleanup of expired UDP sessions (every ~30s).
        if last_cleanup.elapsed() >= UDP_SESSION_CLEANUP_INTERVAL {
            let n = udp_sessions.cleanup();
            if n > 0 {
                log::debug!(
                    "UDP session table: removed {n} expired sessions, {} remaining",
                    udp_sessions.sessions.len()
                );
            }
            last_cleanup = Instant::now();
        }
    }
}

/// Handle a TCP packet: apply NAT (forward) or un-NAT (reverse).
async fn handle_tcp_packet(
    buf: &mut [u8], meta: &IpPacketMeta, tun_addr: &IpAddr, listener_port: u16,
    nat: &Arc<Mutex<TCPNat>>, tun: &AsyncDevice,
) {
    // Check if this is a reverse-path packet (kernel sending data back
    // through TUN after NAT).
    let is_reverse = match (tun_addr, meta.src_ip) {
        (IpAddr::V4(tun), IpAddr::V4(src)) =>
            tun == &src && meta.src_port == listener_port,
        (IpAddr::V6(tun), IpAddr::V6(src)) =>
            tun == &src && meta.src_port == listener_port,
        _ => false,
    };

    if is_reverse {
        // Reverse path: un-NAT and write back to TUN.
        let nat_port = meta.dst_port;
        let guard = nat.lock().await;
        if let Some(session) = guard.lookup_back(nat_port).cloned() {
            drop(guard); // Release lock before I/O

            // We need to set source = original target, dest = original client
            let IpAddr::V4(orig_target_ip) = session.target_addr.ip() else {
                return;
            };
            let IpAddr::V4(orig_client_ip) = session.client_addr.ip() else {
                return;
            };

            packet::rewrite_tcp_ipv4(
                buf,
                meta,
                orig_target_ip,
                session.target_addr.port(),
                orig_client_ip,
                session.client_addr.port(),
            );

            if let Err(e) = tun.send(&buf[..meta.total_len]).await {
                log::debug!("TUN write error (reverse TCP): {e}");
            }
        }
        return;
    }

    // Guard: if destination is the TUN address itself (and not the NAT
    // listener), this packet is a response to a local process that was
    // just written back to TUN by the reverse path. The kernel has already
    // delivered it to the local process via `iif tun0 lookup main`.
    // Processing it again would create a new NAT mapping and outbound
    // connection, causing a self-sustaining loop.
    if meta.dst_ip == *tun_addr && meta.dst_port != listener_port {
        log::error!(
            "TUN re-injection (TCP): dst={}:{} (local process response) — dropped",
            meta.dst_ip,
            meta.dst_port,
        );
        return;
    }
    // Forward path: NAT and write back to TUN.
    let client_addr = SocketAddr::new(meta.src_ip, meta.src_port);
    let target_addr = SocketAddr::new(meta.dst_ip, meta.dst_port);

    // Guard: packets aimed at our TUN listener must be the synthetic
    // `tun_next:nat_port -> tun_addr:listener_port` packets created below. If
    // the NAT entry is gone, dropping here prevents stale internal TCP flows
    // from being fed back into the listener indefinitely.
    if meta.dst_ip == *tun_addr && meta.dst_port == listener_port {
        let tun_next = next_addr(*tun_addr);
        if meta.src_ip == tun_next {
            let guard = nat.lock().await;
            if guard.contains_port(meta.src_port) {
                return;
            }
        }
        log::debug!(
            "stale TUN listener packet dropped: src={}:{} dst={}:{}",
            meta.src_ip,
            meta.src_port,
            meta.dst_ip,
            meta.dst_port,
        );
        return;
    }

    let nat_port = {
        let mut guard = nat.lock().await;
        guard.lookup(client_addr, target_addr)
    };

    // Calculate the "next" address for the TUN interface (used as the
    // source IP in rewritten packets so the kernel routes responses back
    // through TUN).
    let tun_next = next_addr(*tun_addr);

    match (tun_next, meta.src_ip, meta.dst_ip) {
        (IpAddr::V4(tun_next_v4), IpAddr::V4(_), IpAddr::V4(_)) => {
            let IpAddr::V4(tun_v4) = *tun_addr else {
                return;
            };

            packet::rewrite_tcp_ipv4(
                buf,
                meta,
                tun_next_v4,
                nat_port,
                tun_v4,
                listener_port,
            );
        },
        (IpAddr::V6(tun_next_v6), IpAddr::V6(_), IpAddr::V6(_)) => {
            let IpAddr::V6(tun_v6) = *tun_addr else {
                return;
            };

            packet::rewrite_tcp_ipv6(
                buf,
                meta,
                tun_next_v6,
                nat_port,
                tun_v6,
                listener_port,
            );
        },
        _ => return, // Mismatched address families
    }

    if let Err(e) = tun.send(&buf[..meta.total_len]).await {
        log::debug!("TUN write error (forward TCP): {e}");
    }
}

/// Handle a UDP packet: dispatch via session table, or create a new
/// relay session.
///
/// Returns `true` if the packet was dropped (channel full / system under
/// load), `false` if it was successfully dispatched.
async fn handle_udp_packet(
    buf: &[u8], meta: &IpPacketMeta, tun_addr: &IpAddr,
    conn_tx: &mpsc::Sender<InboundConn>, writer: &TunWriter,
    sessions: &mut UdpSessionTable, reverse_dns: &Option<Arc<ReverseDnsCache>>,
) -> bool {
    let l4_off = meta.l4_offset;
    let udp_hdr_end = l4_off + 8; // UDP header is 8 bytes
    let udp_payload = if udp_hdr_end < meta.total_len {
        &buf[udp_hdr_end..meta.total_len]
    } else {
        return false; // Malformed UDP packet
    };

    // Guard: if destination is the TUN address itself, this packet is a
    // response to a local process (e.g. NTP reply, DNS reply) that was
    // just written back to TUN by TunUdpSessionRelay::write_packet.
    // The kernel has already delivered it via `iif tun0 lookup main`.
    // Processing it again would create a new relay and outbound connection,
    // causing a self-sustaining loop.
    if meta.dst_ip == *tun_addr {
        log::error!(
            "TUN re-injection (UDP): dst={}:{} (local process response) — dropped",
            meta.dst_ip,
            meta.dst_port,
        );
        return false;
    }
    let payload = udp_payload.to_vec();

    let key = UdpSessionKey::from_meta(meta);

    // Try to find existing session.
    if let Some(session) = sessions.sessions.get_mut(&key) {
        session.last_activity = Instant::now();
        if session.tx.try_send((payload, meta.src_port)).is_err() {
            // Receiver dropped — the relay task exited. Remove the stale
            // session so the next packet creates a fresh one.
            sessions.sessions.remove(&key);
        }
        return false;
    }

    // No existing session — create a new relay.
    let (packet_tx, packet_rx) = mpsc::channel::<(Vec<u8>, u16)>(256);

    let relay = TunUdpSessionRelay::new(
        writer.clone(),
        meta.dst_ip,
        meta.dst_port,
        meta.src_ip,
        meta.src_port,
        payload,   // first datagram = pending payload
        packet_rx, // subsequent datagrams arrive here
    );

    let initial_destination = if let Some(ref rev) = *reverse_dns {
        match meta.dst_ip {
            IpAddr::V4(v4) =>
                if let Some(domain) = rev.lookup_ipv4(v4).await {
                    Destination::with_resolved(
                        Address::Domain(domain),
                        meta.dst_port,
                        meta.dst_ip,
                    )
                } else {
                    Destination::new(ip_to_address(meta.dst_ip), meta.dst_port)
                },
            IpAddr::V6(v6) =>
                if let Some(domain) = rev.lookup_ipv6(v6).await {
                    Destination::with_resolved(
                        Address::Domain(domain),
                        meta.dst_port,
                        meta.dst_ip,
                    )
                } else {
                    Destination::new(ip_to_address(meta.dst_ip), meta.dst_port)
                },
        }
    } else {
        Destination::new(ip_to_address(meta.dst_ip), meta.dst_port)
    };
    let source = SocketAddr::new(meta.src_ip, meta.src_port);

    let conn = InboundConn::Udp {
        initial_destination,
        packet: Box::new(relay),
        source,
        type_: "tun".into(),
    };

    if conn_tx.try_send(conn).is_ok() {
        // Insert session entry only after conn_tx accepted it.
        sessions.sessions.insert(key, UdpSession {
            tx: packet_tx,
            last_activity: Instant::now(),
        });
        false
    } else {
        // Channel full — system under load (fd exhaustion, outbound failures).
        // Return true so the caller backs off, preventing a retransmit storm.
        true
    }
}

/// Get the next address in the subnet (tun_addr + 1).
fn next_addr(addr: IpAddr) -> IpAddr {
    match addr {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            IpAddr::V4(Ipv4Addr::new(
                octets[0],
                octets[1],
                octets[2],
                octets[3].wrapping_add(1),
            ))
        },
        IpAddr::V6(v6) => {
            let octets = v6.octets();
            let mut new_octets = octets;
            // Add 1 to the last byte.
            for i in (0..16).rev() {
                let (val, overflow) = new_octets[i].overflowing_add(1);
                new_octets[i] = val;
                if !overflow {
                    break;
                }
            }
            IpAddr::V6(Ipv6Addr::from(new_octets))
        },
    }
}

fn ip_to_address(ip: IpAddr) -> Address {
    match ip {
        IpAddr::V4(v4) => Address::Ipv4(v4.octets()),
        IpAddr::V6(v6) => Address::Ipv6(v6.octets()),
    }
}

// ---------------------------------------------------------------------------
// TunUdpSessionRelay
// ---------------------------------------------------------------------------

/// A UDP relay that reads datagrams from a channel (fed by the TUN reader
/// for subsequent packets) and writes responses as raw IP packets to the
/// TUN device.
///
/// The first datagram is held as `pending_payload` to avoid a round-trip
/// through the channel during session creation.
pub struct TunUdpSessionRelay {
    writer: TunWriter,
    /// IP and port for the source of response packets (original target).
    resp_src_ip: IpAddr,
    resp_src_port: u16,
    /// IP and port for the destination of response packets (original client).
    resp_dst_ip: IpAddr,
    resp_dst_port: u16,
    /// Buffered payload from the first incoming datagram.
    pending_payload: Option<Vec<u8>>,
    /// Channel receiver for subsequent datagrams from the same UDP flow.
    /// Items are (payload, latest_client_port).
    packet_rx: mpsc::Receiver<(Vec<u8>, u16)>,
}

impl TunUdpSessionRelay {
    pub fn new(
        writer: TunWriter, resp_src_ip: IpAddr, resp_src_port: u16,
        resp_dst_ip: IpAddr, resp_dst_port: u16, first_payload: Vec<u8>,
        packet_rx: mpsc::Receiver<(Vec<u8>, u16)>,
    ) -> Self {
        Self {
            writer,
            resp_src_ip,
            resp_src_port,
            resp_dst_ip,
            resp_dst_port,
            pending_payload: Some(first_payload),
            packet_rx,
        }
    }
}

#[async_trait]
impl PacketRelay for TunUdpSessionRelay {
    async fn read_packet(
        &mut self, buf: &mut [u8],
    ) -> std::io::Result<(usize, Destination)> {
        // Return the first datagram from pending payload.
        if let Some(payload) = self.pending_payload.take() {
            let len = payload.len().min(buf.len());
            buf[..len].copy_from_slice(&payload[..len]);
            let dest = Destination::new(
                ip_to_address(self.resp_src_ip),
                self.resp_src_port,
            );
            return Ok((len, dest));
        }

        // Subsequent datagrams arrive via channel.
        match self.packet_rx.recv().await {
            Some((data, new_port)) => {
                self.resp_dst_port = new_port;
                let len = data.len().min(buf.len());
                buf[..len].copy_from_slice(&data[..len]);
                let dest = Destination::new(
                    ip_to_address(self.resp_src_ip),
                    self.resp_src_port,
                );
                Ok((len, dest))
            },
            None => {
                // Channel closed → session table removed us (idle timeout
                // or connection end). Signal EOF.
                Ok((0, Destination::new(Address::Ipv4([0, 0, 0, 0]), 0)))
            },
        }
    }

    async fn write_packet(
        &mut self, buf: &[u8], _dest: &Destination,
    ) -> std::io::Result<()> {
        let raw = match (self.resp_src_ip, self.resp_dst_ip) {
            (IpAddr::V4(src), IpAddr::V4(dst)) =>
                packet::build_udp_response_ipv4(
                    src,
                    self.resp_src_port,
                    dst,
                    self.resp_dst_port,
                    buf,
                ),
            (IpAddr::V6(src), IpAddr::V6(dst)) =>
                packet::build_udp_response_ipv6(
                    src,
                    self.resp_src_port,
                    dst,
                    self.resp_dst_port,
                    buf,
                ),
            _ => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "mismatched IP versions",
                ));
            },
        };
        self.writer.write(&raw).await?;
        Ok(())
    }

    async fn close(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
