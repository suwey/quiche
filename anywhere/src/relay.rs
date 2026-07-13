use std::io;
use std::sync::Arc;
use std::sync::atomic::Ordering;

use async_trait::async_trait;
use bytes::Bytes;
use futures_util::sink::SinkExt;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::net::UdpSocket;
use tokio_quiche::http3::driver::InboundFrame;
use tokio_quiche::http3::driver::InboundFrameStream;
use tokio_quiche::http3::driver::OutboundFrame;
use tokio_quiche::http3::driver::OutboundFrameSender;

/// Default UDP idle timeout if no protocol-specific override applies.
pub const DEFAULT_UDP_TIMEOUT: std::time::Duration =
    std::time::Duration::from_secs(120);

/// How long to wait for the remaining direction of a TCP relay to drain
/// after one direction has half-closed. Prevents zombie connections when
/// the peer never sends EOF (e.g. crashed, network partition).
const HALF_CLOSE_TIMEOUT: std::time::Duration =
    std::time::Duration::from_secs(15);

/// Returns the UDP idle timeout for a given sniffed protocol.
///
/// Short-lived query protocols (DNS, NTP, STUN) get a short timeout
/// since they typically complete in a single round-trip.
/// Long-lived protocols (QUIC, DTLS) get a longer timeout to avoid
/// killing active sessions.
pub fn udp_timeout_for_protocol(protocol: &str) -> std::time::Duration {
    match protocol {
        "dns" | "ntp" | "stun" => std::time::Duration::from_secs(10),
        "quic" | "dtls" => std::time::Duration::from_secs(60),
        _ => DEFAULT_UDP_TIMEOUT,
    }
}

use crate::inbound::Destination;
use crate::ui::state::AppStats;
use crate::ui::state::ConnCounters;
use crate::ui::state::TagStats;

const BUF_SIZE: usize = 16 * 1024; // 16 KB
// TUN MTU is 1500 by default; keep relay buffers MTU-scale instead of
// allocating 64KiB per direction per UDP session. P2P traffic can create
// hundreds of UDP sessions, so oversized buffers inflate RSS high-water.
const UDP_BUF_SIZE: usize = 16 * 1024; // 16 KB

/// Unified async read/write abstraction for proxying data between TCP and H3
/// bidirectional streams.
#[async_trait]
pub trait StreamRelay: Send {
    /// Reads up to `buf.len()` bytes into `buf`. Returns the number of bytes
    /// read, or 0 to signal end-of-stream.
    async fn read(&mut self, buf: &mut [u8]) -> io::Result<usize>;

    /// Writes all bytes from `buf` to the stream.
    async fn write(&mut self, buf: &[u8]) -> io::Result<()>;

    /// Shuts down the write side of the stream (sends FIN).
    async fn shutdown(&mut self) -> io::Result<()>;

    /// Forcefully reset the connection (sends TCP RST instead of FIN).
    /// Default implementation falls back to `shutdown`.
    async fn reset(&mut self) {
        let _ = self.shutdown().await;
    }
}

/// Multi-target async datagram relay abstraction.
///
/// Each `read_packet` returns one datagram along with the destination it was
/// addressed to (server-side: the destination the client wanted to reach).
/// Each `write_packet` sends one datagram to the specified destination.
#[async_trait]
pub trait PacketRelay: Send {
    /// Reads one datagram. Returns `(bytes_written, destination)`.
    /// Returns `Ok((0, _))` to signal end-of-session.
    async fn read_packet(
        &mut self, buf: &mut [u8],
    ) -> io::Result<(usize, Destination)>;

    /// Sends one datagram to `dest`.
    async fn write_packet(
        &mut self, buf: &[u8], dest: &Destination,
    ) -> io::Result<()>;

    /// Closes the session.
    async fn close(&mut self) -> io::Result<()>;
}

/// Wraps a [`TcpStream`] as a [`StreamRelay`].
pub struct TcpRelay(TcpStream);

impl TcpRelay {
    pub fn new(stream: TcpStream) -> Self {
        Self(stream)
    }
}

#[async_trait]
impl StreamRelay for TcpRelay {
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
        let sock_ref = SockRef::from(&self.0);
        let _ = sock_ref.set_linger(Some(std::time::Duration::ZERO));
        // Shutdown the write side — with SO_LINGER=0 this triggers RST.
        let _ = self.0.shutdown().await;
    }
}

/// Wraps a [`UdpSocket`] as a [`PacketRelay`].
pub struct UdpRelay(UdpSocket);

impl UdpRelay {
    pub fn new(socket: UdpSocket) -> Self {
        Self(socket)
    }
}

#[async_trait]
impl PacketRelay for UdpRelay {
    async fn read_packet(
        &mut self, buf: &mut [u8],
    ) -> io::Result<(usize, Destination)> {
        let (n, addr) = self.0.recv_from(buf).await?;
        let dest: Destination = addr.to_string().parse().map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid UDP source address",
            )
        })?;
        Ok((n, dest))
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
        self.0.send_to(buf, addr).await?;
        Ok(())
    }

    async fn close(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Wraps an H3 bidirectional frame channel as a [`StreamRelay`].
///
/// Reads are internally buffered so callers see a byte-stream interface
/// regardless of how data arrives in [`InboundFrame::Body`] chunks.
pub struct H3Relay {
    sender: OutboundFrameSender,
    receiver: InboundFrameStream,
    read_buf: Vec<u8>,
    read_pos: usize,
}

impl H3Relay {
    pub fn new(
        sender: OutboundFrameSender, receiver: InboundFrameStream,
    ) -> Self {
        Self {
            sender,
            receiver,
            read_buf: Vec::new(),
            read_pos: 0,
        }
    }
}

#[async_trait]
impl StreamRelay for H3Relay {
    async fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // Refill internal buffer when exhausted.
        if self.read_pos >= self.read_buf.len() {
            loop {
                match self.receiver.recv().await {
                    Some(InboundFrame::Body(data, _fin)) => {
                        self.read_buf = data.to_vec();
                        self.read_pos = 0;

                        // If the Body frame carried no data (e.g. a FIN-only
                        // frame), signal end-of-stream.
                        if self.read_buf.is_empty() {
                            return Ok(0);
                        }
                        break;
                    },
                    Some(InboundFrame::Datagram(_)) => {
                        // Ignore datagrams on the relay channel.
                        continue;
                    },
                    None => {
                        // Stream has been closed by the peer.
                        return Ok(0);
                    },
                }
            }
        }

        let available = self.read_buf.len() - self.read_pos;
        let to_copy = std::cmp::min(buf.len(), available);
        buf[..to_copy].copy_from_slice(
            &self.read_buf[self.read_pos..self.read_pos + to_copy],
        );
        self.read_pos += to_copy;
        Ok(to_copy)
    }

    async fn write(&mut self, buf: &[u8]) -> io::Result<()> {
        self.sender
            .send(OutboundFrame::Body(Bytes::copy_from_slice(buf), false))
            .await
            .map_err(|_| {
                io::Error::new(io::ErrorKind::BrokenPipe, "H3 send failed")
            })
    }

    async fn shutdown(&mut self) -> io::Result<()> {
        self.sender
            .send(OutboundFrame::Body(Bytes::new(), true))
            .await
            .map_err(|_| {
                io::Error::new(io::ErrorKind::BrokenPipe, "H3 shutdown failed")
            })
    }
}

/// Runs two concurrent `copy_one_way` tasks.
///
/// When one direction finishes (EOF / error), it half-closes the peer's
/// write side via `shutdown()`, signaling the remote that no more data
/// will be sent. The relay then **waits for the other direction to drain**
/// before fully closing both sides. This is important for protocols where
/// the server sends data after the client closes its write side (e.g.
/// HTTP request → response, TLS close_notify, SSH channel close).
///
/// If the remaining direction does not drain within [`HALF_CLOSE_TIMEOUT`],
/// the relay gives up and fully closes both sides to prevent zombie
/// connections from lingering indefinitely.
pub async fn bidirectional_relay(
    a: &mut dyn StreamRelay, b: &mut dyn StreamRelay,
) {
    // SAFETY: The two `copy_one_way` futures are mutually exclusive via
    // `tokio::select!` — only one future makes progress at any given time,
    // so the aliased `&mut` references (each relay appears in both futures)
    // never conflict at runtime.
    //
    // After one direction completes, we re-enter a second select to let
    // the other direction drain. The completed direction's future is
    // already finished so it returns immediately; the pending one
    // continues until EOF or timeout.
    unsafe {
        let a1 = &mut *(a as *mut dyn StreamRelay);
        let b1 = &mut *(b as *mut dyn StreamRelay);
        let a2 = &mut *(a as *mut dyn StreamRelay);
        let b2 = &mut *(b as *mut dyn StreamRelay);

        // Phase 1: race both directions. The first to finish half-closes
        // the peer's write side; the loser keeps running.
        let ab_done = tokio::sync::Mutex::new(false);
        let ba_done = tokio::sync::Mutex::new(false);

        tokio::select! {
            _ = copy_one_way(a1, b1) => {
                log::debug!("relay: direction A→B completed, waiting for B→A to drain");
                *ab_done.lock().await = true;
            },
            _ = copy_one_way(b2, a2) => {
                log::debug!("relay: direction B→A completed, waiting for A→B to drain");
                *ba_done.lock().await = true;
            },
        }

        // Phase 2: let the remaining direction drain with a timeout.
        // The completed direction's future is dropped by select!, so
        // we only need to re-run the pending one.
        let a3 = &mut *(a as *mut dyn StreamRelay);
        let b3 = &mut *(b as *mut dyn StreamRelay);
        let a4 = &mut *(a as *mut dyn StreamRelay);
        let b4 = &mut *(b as *mut dyn StreamRelay);

        let ab = *ab_done.lock().await;
        let ba = *ba_done.lock().await;

        if !ab {
            // A→B still running — drain it.
            let _ = tokio::time::timeout(
                HALF_CLOSE_TIMEOUT,
                copy_one_way(a3, b3),
            ).await;
        } else if !ba {
            // B→A still running — drain it.
            let _ = tokio::time::timeout(
                HALF_CLOSE_TIMEOUT,
                copy_one_way(b4, a4),
            ).await;
        }
    }

    let _ = a.shutdown().await;
    let _ = b.shutdown().await;
}

/// Reads from `src` in [`BUF_SIZE`] chunks and writes each chunk to `dst`.
/// When `src` returns 0 (EOF), shuts down the **write side of `dst`**
/// (half-close) so the peer knows no more data is coming, but `dst`'s
/// read side remains open for the reverse direction to drain.
async fn copy_one_way(src: &mut dyn StreamRelay, dst: &mut dyn StreamRelay) {
    let mut buf = [0u8; BUF_SIZE];
    loop {
        match src.read(&mut buf).await {
            Ok(0) => {
                // Half-close: tell dst we're done writing, but don't
                // fully shut it down — the reverse direction may still
                // have data to deliver.
                let _ = dst.shutdown().await;
                break;
            },
            Ok(n) => {
                if dst.write(&buf[..n]).await.is_err() {
                    break;
                }
            },
            Err(e) => {
                log::debug!(
                    "relay: copy_one_way src read error {e}, breaking"
                );
                break;
            },
        }
    }
}

/// Runs two concurrent datagram copy tasks.
///
/// When one direction terminates (idle timeout / error / EOF), the other
/// direction is given a short grace period ([`HALF_CLOSE_TIMEOUT`]) to
/// drain any in-flight packets before both sides are fully closed.
///
/// A timeout is applied to each `read_packet` call: if no packet is received
/// within `idle_timeout` on either side, the relay terminates and both sides
/// are closed. This prevents zombie UDP sessions from lingering indefinitely
/// after NAT mappings expire or the peer disappears.
pub async fn bidirectional_packet_relay(
    a: &mut dyn PacketRelay,
    b: &mut dyn PacketRelay,
    idle_timeout: std::time::Duration,
) {
    // SAFETY: see `bidirectional_relay` — `tokio::select!` guarantees mutual
    // exclusion at runtime.
    unsafe {
        let a1 = &mut *(a as *mut dyn PacketRelay);
        let b1 = &mut *(b as *mut dyn PacketRelay);
        let a2 = &mut *(a as *mut dyn PacketRelay);
        let b2 = &mut *(b as *mut dyn PacketRelay);

        let ab_done = tokio::sync::Mutex::new(false);
        let ba_done = tokio::sync::Mutex::new(false);

        tokio::select! {
            _ = copy_packets_one_way(a1, b1, idle_timeout) => {
                log::debug!("packet relay: A→B done, draining B→A");
                *ab_done.lock().await = true;
            },
            _ = copy_packets_one_way(b2, a2, idle_timeout) => {
                log::debug!("packet relay: B→A done, draining A→B");
                *ba_done.lock().await = true;
            },
        }

        // Drain the remaining direction with a short grace period.
        let a3 = &mut *(a as *mut dyn PacketRelay);
        let b3 = &mut *(b as *mut dyn PacketRelay);
        let a4 = &mut *(a as *mut dyn PacketRelay);
        let b4 = &mut *(b as *mut dyn PacketRelay);

        let ab = *ab_done.lock().await;
        let ba = *ba_done.lock().await;

        if !ab {
            let _ = tokio::time::timeout(
                HALF_CLOSE_TIMEOUT,
                copy_packets_one_way(a3, b3, idle_timeout),
            ).await;
        } else if !ba {
            let _ = tokio::time::timeout(
                HALF_CLOSE_TIMEOUT,
                copy_packets_one_way(b4, a4, idle_timeout),
            ).await;
        }
    }
    let _ = a.close().await;
    let _ = b.close().await;
}

async fn copy_packets_one_way(
    src: &mut dyn PacketRelay,
    dst: &mut dyn PacketRelay,
    idle_timeout: std::time::Duration,
) {
    let mut buf = vec![0u8; UDP_BUF_SIZE];
    loop {
        match tokio::time::timeout(
            idle_timeout,
            src.read_packet(&mut buf),
        )
        .await
        {
            Err(_) => {
                log::debug!(
                    "packet relay: idle timeout ({idle_timeout:?}), \
                     terminating direction"
                );
                break;
            },
            Ok(Ok((0, _))) => break,
            Ok(Ok((n, dest))) => {
                if dst.write_packet(&buf[..n], &dest).await.is_err() {
                    break;
                }
            },
            Ok(Err(_)) => break,
        }
    }
}

/// Wraps a `Box<dyn StreamRelay>` and prepends a buffer of already-read
/// bytes before passing through to the inner relay.
///
/// Used by the TUN sniff path: we read up to 4096 bytes from the TCP stream
/// to sniff TLS SNI / HTTP Host, then wrap the stream so the sniffed bytes
/// are returned first before reading new data from the inner stream.
pub struct PrependStreamRelay {
    inner: Box<dyn StreamRelay>,
    pending: Vec<u8>,
    pending_pos: usize,
}

impl PrependStreamRelay {
    pub fn new(inner: Box<dyn StreamRelay>, pending: Vec<u8>) -> Self {
        Self {
            inner,
            pending,
            pending_pos: 0,
        }
    }
}

#[async_trait]
impl StreamRelay for PrependStreamRelay {
    async fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // Drain pending bytes first.
        if self.pending_pos < self.pending.len() {
            let remaining = &self.pending[self.pending_pos..];
            let n = std::cmp::min(buf.len(), remaining.len());
            buf[..n].copy_from_slice(&remaining[..n]);
            self.pending_pos += n;
            return Ok(n);
        }
        // Pending exhausted — pass through to inner relay.
        self.inner.read(buf).await
    }

    async fn write(&mut self, buf: &[u8]) -> io::Result<()> {
        self.inner.write(buf).await
    }

    async fn shutdown(&mut self) -> io::Result<()> {
        self.inner.shutdown().await
    }

    async fn reset(&mut self) {
        self.inner.reset().await;
    }
}

/// Wraps a [`Box<dyn PacketRelay>`] and replays a buffered first datagram
/// before passing through to the inner relay.
///
/// Used by the UDP sniff path: the first packet is consumed for sniffing,
/// then this wrapper restores it so downstream sees the complete stream.
pub struct PrependPacketRelay {
    inner: Box<dyn PacketRelay>,
    pending: Option<Vec<u8>>,
    pending_dest: Option<Destination>,
}

impl PrependPacketRelay {
    pub fn new(inner: Box<dyn PacketRelay>, first_packet: Vec<u8>, dest: Destination) -> Self {
        Self {
            inner,
            pending: Some(first_packet),
            pending_dest: Some(dest),
        }
    }
}

#[async_trait]
impl PacketRelay for PrependPacketRelay {
    async fn read_packet(
        &mut self, buf: &mut [u8],
    ) -> io::Result<(usize, Destination)> {
        if let (Some(payload), Some(dest)) = (self.pending.take(), self.pending_dest.take()) {
            let len = payload.len().min(buf.len());
            buf[..len].copy_from_slice(&payload[..len]);
            return Ok((len, dest));
        }
        self.inner.read_packet(buf).await
    }

    async fn write_packet(
        &mut self, buf: &[u8], dest: &Destination,
    ) -> io::Result<()> {
        self.inner.write_packet(buf, dest).await
    }

    async fn close(&mut self) -> io::Result<()> {
        self.inner.close().await
    }
}

/// Wraps a Box<dyn StreamRelay> and counts bytes flowing through.
pub struct CountedStreamRelay {
    pub inner: Box<dyn StreamRelay>,
    pub stats: Arc<AppStats>,
    pub conn_counters: Arc<ConnCounters>,
    pub tag_stats: Arc<TagStats>,
}

#[async_trait]
impl StreamRelay for CountedStreamRelay {
    async fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf).await?;
        // read = receiving data = download
        self.stats
            .download_total
            .fetch_add(n as u64, Ordering::Relaxed);
        self.conn_counters
            .download
            .fetch_add(n as u64, Ordering::Relaxed);
        self.tag_stats
            .download
            .fetch_add(n as u64, Ordering::Relaxed);
        Ok(n)
    }

    async fn write(&mut self, buf: &[u8]) -> io::Result<()> {
        let n = buf.len();
        self.inner.write(buf).await?;
        // write = sending data = upload
        self.stats
            .upload_total
            .fetch_add(n as u64, Ordering::Relaxed);
        self.conn_counters
            .upload
            .fetch_add(n as u64, Ordering::Relaxed);
        self.tag_stats.upload.fetch_add(n as u64, Ordering::Relaxed);
        Ok(())
    }

    async fn shutdown(&mut self) -> io::Result<()> {
        self.inner.shutdown().await
    }

    async fn reset(&mut self) {
        self.inner.reset().await;
    }
}

/// Wraps a Box<dyn PacketRelay> and counts bytes flowing through.
pub struct CountedPacketRelay {
    pub inner: Box<dyn PacketRelay>,
    pub stats: Arc<AppStats>,
    pub conn_counters: Arc<ConnCounters>,
    pub tag_stats: Arc<TagStats>,
}

#[async_trait]
impl PacketRelay for CountedPacketRelay {
    async fn read_packet(
        &mut self, buf: &mut [u8],
    ) -> io::Result<(usize, Destination)> {
        let (n, dest) = self.inner.read_packet(buf).await?;
        self.stats
            .download_total
            .fetch_add(n as u64, Ordering::Relaxed);
        self.conn_counters
            .download
            .fetch_add(n as u64, Ordering::Relaxed);
        self.tag_stats
            .download
            .fetch_add(n as u64, Ordering::Relaxed);
        Ok((n, dest))
    }

    async fn write_packet(
        &mut self, buf: &[u8], dest: &Destination,
    ) -> io::Result<()> {
        let n = buf.len();
        self.inner.write_packet(buf, dest).await?;
        self.stats
            .upload_total
            .fetch_add(n as u64, Ordering::Relaxed);
        self.conn_counters
            .upload
            .fetch_add(n as u64, Ordering::Relaxed);
        self.tag_stats.upload.fetch_add(n as u64, Ordering::Relaxed);
        Ok(())
    }

    async fn close(&mut self) -> io::Result<()> {
        self.inner.close().await
    }
}
