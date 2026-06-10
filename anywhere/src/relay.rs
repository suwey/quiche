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

use crate::inbound::Destination;
use crate::ui::state::AppStats;
use crate::ui::state::ConnCounters;
use crate::ui::state::TagStats;

const BUF_SIZE: usize = 4096;
// TUN MTU is 1500 by default; keep relay buffers MTU-scale instead of
// allocating 64KiB per direction per UDP session. P2P traffic can create
// hundreds of UDP sessions, so oversized buffers inflate RSS high-water.
const UDP_BUF_SIZE: usize = 4096;

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

/// Runs two concurrent `copy_one_way` tasks and completes when either
/// direction finishes (half-close / one-way EOF semantics).
pub async fn bidirectional_relay(
    a: &mut dyn StreamRelay, b: &mut dyn StreamRelay,
) {
    // SAFETY: The two `copy_one_way` futures are mutually exclusive via
    // `tokio::select!` — only one future makes progress at any given time,
    // so the aliased `&mut` references (each relay appears in both futures)
    // never conflict at runtime.
    unsafe {
        let a1 = &mut *(a as *mut dyn StreamRelay);
        let b1 = &mut *(b as *mut dyn StreamRelay);
        let a2 = &mut *(a as *mut dyn StreamRelay);
        let b2 = &mut *(b as *mut dyn StreamRelay);

        tokio::select! {
            _ = copy_one_way(a1, b1) => {},
            _ = copy_one_way(b2, a2) => {},
        }
    }

    let _ = a.shutdown().await;
    let _ = b.shutdown().await;
}

/// Reads from `src` in [`BUF_SIZE`] chunks and writes each chunk to `dst`.
/// When `src` returns 0 (EOF), calls [`StreamRelay::shutdown`] on `dst`.
async fn copy_one_way(src: &mut dyn StreamRelay, dst: &mut dyn StreamRelay) {
    let mut buf = [0u8; BUF_SIZE];
    loop {
        match src.read(&mut buf).await {
            Ok(0) => {
                let _ = dst.shutdown().await;
                break;
            },
            Ok(n) =>
                if dst.write(&buf[..n]).await.is_err() {
                    break;
                },
            Err(_) => break,
        }
    }
}

/// Runs two concurrent datagram copy tasks and completes when either direction
/// terminates (no EOF/shutdown semantics for UDP — failure on either side ends
/// the session).
pub async fn bidirectional_packet_relay(
    a: &mut dyn PacketRelay, b: &mut dyn PacketRelay,
) {
    // SAFETY: see `bidirectional_relay` — `tokio::select!` guarantees mutual
    // exclusion at runtime.
    unsafe {
        let a1 = &mut *(a as *mut dyn PacketRelay);
        let b1 = &mut *(b as *mut dyn PacketRelay);
        let a2 = &mut *(a as *mut dyn PacketRelay);
        let b2 = &mut *(b as *mut dyn PacketRelay);

        tokio::select! {
            _ = copy_packets_one_way(a1, b1) => {},
            _ = copy_packets_one_way(b2, a2) => {},
        }
    }
    let _ = a.close().await;
    let _ = b.close().await;
}

async fn copy_packets_one_way(
    src: &mut dyn PacketRelay, dst: &mut dyn PacketRelay,
) {
    let mut buf = vec![0u8; UDP_BUF_SIZE];
    loop {
        match src.read_packet(&mut buf).await {
            Ok((0, _)) => break,
            Ok((n, dest)) => {
                if dst.write_packet(&buf[..n], &dest).await.is_err() {
                    break;
                }
            },
            Err(_) => break,
        }
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
