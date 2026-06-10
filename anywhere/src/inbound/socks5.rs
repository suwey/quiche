use async_trait::async_trait;
use std::io;
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::net::TcpStream;

use crate::inbound::Address;
use crate::inbound::Destination;
use crate::inbound::Inbound;
use crate::inbound::InboundConn;
use crate::relay::TcpRelay;

// ---------------------------------------------------------------------------
// Internal SOCKS5 connection state
// ---------------------------------------------------------------------------

struct Socks5Conn {
    stream: TcpStream,
    buf: Vec<u8>,
    /// Data from SOCKS5 waiting to be sent upstream (early data after the
    /// SOCKS5 request, such as a TLS Client Hello).
    #[allow(dead_code)]
    pending: Vec<u8>,
}

impl Socks5Conn {
    fn new(stream: TcpStream) -> Self {
        Self {
            stream,
            buf: Vec::new(),
            pending: Vec::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// Socks5Inbound
// ---------------------------------------------------------------------------

pub struct Socks5Inbound {
    listener: TcpListener,
}

impl Socks5Inbound {
    pub async fn new(listen: &str) -> io::Result<Self> {
        let listener = TcpListener::bind(listen).await?;
        log::info!("SOCKS5 inbound listening on {listen}");
        Ok(Self { listener })
    }
}

#[async_trait]
impl Inbound for Socks5Inbound {
    async fn accept(&mut self) -> Option<InboundConn> {
        loop {
            let (stream, peer) = match self.listener.accept().await {
                Ok(v) => v,
                Err(e) => {
                    log::warn!("SOCKS5 accept error: {e}, retrying in 1s...");
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    continue;
                },
            };
            log::debug!("SOCKS5 connection from {peer}");

            let mut conn = Socks5Conn::new(stream);

            // Phase 1: method negotiation
            let handshake_ok = loop {
                match process_handshake(&mut conn).await {
                    Ok(true) => break true,
                    Ok(false) => {
                        tokio::task::yield_now().await;
                        continue;
                    },
                    Err(e) => {
                        log::warn!("SOCKS5 handshake error from {peer}: {e}");
                        break false;
                    },
                }
            };
            if !handshake_ok {
                continue;
            }

            // Phase 2: request parsing
            let destination = loop {
                match process_request(&mut conn).await {
                    Ok(Some(d)) => break Some(d),
                    Ok(None) => {
                        tokio::task::yield_now().await;
                        continue;
                    },
                    Err(e) => {
                        log::warn!("SOCKS5 request error from {peer}: {e}");
                        break None;
                    },
                }
            };
            let Some(destination) = destination else {
                continue;
            };

            log::debug!("SOCKS5 connect to {destination} from {peer}");

            return Some(InboundConn::Tcp {
                destination,
                stream: Box::new(TcpRelay::new(conn.stream)),
                source: peer,
                type_: "socks5".to_string(),
            });
        }
    }
}

// ---------------------------------------------------------------------------
// SOCKS5 helpers (ported from anywhere-client)
// ---------------------------------------------------------------------------

/// Process SOCKS5 method negotiation.
/// Returns `true` when handshake is complete and the caller should move to
/// the Request state.
async fn process_handshake(conn: &mut Socks5Conn) -> io::Result<bool> {
    let mut temp = [0; 1024];
    match conn.stream.read(&mut temp).await {
        Ok(0) => {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "connection closed",
            ));
        },
        Ok(n) => conn.buf.extend_from_slice(&temp[..n]),
        Err(e) if e.kind() == io::ErrorKind::WouldBlock => {},
        Err(e) => return Err(e),
    }

    if conn.buf.len() < 2 {
        return Ok(false);
    }
    let nmethods = conn.buf[1] as usize;
    let handshake_len = 2 + nmethods;
    if conn.buf.len() < handshake_len {
        return Ok(false);
    }

    if conn.buf[0] != 0x05 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "bad socks5 version",
        ));
    }
    let methods = &conn.buf[2..handshake_len];
    if !methods.contains(&0x00) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "no acceptable auth method",
        ));
    }

    conn.stream.write_all(&[0x05, 0x00]).await?;
    conn.buf.drain(..handshake_len);
    Ok(true)
}

/// Process SOCKS5 CONNECT request.
/// Returns `Some(destination)` when the request is fully parsed.
async fn process_request(
    conn: &mut Socks5Conn,
) -> io::Result<Option<Destination>> {
    let mut temp = [0; 2048];
    match conn.stream.read(&mut temp).await {
        Ok(0) => {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "connection closed",
            ));
        },
        Ok(n) => conn.buf.extend_from_slice(&temp[..n]),
        Err(e) if e.kind() == io::ErrorKind::WouldBlock => {},
        Err(e) => return Err(e),
    }

    let total_len = match request_total_len(&conn.buf) {
        Some(len) => len,
        None => return Ok(None),
    };

    if conn.buf.len() < total_len {
        return Ok(None);
    }

    if conn.buf[0] != 0x05 || conn.buf[1] != 0x01 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "bad socks5 request",
        ));
    }

    let target = parse_target(&conn.buf[..total_len]).ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "parse target failed")
    })?;

    // Reply success (SOCKS5: Ver=5, Rep=0, RSV=0, ATYP=1, BND.ADDR=0, BND.PORT=0)
    conn.stream
        .write_all(&[0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
        .await?;

    // Move any extra data (TLS Client Hello etc.) to pending_to_h3
    if conn.buf.len() > total_len {
        conn.pending.extend_from_slice(&conn.buf[total_len..]);
    }
    conn.buf.clear();
    Ok(Some(target))
}

fn request_total_len(buf: &[u8]) -> Option<usize> {
    if buf.len() < 5 {
        return None;
    }
    match buf[3] {
        0x01 => Some(10),
        0x03 => {
            let domain_len = buf[4] as usize;
            Some(7 + domain_len)
        },
        0x04 => Some(22),
        _ => None,
    }
}

fn parse_target(buf: &[u8]) -> Option<Destination> {
    let atyp = buf[3];
    let port = u16::from_be_bytes([buf[buf.len() - 2], buf[buf.len() - 1]]);
    match atyp {
        0x01 => {
            let octets: [u8; 4] = buf[4..8].try_into().ok()?;
            Some(Destination::new(Address::Ipv4(octets), port))
        },
        0x03 => {
            let domain_len = buf[4] as usize;
            let domain = std::str::from_utf8(&buf[5..5 + domain_len])
                .ok()?
                .to_string();
            Some(Destination::new(Address::Domain(domain), port))
        },
        0x04 => {
            let octets: [u8; 16] = buf[4..20].try_into().ok()?;
            Some(Destination::new(Address::Ipv6(octets), port))
        },
        _ => None,
    }
}
