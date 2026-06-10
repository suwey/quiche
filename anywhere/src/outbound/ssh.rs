// SPDX-License-Identifier: BSD-2-Clause
// Copyright © The anywhere project contributors.

//! SSH-tunnel outbound via SOCKS5.
//!
//! Spawns a command (e.g. `ssh -D 1080 -N user@host`) that provides a SOCKS5
//! endpoint on a local port. Each [`OutboundClient::dial`] connects to that
//! endpoint and issues a SOCKS5 CONNECT; [`OutboundClient::dial_udp`] uses
//! UDP ASSOCIATE.
//!
//! # Config
//!
//! ```toml
//! [[outbounds]]
//! type = "ssh"
//! tag = "mac"
//! cmd = "ssh -D 1080 -N user@host"
//! server = "127.0.0.1:1080"
//! ```

use std::io;
use std::net::SocketAddr;
#[cfg(unix)]
use std::os::unix::process::CommandExt;
use std::process::Stdio;
use std::sync::Arc;
use std::sync::atomic::AtomicI32;
use std::sync::atomic::AtomicU32;
use std::sync::atomic::Ordering;
use std::time::Duration;

use async_trait::async_trait;
use tokio::io::AsyncBufReadExt;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::net::UdpSocket;
use tokio::process::Child;
use tokio::sync::Mutex;
use tokio::time::Instant;
use tokio::time::sleep;

use crate::inbound::Address;
use crate::inbound::Destination;
use crate::outbound::OutboundClient;
use crate::relay::PacketRelay;
use crate::relay::StreamRelay;
use crate::relay::TcpRelay;

const SSH_STARTUP_RETRIES: usize = 25; // 5 s total at 200 ms intervals.
const SSH_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const SSH_UDP_IDLE_TIMEOUT: Duration = Duration::from_secs(60);
const MAX_FAILURES_BEFORE_RESPAWN: u32 = 1;
const PROXY_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// Proxy protocol
// ---------------------------------------------------------------------------

/// Supported proxy protocols for talking to the tunnel endpoint.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ProxyType {
    Socks5,
    Http,
}

impl ProxyType {
    fn from_config(s: Option<&str>) -> Self {
        match s {
            Some("socks5") => ProxyType::Socks5,
            _ => ProxyType::Http,
        }
    }
}
// ---------------------------------------------------------------------------
pub struct SshOutboundClient {
    cmd: String,
    local_ip: std::net::IpAddr,
    allocated_port: std::sync::atomic::AtomicU16,
    process: Arc<Mutex<Option<Child>>>,
    child_pid: AtomicI32,
    proxy_type: ProxyType,
    /// Consecutive CONNECT failures. Reset on success; when reaching the
    /// threshold the tunnel is respawned even if the port is still open.
    failure_count: std::sync::atomic::AtomicU32,
}

impl SshOutboundClient {
    fn current_addr(&self) -> SocketAddr {
        SocketAddr::new(
            self.local_ip,
            self.allocated_port.load(Ordering::Relaxed),
        )
    }

    pub async fn from_config(
        cfg: &crate::config::OutboundConfig,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let cmd = cfg.cmd.as_deref().ok_or("ssh outbound: missing 'cmd'")?;
        let server = cfg
            .server
            .as_deref()
            .ok_or("ssh outbound: missing 'server'")?;

        let pt = ProxyType::from_config(cfg.proxy_type.as_deref());

        // server may contain {PORT}; resolve the IP part (throwaway port).
        // We'll replace {PORT} with a free port at spawn time.
        let bootstrap_addr =
            crate::outbound::common::resolve_addr(&server.replace("{PORT}", "1"))
                .map_err(|e| {
                    format!("ssh outbound: bad server '{server}': {e}")
                })?;

        let client = Self {
            cmd: cmd.to_string(),
            local_ip: bootstrap_addr.ip(),
            allocated_port: std::sync::atomic::AtomicU16::new(
                bootstrap_addr.port(),
            ),
            process: Arc::new(Mutex::new(None)),
            child_pid: AtomicI32::new(0),
            proxy_type: pt,
            failure_count: AtomicU32::new(0),
        };

        // Spawn the tunnel. Fail registration if the binary cannot be
        // spawned (command not found, fork error, etc.).
        client
            .spawn_tunnel()
            .await
            .map_err(|e| format!("ssh outbound '{}': {e}", client.cmd))?;

        // Wait a bit for the port to become ready. If it times out, log a
        // If it times out, log at error level because the outbound won't
        // work until the port becomes reachable.
        if let Err(e) = client.poll_port(SSH_STARTUP_RETRIES).await {
            log::error!(
                "ssh outbound '{}' tunnel not yet ready: {e}",
                client.cmd,
            );
        }

        Ok(client)
    }

    /// Spawn the tunnel command and store the child handle.
    ///
    /// If the config cmd contains `{PORT}`, it is replaced with a free
    /// ephemeral port so the tunnel never collides with TIME_WAIT from a
    /// previous instance.
    async fn spawn_tunnel(&self) -> io::Result<()> {
        let mut guard = self.process.lock().await;

        // If we already have a running process, nothing to do.
        if let Some(child) = &mut *guard {
            match child.try_wait() {
                Ok(None) => return Ok(()),
                _ => {
                    let _ = child.kill().await;
                    let _ = child.wait().await;
                    *guard = None;
                },
            }
        }

        // Allocate a free port for {PORT} substitution.
        let port = if self.cmd.contains("{PORT}") {
            let listener =
                std::net::TcpListener::bind("127.0.0.1:0").map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::Other,
                        format!("bind temp port: {e}"),
                    )
                })?;
            let p = listener
                .local_addr()
                .map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::Other,
                        format!("get temp port: {e}"),
                    )
                })?
                .port();
            drop(listener);
            self.allocated_port.store(p, Ordering::Relaxed);
            p
        } else {
            self.allocated_port.load(Ordering::Relaxed)
        };
        let resolved_cmd = self.cmd.replace("{PORT}", &port.to_string());

        // Parse into binary + args.
        let parts: Vec<&str> = resolved_cmd.split_whitespace().collect();
        if parts.is_empty() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "empty cmd"));
        }

        let mut std_cmd = std::process::Command::new(parts[0]);
        std_cmd
            .args(&parts[1..])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        #[cfg(unix)]
        {
            std_cmd.process_group(0);
        }
        let mut child = tokio::process::Command::from(std_cmd)
            .kill_on_drop(true)
            .spawn()
            .map_err(|e| {
                io::Error::new(
                    io::ErrorKind::Other,
                    format!("failed to spawn '{}': {e}", resolved_cmd),
                )
            })?;

        // Log stderr so the user can see SSH connection errors.
        if let Some(stderr) = child.stderr.take() {
            let cmd_tag = resolved_cmd.clone();
            tokio::spawn(async move {
                let reader = tokio::io::BufReader::new(stderr);
                let mut lines = reader.lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    log::error!("ssh [stderr] {}: {line}", cmd_tag);
                }
            });
        }

        let pid = child.id().unwrap_or(0) as i32;
        *guard = Some(child);
        self.child_pid.store(pid, Ordering::Relaxed);
        Ok(())
    }

    /// Poll `server_addr` up to `n` times (200 ms interval) until reachable.
    async fn poll_port(&self, n: usize) -> io::Result<()> {
        for _ in 0..n {
            if TcpStream::connect(self.current_addr()).await.is_ok() {
                return Ok(());
            }
            sleep(Duration::from_millis(200)).await;
        }
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            format!(
                "tunnel at {} not reachable after {} ms",
                self.current_addr(),
                n * 200,
            ),
        ))
    }

    /// Ensure the tunnel process is running and the local endpoint is
    /// reachable. Spawns / respawns as needed, with a brief timeout so the
    /// caller can fall back quickly instead of blocking for the full poll
    /// Ensure the tunnel process is running and the local endpoint is
    /// reachable. Spawns / respawns as needed.
    async fn ensure_running(&self) -> io::Result<()> {
        // Quick check (~500 ms) — most of the time the tunnel is already up.
        if tokio::time::timeout(
            Duration::from_millis(500),
            TcpStream::connect(self.current_addr()),
        )
        .await
        .ok()
        .and_then(|r| r.ok())
        .is_some()
        {
            return Ok(());
        }

        // Process might have died — respawn.
        self.spawn_tunnel().await?;

        // After a respawn, do the full poll cycle (up to 5 s) so the tunnel
        // has time to reconnect across a potentially slow link.
        self.poll_port(SSH_STARTUP_RETRIES).await
    }

    // -----------------------------------------------------------------------
    // Proxy protocol dispatch
    // -----------------------------------------------------------------------

    /// Connect to `dest` through the tunnel endpoint using the configured
    /// proxy protocol. On success the caller can read/write the proxied TCP
    /// stream directly.
    async fn proxy_connect(
        proxy_type: ProxyType, stream: &mut TcpStream, dest: &Destination,
    ) -> io::Result<()> {
        match proxy_type {
            ProxyType::Socks5 => {
                Self::socks5_handshake(stream).await?;
                Self::socks5_connect(stream, dest).await
            },
            ProxyType::Http => Self::http_connect(stream, dest).await,
        }
    }

    /// SOCKS5 handshake (no-auth).
    async fn socks5_handshake(stream: &mut TcpStream) -> io::Result<()> {
        stream.write_all(&[0x05, 0x01, 0x00]).await?;
        let mut buf = [0u8; 2];
        stream.read_exact(&mut buf).await?;
        if buf != [0x05, 0x00] {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("SOCKS5 handshake rejected: {buf:02x?}"),
            ));
        }
        Ok(())
    }

    /// SOCKS5 CONNECT. Caller must have handshaken.
    async fn socks5_connect(
        stream: &mut TcpStream, dest: &Destination,
    ) -> io::Result<()> {
        let mut req = Vec::with_capacity(10);
        req.extend_from_slice(&[0x05, 0x01, 0x00]);
        match &dest.address {
            Address::Ipv4(o) => {
                req.push(0x01);
                req.extend_from_slice(o);
            },
            Address::Ipv6(o) => {
                req.push(0x04);
                req.extend_from_slice(o);
            },
            Address::Domain(d) => {
                req.push(0x03);
                req.push(d.len() as u8);
                req.extend_from_slice(d.as_bytes());
            },
        }
        req.extend_from_slice(&dest.port.to_be_bytes());
        stream.write_all(&req).await?;

        let mut header = [0u8; 4];
        stream.read_exact(&mut header).await?;
        if header[1] != 0x00 {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("SOCKS5 CONNECT failed: rep={}", header[1]),
            ));
        }
        let atyp = header[3];
        let addr_len: usize = match atyp {
            0x01 => 4,
            0x04 => 16,
            0x03 => {
                let mut len = [0u8; 1];
                stream.read_exact(&mut len).await?;
                len[0] as usize
            },
            _ =>
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("SOCKS5 CONNECT unknown ATYP: {atyp}"),
                )),
        };
        let mut tail = vec![0u8; addr_len + 2];
        stream.read_exact(&mut tail).await?;
        Ok(())
    }

    /// HTTP CONNECT proxy handshake.
    async fn http_connect(
        stream: &mut TcpStream, dest: &Destination,
    ) -> io::Result<()> {
        let host_port = match &dest.address {
            Address::Ipv4(o) => {
                let ip = std::net::Ipv4Addr::from(*o);
                format!("{ip}:{}", dest.port)
            },
            Address::Ipv6(o) => {
                let ip = std::net::Ipv6Addr::from(*o);
                format!("[{ip}]:{}", dest.port)
            },
            Address::Domain(d) => format!("{d}:{}", dest.port),
        };
        let req =
            format!("CONNECT {host_port} HTTP/1.1\r\nHost: {host_port}\r\n\r\n");
        stream.write_all(req.as_bytes()).await?;

        // Read response headers until \r\n\r\n.
        let mut buf = [0u8; 4096];
        let mut pos = 0;
        loop {
            if pos >= buf.len() {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    "HTTP CONNECT response too large",
                ));
            }
            let n = stream.read(&mut buf[pos..]).await?;
            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionReset,
                    "HTTP CONNECT: connection closed",
                ));
            }
            pos += n;
            if buf[..pos].windows(4).any(|w| w == b"\r\n\r\n") {
                break;
            }
        }

        let status_line = std::str::from_utf8(&buf[..pos])
            .ok()
            .and_then(|s| s.lines().next())
            .unwrap_or("");
        if !status_line.contains("200") {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("HTTP CONNECT failed: {status_line}"),
            ));
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// OutboundClient impl
// ---------------------------------------------------------------------------

#[async_trait]
impl OutboundClient for SshOutboundClient {
    async fn dial(
        &self, dest: &Destination,
    ) -> Result<Box<dyn StreamRelay>, Box<dyn std::error::Error>> {
        self.ensure_running()
            .await
            .map_err(|e| format!("ssh outbound '{}' not ready: {e}", self.cmd))?;

        let failure_count = match self.try_dial(dest).await {
            Ok(relay) => {
                self.failure_count.store(0, Ordering::Relaxed);
                return Ok(relay);
            },
            Err(_) => self.failure_count.fetch_add(1, Ordering::Relaxed) + 1,
        };

        log::warn!(
            "ssh outbound: CONNECT failed \
             (count={failure_count}/{MAX_FAILURES_BEFORE_RESPAWN})",
        );

        if failure_count >= MAX_FAILURES_BEFORE_RESPAWN {
            self.failure_count.store(0, Ordering::Relaxed);
            self.kill_process().await;
            self.spawn_tunnel().await?;
            self.poll_port(SSH_STARTUP_RETRIES).await.map_err(|e| {
                format!("ssh outbound '{}' respawn failed: {e}", self.cmd)
            })?;
            return self.try_dial(dest).await;
        }

        sleep(Duration::from_millis(500)).await;
        self.try_dial(dest).await
    }

    async fn dial_udp(
        &self, _initial_dest: &Destination,
    ) -> Result<Box<dyn PacketRelay>, Box<dyn std::error::Error>> {
        self.ensure_running()
            .await
            .map_err(|e| format!("ssh outbound '{}' not ready: {e}", self.cmd))?;

        self.try_dial_udp().await
    }

    async fn test_latency(&self, host: &str, port: u16) -> Option<u64> {
        self.ensure_running().await.ok()?;

        let dest = if let Ok(ip) = host.parse::<std::net::IpAddr>() {
            let addr = match ip {
                std::net::IpAddr::V4(v4) => Address::Ipv4(v4.octets()),
                std::net::IpAddr::V6(v6) => Address::Ipv6(v6.octets()),
            };
            Destination {
                address: addr,
                port,
                resolved_ip: None,
            }
        } else {
            Destination {
                address: Address::Domain(host.to_string()),
                port,
                resolved_ip: None,
            }
        };

        match self.try_connect_latency(&dest).await {
            Some(elapsed) => Some(elapsed),
            None => {
                log::warn!("ssh outbound: test_latency failed, may be stale");
                None
            },
        }
    }
}
impl SshOutboundClient {
    /// Kill the process group (`sh` + children like `ssh`) by PID stored in
    /// [`Self::child_pid`]. Used from both the async retry path and the
    /// sync Drop impl without needing the Mutex.
    fn kill_process_group(pid: i32) {
        if pid <= 0 {
            return;
        }
        #[cfg(unix)]
        unsafe {
            libc::kill(-pid, libc::SIGTERM);
        }
    }

    /// Force-kill the current tunnel process group (`sh` + `ssh`) and wait
    /// for reaping. Used inside the SOCKS5-failure retry path.
    async fn kill_process(&self) {
        let pid = self.child_pid.load(Ordering::Relaxed);
        Self::kill_process_group(pid);

        let mut guard = self.process.lock().await;
        if let Some(mut child) = guard.take() {
            let _ = child.kill().await;
            let _ = child.wait().await;
        }
        self.child_pid.store(0, Ordering::Relaxed);
    }

    /// Connect to the tunnel endpoint and establish proxied TCP connection.
    async fn try_dial(
        &self, dest: &Destination,
    ) -> Result<Box<dyn StreamRelay>, Box<dyn std::error::Error>> {
        let mut stream = tokio::time::timeout(
            SSH_CONNECT_TIMEOUT,
            TcpStream::connect(self.current_addr()),
        )
        .await
        .map_err(|_| "ssh outbound: connect timeout to tunnel endpoint")?
        .map_err(|e| format!("ssh outbound: connect to tunnel endpoint: {e}"))?;

        tokio::time::timeout(
            PROXY_CONNECT_TIMEOUT,
            Self::proxy_connect(self.proxy_type, &mut stream, dest),
        )
        .await
        .map_err(|_| "ssh outbound: proxy connect timeout")?
        .map_err(|e| format!("ssh outbound: proxy connect failed: {e}"))?;

        Ok(Box::new(TcpRelay::new(stream)))
    }

    /// Connect to the tunnel endpoint and establish UDP relay (SOCKS5 only).
    async fn try_dial_udp(
        &self,
    ) -> Result<Box<dyn PacketRelay>, Box<dyn std::error::Error>> {
        if self.proxy_type == ProxyType::Http {
            return Err("HTTP CONNECT proxy does not support UDP".into());
        }

        let mut assoc_tcp = tokio::time::timeout(
            SSH_CONNECT_TIMEOUT,
            TcpStream::connect(self.current_addr()),
        )
        .await
        .map_err(|_| "ssh outbound: connect timeout for UDP ASSOCIATE")?
        .map_err(|e| format!("ssh outbound: connect for UDP ASSOCIATE: {e}"))?;

        Self::socks5_handshake(&mut assoc_tcp).await?;
        let relay_addr = Self::socks5_udp_associate(&mut assoc_tcp).await?;

        let local = UdpSocket::bind("0.0.0.0:0").await?;
        log::info!(
            "ssh outbound UDP ASSOCIATE relay={relay_addr}, local={}",
            local.local_addr()?,
        );

        Ok(Box::new(SshUdpRelay {
            assoc_tcp: Arc::new(Mutex::new(assoc_tcp)),
            relay_addr,
            local,
            last_activity: Instant::now(),
            idle_timeout: SSH_UDP_IDLE_TIMEOUT,
        }))
    }

    /// Connect and do latency measurement.
    async fn try_connect_latency(&self, dest: &Destination) -> Option<u64> {
        let start = Instant::now();
        let mut stream = tokio::time::timeout(
            Duration::from_secs(5),
            TcpStream::connect(self.current_addr()),
        )
        .await
        .ok()?
        .ok()?;

        tokio::time::timeout(
            PROXY_CONNECT_TIMEOUT,
            Self::proxy_connect(self.proxy_type, &mut stream, dest),
        )
        .await
        .ok()?
        .ok()?;

        let elapsed = start.elapsed().as_millis() as u64;
        let _ = stream
            .into_std()
            .map(|s| s.shutdown(std::net::Shutdown::Both));
        Some(elapsed)
    }
}

// Add socks5_udp_associate back — it was removed during the proxy_type
// refactor.
impl SshOutboundClient {
    /// SOCKS5 UDP ASSOCIATE. Returns the UDP relay address the server assigned.
    async fn socks5_udp_associate(
        stream: &mut TcpStream,
    ) -> io::Result<SocketAddr> {
        stream
            .write_all(&[
                0x05, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            ])
            .await?;

        let mut header = [0u8; 4];
        stream.read_exact(&mut header).await?;
        if header[1] != 0x00 {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("SOCKS5 UDP ASSOCIATE failed: rep={}", header[1]),
            ));
        }

        let atyp = header[3];
        let addr: SocketAddr = match atyp {
            0x01 => {
                let mut octets = [0u8; 4];
                stream.read_exact(&mut octets).await?;
                let mut port = [0u8; 2];
                stream.read_exact(&mut port).await?;
                SocketAddr::new(
                    std::net::IpAddr::V4(std::net::Ipv4Addr::from(octets)),
                    u16::from_be_bytes(port),
                )
            },
            0x04 => {
                let mut octets = [0u8; 16];
                stream.read_exact(&mut octets).await?;
                let mut port = [0u8; 2];
                stream.read_exact(&mut port).await?;
                SocketAddr::new(
                    std::net::IpAddr::V6(std::net::Ipv6Addr::from(octets)),
                    u16::from_be_bytes(port),
                )
            },
            0x03 => {
                let mut len = [0u8; 1];
                stream.read_exact(&mut len).await?;
                let mut name = vec![0u8; len[0] as usize];
                stream.read_exact(&mut name).await?;
                let mut port_bytes = [0u8; 2];
                stream.read_exact(&mut port_bytes).await?;
                let domain = String::from_utf8_lossy(&name);
                let port = u16::from_be_bytes(port_bytes);
                let relay_addr_str = format!("{domain}:{port}");
                crate::outbound::common::resolve_addr(&relay_addr_str).map_err(
                    |e| {
                        io::Error::new(
                            io::ErrorKind::Other,
                            format!(
                                "SOCKS5 UDP ASSOCIATE: cannot resolve relay \
                                 '{relay_addr_str}': {e}"
                            ),
                        )
                    },
                )?
            },
            _ =>
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("SOCKS5 UDP ASSOCIATE unknown ATYP: {atyp}"),
                )),
        };

        Ok(addr)
    }
}
impl Drop for SshOutboundClient {
    fn drop(&mut self) {
        let pid = self.child_pid.load(Ordering::Relaxed);
        Self::kill_process_group(pid);
        if pid > 0 {
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        // kill_on_drop(true) on the Command + dropping the Child handle
        // sends SIGKILL as the final blow.
    }
}

// ---------------------------------------------------------------------------
// SshUdpRelay
// ---------------------------------------------------------------------------

/// UDP relay backed by a SOCKS5 UDP ASSOCIATE association.
struct SshUdpRelay {
    #[allow(dead_code)] // Held open to keep the UDP ASSOCIATION alive.
    assoc_tcp: Arc<Mutex<TcpStream>>,
    /// Server-assigned UDP relay endpoint.
    relay_addr: SocketAddr,
    local: UdpSocket,
    last_activity: Instant,
    idle_timeout: Duration,
}

impl SshUdpRelay {
    fn next_deadline(&self) -> Instant {
        self.last_activity + self.idle_timeout
    }
}

#[async_trait]
impl PacketRelay for SshUdpRelay {
    async fn read_packet(
        &mut self, buf: &mut [u8],
    ) -> io::Result<(usize, Destination)> {
        loop {
            let deadline = self.next_deadline();
            let remain = deadline
                .checked_duration_since(Instant::now())
                .unwrap_or(Duration::ZERO);

            let (n, _src) =
                tokio::time::timeout(remain, self.local.recv_from(buf)).await??;

            self.last_activity = Instant::now();

            // Skip packets smaller than the SOCKS5 UDP header minimum (4 bytes
            // for RSV+FRAG+ATYP).
            if n < 4 {
                continue;
            }

            let frag = buf[2];
            if frag != 0x00 {
                // Fragmentation not supported — drop.
                continue;
            }

            let atyp = buf[3];
            let (offset, dest_addr): (usize, Address) = match atyp {
                0x01 if n >= 10 => {
                    let octets: [u8; 4] = buf[4..8].try_into().unwrap();
                    let addr = std::net::Ipv4Addr::from(octets);
                    (8, Address::Ipv4(addr.octets()))
                },
                0x04 if n >= 22 => {
                    let octets: [u8; 16] = buf[4..20].try_into().unwrap();
                    let addr = std::net::Ipv6Addr::from(octets);
                    (20, Address::Ipv6(addr.octets()))
                },
                0x03 if n >= 5 + buf[4] as usize + 2 => {
                    let dlen = buf[4] as usize;
                    let domain =
                        String::from_utf8_lossy(&buf[5..5 + dlen]).to_string();
                    (5 + dlen, Address::Domain(domain))
                },
                _ => continue,
            };

            let port = u16::from_be_bytes([buf[offset], buf[offset + 1]]);
            let payload_start = offset + 2;

            // Shift payload to start of buf.
            buf.copy_within(payload_start..n, 0);
            let payload_len = n - payload_start;

            return Ok((payload_len, Destination {
                address: dest_addr,
                port,
                resolved_ip: None,
            }));
        }
    }

    async fn write_packet(
        &mut self, buf: &[u8], dest: &Destination,
    ) -> io::Result<()> {
        self.last_activity = Instant::now();

        // Build SOCKS5 UDP request header.
        let mut pkt = Vec::with_capacity(64);
        pkt.extend_from_slice(&[0x00, 0x00, 0x00]); // RSV + FRAG
        match &dest.address {
            Address::Ipv4(o) => {
                pkt.push(0x01);
                pkt.extend_from_slice(o);
            },
            Address::Ipv6(o) => {
                pkt.push(0x04);
                pkt.extend_from_slice(o);
            },
            Address::Domain(d) => {
                pkt.push(0x03);
                pkt.push(d.len() as u8);
                pkt.extend_from_slice(d.as_bytes());
            },
        }
        pkt.extend_from_slice(&dest.port.to_be_bytes());
        pkt.extend_from_slice(buf);

        self.local.send_to(&pkt, self.relay_addr).await?;
        Ok(())
    }

    async fn close(&mut self) -> io::Result<()> {
        // Drop the UDP socket; the association TCP will be dropped when
        // SshUdpRelay itself is dropped.
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::OutboundConfig;

    #[tokio::test]
    async fn test_from_config_missing_cmd() {
        let cfg = OutboundConfig {
            type_: "ssh".into(),
            tag: Some("test".into()),
            server: Some("127.0.0.1:1080".into()),
            cmd: None,
            proxy_type: None,
            password: None,
            sni: None,
            fp: false,
            ech_config: None,
            outbounds: None,
            interval: None,
            url: None,
            mux: false,
            insecure: false,
            transport_type: None,
            transport_path: None,
            transport_headers: None,
        };
        assert!(SshOutboundClient::from_config(&cfg).await.is_err());
    }

    #[tokio::test]
    async fn test_from_config_missing_server() {
        let cfg = OutboundConfig {
            type_: "ssh".into(),
            tag: Some("test".into()),
            server: None,
            cmd: Some("ssh -D 1080 -N host".into()),
            proxy_type: None,
            password: None,
            sni: None,
            fp: false,
            ech_config: None,
            outbounds: None,
            interval: None,
            url: None,
            mux: false,
            insecure: false,
            transport_type: None,
            transport_path: None,
            transport_headers: None,
        };
        assert!(SshOutboundClient::from_config(&cfg).await.is_err());
    }

    #[tokio::test]
    async fn test_from_config_ok() {
        let cfg = OutboundConfig {
            type_: "ssh".into(),
            tag: Some("test".into()),
            server: Some("127.0.0.1:1080".into()),
            cmd: Some("true".into()), // exits immediately, port won't come up
            proxy_type: None,
            password: None,
            sni: None,
            fp: false,
            ech_config: None,
            outbounds: None,
            interval: None,
            url: None,
            mux: false,
            insecure: false,
            transport_type: None,
            transport_path: None,
            transport_headers: None,
        };
        // from_config does NOT fail on spawn failure or port timeout — it
        // logs a warning and returns the client.
        let client = SshOutboundClient::from_config(&cfg).await.unwrap();
        assert_eq!(client.local_ip.to_string(), "127.0.0.1");
        assert_eq!(
            client
                .allocated_port
                .load(std::sync::atomic::Ordering::Relaxed),
            1080,
        );
    }
}
