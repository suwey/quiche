// SPDX-License-Identifier: BSD-2-Clause
// Copyright © The anywhere project contributors.

//! Shadowsocks 2022 (AEAD-2022) outbound.
//!
//! 仅支持 SS2022 加密方法：
//! - 2022-blake3-aes-128-gcm
//! - 2022-blake3-aes-256-gcm
//! - 2022-blake3-chacha20-poly1305
//!
//! 可选 SIP003 插件：obfs-local (http/tls 混淆)。

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};

use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;

use crate::config::OutboundConfig;
use crate::inbound::Address;
use crate::inbound::Destination;
use crate::outbound::OutboundClient;
use crate::relay::PacketRelay;
use crate::relay::StreamRelay;

pub mod cipher;
pub mod packet;
pub mod plugin;
pub mod socks;
pub mod stream;

use cipher::CipherMethod;

/// 统一连接类型：裸 TCP 或 obfs 包装。
enum SsConn {
    Plain(TcpStream),
    Obfs(plugin::ObfsConn),
}

impl AsyncRead for SsConn {
    fn poll_read(
        self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            SsConn::Plain(c) => Pin::new(c).poll_read(cx, buf),
            SsConn::Obfs(c) => Pin::new(c).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for SsConn {
    fn poll_write(
        self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            SsConn::Plain(c) => Pin::new(c).poll_write(cx, buf),
            SsConn::Obfs(c) => Pin::new(c).poll_write(cx, buf),
        }
    }

    fn poll_flush(
        self: Pin<&mut Self>, cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            SsConn::Plain(c) => Pin::new(c).poll_flush(cx),
            SsConn::Obfs(c) => Pin::new(c).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        self: Pin<&mut Self>, cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            SsConn::Plain(c) => Pin::new(c).poll_shutdown(cx),
            SsConn::Obfs(c) => Pin::new(c).poll_shutdown(cx),
        }
    }
}


/// Shadowsocks 2022 outbound client.
///
/// 连接远端 SS2022 服务器，通过 `SsTcpStream` (TCP) 和 `SsUdpRelay` (UDP)
/// 提供代理。加密握手延迟到首次 read/write 时执行（early conn 模式）。
/// 可选 SIP003 插件 (obfs-local) 在 TCP 连接上做额外混淆。
pub struct ShadowsocksOutboundClient {
    method: CipherMethod,
    server_addr: SocketAddr,
    /// 可选 SIP003 插件配置。
    obfs_plugin: Option<plugin::ObfsPlugin>,
    /// Tunnel UDP over the SS TCP stream (for servers without UDP relay).
    uot: bool,
}

impl ShadowsocksOutboundClient {
    pub async fn from_config(
        cfg: &OutboundConfig,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let server =
            cfg.server.as_deref().ok_or("shadowsocks: missing server")?;
        let method_str =
            cfg.method.as_deref().ok_or("shadowsocks: missing method")?;
        let password =
            cfg.password.as_deref().ok_or("shadowsocks: missing password")?;

        let method = CipherMethod::new(method_str, password)
            .map_err(|e| format!("shadowsocks: {e}"))?;
        let server_addr = crate::outbound::common::resolve_addr(server)
            .map_err(|e| format!("shadowsocks: {e}"))?;

        let obfs_plugin = match &cfg.plugin {
            Some(name) => Some(plugin::ObfsPlugin::parse(
                name,
                cfg.plugin_opts.as_deref().unwrap_or(""),
                server_addr.port(),
            )
            .map_err(|e| format!("shadowsocks: {e}"))?),
            None => None,
        };

        Ok(Self { method, server_addr, obfs_plugin, uot: cfg.uot })
    }

    /// UDP-over-TCP: open a SS TCP stream to the UoT magic address, send the
    /// UoT request (bundled as SS early data), and wrap as a `PacketRelay`.
    /// Used when the server has no UDP relay (`uot = true`).
    async fn dial_udp_uot(
        &self, initial_dest: &Destination,
    ) -> Result<Box<dyn PacketRelay>, Box<dyn std::error::Error>> {
        use crate::protocol::uot::{self, UotPacketRelay};

        let tcp =
            crate::outbound::common::connect_tcp_bypass(self.server_addr)
                .await?;
        let conn = match &self.obfs_plugin {
            Some(p) => SsConn::Obfs(p.wrap(tcp)),
            None => SsConn::Plain(tcp),
        };
        // SS dials the magic FQDN; a UoT-aware server switches to UDP relay.
        let magic = Destination::new(
            Address::Domain(uot::UOT_MAGIC_ADDRESS.to_string()),
            443,
        );
        let mut stream =
            stream::SsTcpStream::new(conn, self.method.clone(), magic);
        let req = uot::encode_request(false, initial_dest)?;
        stream.write(&req).await?;
        Ok(Box::new(UotPacketRelay::new(stream)))
    }
}

#[async_trait]
impl OutboundClient for ShadowsocksOutboundClient {
    async fn dial(
        &self, dest: &Destination,
    ) -> Result<Box<dyn StreamRelay>, Box<dyn std::error::Error>> {
        let tcp =
            crate::outbound::common::connect_tcp_bypass(self.server_addr)
                .await?;
        let conn = match &self.obfs_plugin {
            Some(p) => SsConn::Obfs(p.wrap(tcp)),
            None => SsConn::Plain(tcp),
        };
        Ok(Box::new(stream::SsTcpStream::new(
            conn,
            self.method.clone(),
            dest.clone(),
        )))
    }

    async fn dial_udp(
        &self, initial_dest: &Destination,
    ) -> Result<Box<dyn PacketRelay>, Box<dyn std::error::Error>> {
        if self.uot {
            return self.dial_udp_uot(initial_dest).await;
        }
        let bind_addr: SocketAddr = match self.server_addr {
            SocketAddr::V4(_) => "0.0.0.0:0".parse().unwrap(),
            SocketAddr::V6(_) => "[::]:0".parse().unwrap(),
        };
        let socket =
            crate::outbound::common::bind_udp_bypass(bind_addr).await?;
        socket.connect(self.server_addr).await?;
        Ok(Box::new(packet::SsUdpRelay::new(
            socket,
            self.method.clone(),
        )))
    }
}
