//! 连接管理层接口
//!
//! 职责：创建、池化、回收传输会话
//! M6: AsymmetricConnectionManager for stream-up/packet-up.
pub mod asymmetric;
pub mod pool;
pub mod reconnect;
use async_trait::async_trait;

use crate::transport::TransportSession;

/// 连接管理器接口
#[async_trait]
pub trait ConnectionManager: Send + Sync {
    /// 获取一条可用的传输会话（上行）
    async fn acquire_uplink(
        &self,
    ) -> Result<Box<dyn TransportSession>, ConnError>;
    /// 获取一条可用的传输会话（下行）
    async fn acquire_downlink(
        &self,
    ) -> Result<Box<dyn TransportSession>, ConnError>;
    /// 释放一条传输会话
    async fn release(&self, session: Box<dyn TransportSession>);
    /// 健康检查
    fn is_healthy(&self) -> bool;
    /// 强制关闭所有连接
    async fn shutdown(&self);
}

#[allow(dead_code)]
#[derive(Debug)]
pub enum ConnError {
    NoAvailable,
    CreateFailed(String),
    Closed,
}

impl std::fmt::Display for ConnError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoAvailable => write!(f, "no available connection"),
            Self::CreateFailed(s) => write!(f, "create failed: {s}"),
            Self::Closed => write!(f, "connection closed"),
        }
    }
}

impl std::error::Error for ConnError {}

// ---------------------------------------------------------------------------
// SingleConnectionManager - one session per acquire (no pooling)
// ---------------------------------------------------------------------------

use crate::transport::{TransportContext, TransportFactory};

/// Simple connection manager: creates a new session on each `acquire_*()`.
///
/// Used by mless over WS (backward compat) and any transport that doesn't
/// need connection pooling. Each call to `acquire_uplink()` invokes the
/// factory to create a fresh `TransportSession`.
#[allow(dead_code)]
pub struct SingleConnectionManager {
    factory: Box<dyn TransportFactory>,
    ctx: TransportContext,
}

#[allow(dead_code)]
impl SingleConnectionManager {
    pub fn new(
        factory: Box<dyn TransportFactory>, ctx: TransportContext,
    ) -> Self {
        Self { factory, ctx }
    }
}

#[async_trait]
impl ConnectionManager for SingleConnectionManager {
    async fn acquire_uplink(
        &self,
    ) -> Result<Box<dyn TransportSession>, ConnError> {
        self.factory
            .create(&self.ctx)
            .await
            .map_err(|e| ConnError::CreateFailed(e.to_string()))
    }

    async fn acquire_downlink(
        &self,
    ) -> Result<Box<dyn TransportSession>, ConnError> {
        self.acquire_uplink().await
    }

    async fn release(&self, _session: Box<dyn TransportSession>) {}

    fn is_healthy(&self) -> bool {
        true
    }

    async fn shutdown(&self) {}
}
