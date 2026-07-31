//! 连接管理层接口
//!
//! 职责：创建、池化、回收传输会话
//! M0 阶段：仅定义 trait，现有 vless Pool 和 mless MlessMultiplexer 不适配此 trait

use async_trait::async_trait;

use crate::transport::TransportSession;

/// 连接管理器接口
#[allow(dead_code)]
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

/// 连接管理错误（M0 定义但不使用）
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
