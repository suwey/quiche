pub mod ws;
pub mod xhttp;

use std::collections::HashMap;
use std::io;

use async_trait::async_trait;

// ========== 传输层 Trait ==========

/// 上行写入器：把数据写到远端
#[async_trait]
pub trait UplinkWriter: Send {
    async fn write(&mut self, data: &[u8]) -> io::Result<()>;
    async fn shutdown(&mut self) -> io::Result<()>;
}

/// 下行读取器：从远端读数据
#[async_trait]
pub trait DownlinkReader: Send {
    async fn read(&mut self, buf: &mut [u8]) -> io::Result<usize>;
}

/// 传输会话：一条逻辑连接
///
/// 对称传输（WS、stream-one）：uplink 和 downlink 共享同一条连接
/// 非对称传输（stream-up、packet-up）：uplink 和 downlink 是独立连接
///
/// M0 阶段：仅定义，不创建新实现。WsTransportSession 适配现有 WsStream。
#[async_trait]
pub trait TransportSession: Send {
    /// 获取上行写入器
    async fn uplink(&mut self) -> io::Result<Box<dyn UplinkWriter>>;
    /// 获取下行读取器
    async fn downlink(&mut self) -> io::Result<Box<dyn DownlinkReader>>;
    /// 关闭整个会话
    async fn close(&mut self) -> io::Result<()>;
    /// 传输类型标识（用于日志/诊断）
    fn kind(&self) -> &'static str;
}

/// 传输创建上下文
#[derive(Clone)]
pub struct TransportContext {
    pub server: String,
    pub port: u16,
    pub tls_server: String,
    pub insecure: bool,
    pub tls_fp: bool,
    pub path: String,
    pub headers: HashMap<String, String>,
    pub fragment: Option<crate::tlsfragment::FragmentConfig>,
}

/// 传输层工厂 trait（M0 定义但不使用）
#[allow(dead_code)]
#[async_trait]
pub trait TransportFactory: Send + Sync {
    async fn create(
        &self,
        ctx: &TransportContext,
    ) -> Result<Box<dyn TransportSession>, TransportError>;

    fn supports_asymmetric(&self) -> bool {
        false
    }
}

/// 传输层错误（M0 定义但不使用）
#[allow(dead_code)]
#[derive(Debug)]
pub enum TransportError {
    Connect(String),
    Tls(String),
    Upgrade(String),
    Io(io::Error),
}

impl std::fmt::Display for TransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Connect(s) => write!(f, "connect: {s}"),
            Self::Tls(s) => write!(f, "tls: {s}"),
            Self::Upgrade(s) => write!(f, "upgrade: {s}"),
            Self::Io(e) => write!(f, "io: {e}"),
        }
    }
}

impl std::error::Error for TransportError {}

impl From<io::Error> for TransportError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}
