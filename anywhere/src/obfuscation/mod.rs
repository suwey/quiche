//! 混淆层接口
//!
//! 混淆层不修改数据内容，只修改数据的外在特征（大小、时序、头部）

use std::io;
use async_trait::async_trait;

pub mod fragment;

/// 混淆层接口
#[async_trait]
pub trait ObfuscationLayer: Send {
    /// 在上行数据发送前调用
    async fn pre_send(
        &mut self,
        data: &[u8],
        ctx: &ObfContext,
    ) -> io::Result<Vec<u8>>;
    /// 在下行数据接收后调用
    async fn post_recv(
        &mut self,
        data: &[u8],
        ctx: &ObfContext,
    ) -> io::Result<Vec<u8>>;
    /// 此混淆层是否需要 HTTP 请求上下文
    #[allow(dead_code)]
    fn needs_http_ctx(&self) -> bool {
        false
    }
    fn name(&self) -> &'static str;
}

/// 混淆上下文（M0 定义但不使用）
#[allow(dead_code)]
pub struct ObfContext {
    pub request_url: Option<&'static str>,
    pub is_first: bool,
    pub seq: Option<u64>,
}

/// 混淆链（M0 定义但不使用）
#[allow(dead_code)]
pub struct ObfuscationChain {
    layers: Vec<Box<dyn ObfuscationLayer>>,
}
