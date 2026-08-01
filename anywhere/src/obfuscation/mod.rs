//! 混淆层接口
//!
//! 混淆层不修改数据内容，只修改数据的外在特征（大小、时序、头部）

use std::io;
use async_trait::async_trait;

pub mod fragment;
pub mod jitter;
pub mod noise;
pub mod padding;
pub mod range;

/// 混淆层接口
#[async_trait]
pub trait ObfuscationLayer: Send {
    /// 在上行数据发送前调用
    async fn pre_send(
        &mut self,
        data: &[u8],
        ctx: &ObfContext<'_>,
    ) -> io::Result<Vec<u8>>;
    /// 在下行数据接收后调用
    async fn post_recv(
        &mut self,
        data: &[u8],
        ctx: &ObfContext<'_>,
    ) -> io::Result<Vec<u8>>;
    /// 此混淆层是否需要 HTTP 请求上下文
    #[allow(dead_code)]
    fn needs_http_ctx(&self) -> bool {
        false
    }
    fn name(&self) -> &'static str;
}

/// 混淆上下文：传递跨层信息
#[allow(dead_code)]
pub struct ObfContext<'a> {
    /// 当前 HTTP 请求的 URL（XPadding 用）
    pub request_url: Option<&'a str>,
    /// 当前是首包还是后续包
    pub is_first: bool,
    /// 当前包序号（packet-up 模式）
    pub seq: Option<u64>,
    /// HTTP 响应头（下行 padding 校验用）
    pub response_headers: Option<&'a http::HeaderMap>,
}

/// 混淆链（M0 定义但不使用）
#[allow(dead_code)]
pub struct ObfuscationChain {
    layers: Vec<Box<dyn ObfuscationLayer>>,
}
