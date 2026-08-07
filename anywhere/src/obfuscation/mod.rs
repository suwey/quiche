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
    fn needs_http_ctx(&self) -> bool {
        false
    }
    fn name(&self) -> &'static str;
}

/// 混淆上下文：传递跨层信息
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

/// 混淆链：按顺序串联多个混淆层。
///
/// `pre_send` 按添加顺序正向执行，`post_recv` 按相反顺序执行，
/// 保证数据经过对称的混淆/解混淆处理。
pub struct ObfuscationChain {
    layers: Vec<Box<dyn ObfuscationLayer>>,
}

impl ObfuscationChain {
    /// 创建空的混淆链。
    pub fn new() -> Self {
        Self { layers: Vec::new() }
    }

    /// 追加一个混淆层，返回 `self` 以支持链式调用。
    pub fn with_layer(mut self, layer: Box<dyn ObfuscationLayer>) -> Self {
        self.layers.push(layer);
        self
    }

    /// 是否没有任何混淆层。
    pub fn is_empty(&self) -> bool {
        self.layers.is_empty()
    }

    /// 混淆层数量。
    pub fn len(&self) -> usize {
        self.layers.len()
    }

    /// 上行发送前：按添加顺序正向依次执行各层的 `pre_send`。
    pub async fn pre_send(&mut self, data: &[u8], ctx: &ObfContext<'_>) -> io::Result<Vec<u8>> {
        let mut buf = data.to_vec();
        for layer in &mut self.layers {
            buf = layer.pre_send(&buf, ctx).await?;
        }
        Ok(buf)
    }

    /// 下行接收后：按添加顺序逆序依次执行各层的 `post_recv`。
    pub async fn post_recv(&mut self, data: &[u8], ctx: &ObfContext<'_>) -> io::Result<Vec<u8>> {
        let mut buf = data.to_vec();
        for layer in self.layers.iter_mut().rev() {
            buf = layer.post_recv(&buf, ctx).await?;
        }
        Ok(buf)
    }
}

impl Default for ObfuscationChain {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod chain_tests {
    use super::*;

    /// 记录调用顺序的测试混淆层
    struct OrderLayer {
        name: &'static str,
        calls: Arc<Mutex<Vec<String>>>,
    }

    impl OrderLayer {
        fn new(name: &'static str, calls: Arc<Mutex<Vec<String>>>) -> Self {
            Self { name, calls }
        }
    }

    #[async_trait]
    impl ObfuscationLayer for OrderLayer {
        async fn pre_send(&mut self, data: &[u8], _ctx: &ObfContext<'_>) -> io::Result<Vec<u8>> {
            self.calls.lock().unwrap().push(format!("pre_send:{}", self.name));
            // 前缀数据以标识经过的层
            let mut out = format!("[{}]", self.name).into_bytes();
            out.extend_from_slice(data);
            Ok(out)
        }

        async fn post_recv(&mut self, data: &[u8], _ctx: &ObfContext<'_>) -> io::Result<Vec<u8>> {
            self.calls.lock().unwrap().push(format!("post_recv:{}", self.name));
            // 移除前缀以还原数据
            let prefix = format!("[{}]", self.name).into_bytes();
            if data.starts_with(&prefix) {
                Ok(data[prefix.len()..].to_vec())
            } else {
                Ok(data.to_vec())
            }
        }

        fn name(&self) -> &'static str {
            self.name
        }
    }

    use std::sync::{Arc, Mutex};

    fn make_ctx() -> ObfContext<'static> {
        ObfContext {
            request_url: None,
            is_first: true,
            seq: None,
            response_headers: None,
        }
    }

    #[tokio::test]
    async fn empty_chain_passes_through() {
        let mut chain = ObfuscationChain::new();
        assert!(chain.is_empty());
        assert_eq!(chain.len(), 0);

        let ctx = make_ctx();
        let data = b"hello";
        let sent = chain.pre_send(data, &ctx).await.unwrap();
        assert_eq!(sent, data);

        let recv = chain.post_recv(data, &ctx).await.unwrap();
        assert_eq!(recv, data);
    }

    #[tokio::test]
    async fn single_layer_roundtrip() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let mut chain = ObfuscationChain::new()
            .with_layer(Box::new(OrderLayer::new("A", calls.clone())));
        assert!(!chain.is_empty());
        assert_eq!(chain.len(), 1);

        let ctx = make_ctx();
        let original = b"payload";
        let sent = chain.pre_send(original, &ctx).await.unwrap();
        assert_eq!(sent, b"[A]payload");

        let mut chain2 = ObfuscationChain::new()
            .with_layer(Box::new(OrderLayer::new("A", calls.clone())));
        let recv = chain2.post_recv(&sent, &ctx).await.unwrap();
        assert_eq!(recv, original);
    }

    #[tokio::test]
    async fn multi_layer_pre_send_order_is_forward() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let mut chain = ObfuscationChain::new()
            .with_layer(Box::new(OrderLayer::new("L1", calls.clone())))
            .with_layer(Box::new(OrderLayer::new("L2", calls.clone())))
            .with_layer(Box::new(OrderLayer::new("L3", calls.clone())));

        let ctx = make_ctx();
        let sent = chain.pre_send(b"data", &ctx).await.unwrap();
        // L1 先执行 → [L1]data，L2 → [L2][L1]data，L3 → [L3][L2][L1]data
        assert_eq!(sent, b"[L3][L2][L1]data");

        let recorded = calls.lock().unwrap().clone();
        assert_eq!(recorded, vec!["pre_send:L1", "pre_send:L2", "pre_send:L3"]);
    }

    #[tokio::test]
    async fn multi_layer_post_recv_order_is_reverse() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let mut chain = ObfuscationChain::new()
            .with_layer(Box::new(OrderLayer::new("L1", calls.clone())))
            .with_layer(Box::new(OrderLayer::new("L2", calls.clone())))
            .with_layer(Box::new(OrderLayer::new("L3", calls.clone())));

        let ctx = make_ctx();
        // 模拟 pre_send 后的数据: [L3][L2][L1]data
        let sent = b"[L3][L2][L1]data";
        let recv = chain.post_recv(sent, &ctx).await.unwrap();
        assert_eq!(recv, b"data");

        let recorded = calls.lock().unwrap().clone();
        assert_eq!(recorded, vec!["post_recv:L3", "post_recv:L2", "post_recv:L1"]);
    }

    #[tokio::test]
    async fn full_roundtrip_multi_layer() {
        let ctx = make_ctx();
        let original = b"round-trip test";

        // pre_send
        let mut send_chain = ObfuscationChain::new()
            .with_layer(Box::new(OrderLayer::new("X", Arc::new(Mutex::new(Vec::new())))))
            .with_layer(Box::new(OrderLayer::new("Y", Arc::new(Mutex::new(Vec::new())))));
        let sent = send_chain.pre_send(original, &ctx).await.unwrap();

        // post_recv with a fresh chain (same layer order)
        let mut recv_chain = ObfuscationChain::new()
            .with_layer(Box::new(OrderLayer::new("X", Arc::new(Mutex::new(Vec::new())))))
            .with_layer(Box::new(OrderLayer::new("Y", Arc::new(Mutex::new(Vec::new())))));
        let recv = recv_chain.post_recv(&sent, &ctx).await.unwrap();

        assert_eq!(recv, original);
    }

    #[tokio::test]
    async fn default_is_empty() {
        let chain = ObfuscationChain::default();
        assert!(chain.is_empty());
        assert_eq!(chain.len(), 0);
    }
}
