//! 加密层接口
//!
//! 位置：协议层和传输层之间
//! 输入：协议层编码后的明文帧
//! 输出：密文，交给传输层发送
//!
//! NOTE: `NoCrypto` is a design-time placeholder, never used.
//! `CryptoFactory` trait is live (used by mless's `AheadXorFactory`).

use async_trait::async_trait;
use std::io;

/// 加密层接口
#[async_trait]
pub trait CryptoLayer: Send {
    /// 加密上行数据
    async fn encrypt(&mut self, plaintext: &[u8]) -> io::Result<Vec<u8>>;
    /// 解密下行数据
    async fn decrypt(&mut self, ciphertext: &[u8]) -> io::Result<Vec<u8>>;
    /// 重置加密状态（用于重连）
    fn reset(&mut self);
}

/// 加密层工厂 trait（M0 定义但不使用）
#[allow(dead_code)]
pub trait CryptoFactory: Send + Sync {
    fn create(&self, secret: &str) -> Box<dyn CryptoLayer>;
    fn name(&self) -> &'static str;
}

/// 无加密透传（M0 定义但不使用）
#[allow(dead_code)]
pub struct NoCrypto;

#[allow(dead_code)]
#[async_trait]
impl CryptoLayer for NoCrypto {
    async fn encrypt(&mut self, p: &[u8]) -> io::Result<Vec<u8>> {
        Ok(p.to_vec())
    }
    async fn decrypt(&mut self, c: &[u8]) -> io::Result<Vec<u8>> {
        Ok(c.to_vec())
    }
    fn reset(&mut self) {}
}
