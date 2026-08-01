# XHTTP 可插拔传输架构设计

> **版本**: v1.0 - 2026-08-01
> **状态**: M0-M6 完成，M7 文档收尾
> **基准代码**: `quiche/anywhere/`（Rust 客户端 + Hermes Workers TS 服务端）

## 1. 架构总览

XHTTP 传输层采用全面可插拔架构，每一层有独立的 trait/interface，可以单独替换、配置、组合。

```
应用层 (Inbound / Outbound)
    TUN / SOCKS5 / HTTP Proxy -> OutboundClient::dial()
协议层 (Protocol Layer)
    VLESS / mless-mux / anytls / Trojan
加密层 (Crypto Layer) [可插拔]
    Ahead-XOR (SHA-256 CTR) / AES-GCM / none
混淆层 (Obfuscation Layer) [可插拔]
    XPadding / TLS-Fragment / Noise / none
传输层 (Transport Layer) [可插拔]
    WebSocket / XHTTP (stream-one/stream-up/packet-up) / gRPC / raw
连接管理层 (Connection Manager) [可插拔]
    Single / Pool / Xmux / 非对称双池
底层网络 (Network Layer)
    TCP + TLS (BoringSSL/rustls) / QUIC
```

### 核心 Trait

| Trait | 文件 | 职责 |
|-------|------|------|
| `TransportSession` | `transport/mod.rs` | 传输会话（分离 UplinkWriter + DownlinkReader） |
| `CryptoLayer` / `CryptoFactory` | `crypto/mod.rs` | 帧级加密/解密 |
| `ObfuscationLayer` | `obfuscation/mod.rs` | 流量特征混淆 |
| `ConnectionManager` | `connection/mod.rs` | 连接池、寿命控制、自动回退 |

## 2. XHTTP 三种模式

### 2.1 stream-one（对称）

单条 HTTP POST，body = 上行数据，response body = 下行数据。

```
Client ─── POST /path/session_id (body=上行, response body=下行) ─── Server
```

- **适用场景**: 默认模式，兼容性最好
- **H2 多路复用**: 多个 stream-one 会话共享一条 H2 连接
- **配置**: `mode = "stream-one"`（或 `auto`）

### 2.2 stream-up（非对称）

上行和下行使用独立的 HTTP 请求，通过 session_id 关联。

```
Client ─── POST /path/session_id (body=上行) ───────────── Server
Client ─── GET  /path/session_id (response body=下行) ──── Server
```

- **适用场景**: 非对称 CDN（上行走 CDN-A，下行走 CDN-B）
- **独立连接池**: 上行和下行可以走完全不同的服务器/协议
- **配置**: `mode = "stream-up"`

### 2.3 packet-up（非对称 + 分片）

上行数据分割为多个短 POST，每个带 `?seq=N`，服务端按 seq 重组。

```
Client ─── POST /path/session_id?seq=0 (body=chunk0) ──── Server
Client ─── POST /path/session_id?seq=1 (body=chunk1) ──── Server
Client ─── GET  /path/session_id (response body=下行) ─── Server
```

- **适用场景**: 极端审查环境（短 POST 特征弱，不易被识别）
- **UploadQueue**: 客户端缓冲数据 -> 16KB 分块 -> seq 递增发送
- **服务端重组**: 按 seq 排序拼接
- **配置**: `mode = "packet-up"`

## 3. mless 帧协议

所有 XHTTP 模式使用与 WebSocket 相同的 mless 帧协议：

```
[varint(stream_id)][flags: 1 byte][varint(payload_len)][payload: N bytes]
```

### 帧类型

| flags | 名称 | 说明 |
|-------|------|------|
| `0x00` | DATA | 数据帧，payload 为加密后的应用数据 |
| `0x80` | FIRST | 首帧，payload = VLESS/Trojan 首包 + 初始数据 |
| `0x40` | CLOSE | 关闭帧，无 payload，关闭指定 stream |

### 加密

- **算法**: Ahead-XOR (SHA-256 CTR-like)
- **密钥派生**: `SHA-256(UUID || "anywhere-obfuscation-v1")` -> 32 字节
- **加密**: `ciphertext[i] = plaintext[i] XOR SHA-256(key || counter_LE64)[i % 32]`
- **计数器**: send_counter / recv_counter 独立递增，从 0 开始
- **帧头不加密**: 只有 payload 被加密，帧头（stream_id, flags, length）明文传输

### 数据流

```
客户端上行:
  send_data(plaintext) -> MlessMessage::Data -> channel
  io_loop: channel -> crypto.encrypt() -> encode_frame() -> uplink.write()

客户端下行:
  io_loop: downlink.read() -> decode_frame() -> crypto.decrypt() -> on_frame(plaintext)
  on_frame -> stream channel -> MlessStreamRelay::read()
```

## 4. 可插拔配置

### 4.1 客户端配置（当前格式，扁平字段）

```toml
[[outbound]]
type = "mless"
server = "example.com:443"
password = "00000000-0000-4000-8000-000000000000"

# 传输类型: ws / xhttp
transport_type = "xhttp"
transport_path = "/xhttp"
transport_headers = { Host = "example.com" }

# TLS
insecure = false
fp = true          # BoringSSL Chrome 指纹
tls_fragment = true # TLS ClientHello 分片
```

### 4.2 XHTTP 高级配置（通过代码 API）

```rust
XhttpConfig {
    host: "example.com".to_string(),
    port: 443,
    path: "/xhttp".to_string(),
    mode: XhttpMode::StreamOne,  // StreamOne / StreamUp / PacketUp
    http_version: HttpVersionPref::Http2,
    insecure: false,
    session_id_placement: SessionPlacement::Path,  // Path / Query / Header / Cookie
    padding: Some(XPaddingConfig::default()),       // XPadding 配置
    // 非对称配置 (M6)
    uplink: None,      // Option<XhttpDirectionConfig>
    downlink: None,    // Option<XhttpDirectionConfig>
    // 节流 (M6 packet-up)
    sc_max_each_post_bytes: None,  // Option<Range>
    sc_min_posts_interval_ms: None,
    // ...
}
```

### 4.3 服务端配置

服务端自动检测，无需显式配置：
- **协议**: 从首包自动识别 VLESS / Trojan
- **加密**: 始终使用 AheadXor + UUID
- **XPadding**: 从 Referer / X-Padding header 自动检测
- **模式**: 从请求方法推断（POST = 上行，GET = 下行）

## 5. 迁移指南

### 5.1 从旧 XHTTP 协议迁移

**旧协议**（M5 之前）: XHTTP 传输直接读取原始 VLESS/Trojan 数据，无 mless 帧、无加密。

**新协议**（M5 之后）: XHTTP 传输使用 mless 帧协议 + AheadXor 加密，与 WebSocket 一致。

**迁移步骤**:

1. **服务端**: 部署 M5 重写后的 `transport-xhttp.ts`（自动支持新协议）
2. **客户端**: 更新到 M4 版本（`from_config` 支持 `transport_type = "xhttp"`）
3. **配置**: 无需修改（`transport_type = "xhttp"` 自动使用新协议）
4. **回滚**: 降级服务端到 M5 之前的版本，客户端降级到 M4 之前的版本

**注意**: 新旧协议不兼容。服务端和客户端必须同时升级。

### 5.2 从 WebSocket 迁移到 XHTTP

```toml
# 之前 (WebSocket)
transport_type = "ws"
transport_path = "/ws"

# 之后 (XHTTP stream-one)
transport_type = "xhttp"
transport_path = "/xhttp"
```

XHTTP 优势:
- H2 多路复用（多个会话共享一条 TCP+TLS 连接）
- 更好的 CDN 兼容性（标准 HTTP POST，不需要 WebSocket upgrade）
- 支持 XPadding（流量大小混淆）
- 支持非对称模式（stream-up / packet-up）

### 5.3 切换到 stream-up / packet-up

```toml
# stream-up: 上下行分离
transport_type = "xhttp"
# 需要通过代码 API 设置 mode = StreamUp

# packet-up: 上行分片
transport_type = "xhttp"
# 需要通过代码 API 设置 mode = PacketUp
```

**注意**: stream-up/packet-up 需要服务端 session 管理支持（M6 服务端，需部署环境验证）。

## 6. 性能特性

### 6.1 各模式对比

| 维度 | stream-one | stream-up | packet-up |
|------|-----------|-----------|-----------|
| HTTP 请求数 | 1 (POST) | 2 (POST+GET) | N+1 (N×POST+GET) |
| H2 流复用 | ✅ 多会话共享 | ✅ | ✅ |
| CDN 非对称 | ❌ | ✅ | ✅ |
| 审查对抗 | 中 | 高 | 极高 |
| 延迟 | 最低 | 中 | 高（分片开销） |
| 吞吐量 | 最高 | 高 | 中（每 POST 有 HTTP 开销） |

### 6.2 性能优化建议

- **默认用 stream-one**: 最低延迟，最高吞吐量
- **CDN 优化用 stream-up**: 上行走近端 CDN，下行走远端 CDN
- **极端审查用 packet-up**: 短 POST 特征弱，但吞吐量有损失
- **H2 连接复用**: `XmuxConnectionManager` 自动管理 H2 连接池
- **XPadding**: 开启后增加 100-1000 字节/请求的开销，但显著降低流量大小可预测性

### 6.3 基准测试方法

```bash
# 1. 启动测试服务器
# （需要部署 Hermes Workers 或本地 mock 服务器）

# 2. 运行吞吐量测试
cargo test --lib transport::xhttp::tests::stream_one_large_data -- --nocapture
cargo test --lib transport::xhttp::tests::packet_up_multiple_posts -- --nocapture

# 3. 对比各模式延迟
# stream-one: 1 RTT (POST + response)
# stream-up: 2 RTT (POST + GET)
# packet-up: N RTT (N × POST) + 1 RTT (GET)
```

### 6.4 已知限制

- **H3 未实现**: 当前全模式使用 H2。H3 (QUIC) 可降低连接建立延迟，但实现量大，延期处理
- **服务端 session 管理**: stream-up/packet-up 需要跨请求状态，依赖 Cloudflare Workers DO 或模块级 Map
- **download_queue**: downlink 为单条 GET 长连接，无需重排。如未来支持多 GET 响应，需添加

## 7. 测试覆盖

| 层级 | 测试数 | 覆盖范围 |
|------|--------|----------|
| Obfuscation (M0-M2) | 57 | HPACK, XPadding, Fragment, Jitter, Noise, Range |
| XHTTP Transport (M3) | 41 | config, placement, padding, fallback, h2, xmux, stream-one |
| mless Integration (M4) | 2 | E2E echo + multi-frame over XHTTP |
| stream-up/packet-up (M6) | 15 | UploadQueue, Asymmetric, stream-up echo, packet-up 32KB |
| **总计** | **277** | 全部通过，0 回归 |

## 8. 文件结构

```
src/
├── transport/
│   ├── mod.rs                    # TransportSession / UplinkWriter / DownlinkReader
│   ├── ws.rs                     # WsTransportSession + WsTransportFactory
│   └── xhttp/
│       ├── mod.rs                # XhttpSession (3 modes) + PacketUplinkWriter
│       ├── config.rs             # XhttpConfig / XhttpMode / SessionPlacement
│       ├── h2.rs                 # H2 client (TLS + ALPN h2) + ChannelBody
│       ├── placement.rs          # session_id / seq 放置 (path/query/header/cookie)
│       ├── padding.rs            # XPaddingMiddleware
│       ├── fallback.rs           # HTTP 版本回退 (H2 -> H1)
│       ├── xmux.rs               # XmuxConnectionManager (H2 连接池)
│       └── upload_queue.rs       # UploadQueue (packet-up 分块 + seq)
├── crypto/
│   └── mod.rs                    # CryptoLayer / CryptoFactory / NoCrypto
├── obfuscation/
│   ├── mod.rs                    # ObfuscationLayer / ObfContext
│   ├── padding.rs                # XPadding (HPACK + repeat-x + tokenish)
│   ├── fragment.rs               # TLS Fragment (SNI 分片)
│   ├── jitter.rs                 # TimingJitter / SizeJitter / ConnBehaviorJitter
│   ├── noise.rs                  # UDP 噪声注入
│   └── range.rs                  # Range / SegmentRange (CSPRNG)
├── connection/
│   ├── mod.rs                    # ConnectionManager / SingleConnectionManager
│   └── asymmetric.rs             # AsymmetricConnectionManager (双池)
└── outbound/mless/
    ├── mod.rs                    # MlessOutboundClient (可插拔组装)
    ├── multiplexer.rs            # MlessMultiplexer (async io_loop + MlessMessage)
    ├── crypto.rs                 # Obfuscation + AheadXorFactory
    ├── frame.rs                  # mless 帧编解码 (QUIC varint)
    └── vless.rs                  # VLESS 首包构建
```
