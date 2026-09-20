# sing-box 对齐调整计划

> 背景与逐项依据原见 `docs/sing-box-comparison.md`（已删除，可操作结论已并入本文档）。
> REALITY/Vision 协议依据为 xray-core 与 metacubex/utls 源码（~/xray-core、
> ~/workspaces/go/pkg/mod/github.com/metacubex/utls@*），代码内注释含 file:line；
> 摸底文档 reality-vision-plan.md 已删除（结论并入本文档与代码注释）。

## 0. 已决议事项

### 0.1 boring-sys 补丁追认（`reality-server-sigalg.patch`）

**结论：保留。** 关键事实（已逐字节验证）：

- REALITY 生态服务端（xray 的 xtls/reality fork、sing-box 的 metacubex/utls RealityConfig）都强制用
  Ed25519 签 CertificateVerify，无视客户端通告（utls `reality.go:258`）。
- 两家客户端的 utls chrome 指纹 sigalgs **逐字节一致且都不含 ed25519**（metacubex/utls v1.8.4 与
  refraction-networking/utls v1.8.3 的 `u_common.go:296`，均无 0x0807）。
- 因此不打补丁时：anywhere 自家客户端可连（显式通告 ed25519，`reality.rs:230-241`），
  **xray 与 sing-box 客户端握手必死于 NO_COMMON_SIGNATURE_ALGORITHMS**（xray 已实证）。
- 替代方案不成立：一次性证书是 Ed25519 格式 + HMAC 覆写尾部，三家客户端验证逻辑均硬编码；
  手动记录层握手是"阶段 3"量级。
- 补丁风险面：per-SSL 标志、默认关闭、仅 REALITY 服务端路径；对 anytls / 普通 TLS / QUIC 零影响。
  被绕过的"客户端 sigalgs 交集"在 REALITY 信任模型中不承担安全职责（身份由 session_id AEAD
  认证 + 证书 HMAC 绑定建立）。

## 1. 本次实施（已批准）

### 1.1 REALITY `min_client_ver` 默认放开

- **问题**：服务端默认下限 `[26,3,27]`（抄 xray 默认），sing-box 客户端上报自家版本 `{1,8,1}`
  （`reality_client.go:184-190`）被默认拒绝。xray 默认同样拒 sing-box，属"生态默认值碰撞"，
  但 anywhere 改默认值即恢复互通。
- **改动**：`transport/reality_server.rs`（默认值来源约 :81-84,:509-512，校验 :648-654）——
  默认**不限制**版本；配置显式设置 `min_client_ver` 时仍照常校验。相应调整单测断言，
  `config/vless-reality-server.toml` 注释补充该字段说明。
- **验收**：新增/调整单测覆盖"默认放行 + 配置后拦截"；`tests/vless_reality.rs` 全绿。

### 1.2 anytls 服务端下发 `CMD_UPDATE_PADDING_SCHEME`

- **问题**：inbound 在 `CMD_SETTINGS` 处理中对 client/server md5 不一致只做了占位
  （`inbound/anytls.rs` 原 :414-426 TODO），自定义 `padding_scheme` 对客户端方向不生效。
  sing-anytls 服务端会下发（sing-anytls `session.go:271-283`）。
- **改动**：`inbound/anytls.rs`——以服务端**实际生效**的 scheme 原文（配置的
  `padding_scheme`，缺省为 `DEFAULT_PADDING_SCHEME`）计算 md5；与 client 上报的
  `padding-md5` 不一致时，将 `CMD_UPDATE_PADDING_SCHEME(stream_id=0, data=方案原文)`
  入 outbound 队列（沿用 `OutboundMsg::RawFrame` 路径，写出去时按 pkt_counter 计数）。
  注意 `PaddingFactory` 不保留原文，需把方案原文传入会话（构造时一并传递）。
- **验收**：单测覆盖 md5 比较与帧构造；e2e：anytls_loopback 增加用例——服务端配置自定义
  `padding_scheme`，客户端（outbound）收到 update 后中继流量正常（outbound 已实现
  update 处理，会更新进程级 PaddingCache）。

## 2. 延后项（已决策，记录在案）

### 2.1 vless command 0x03（XUDP / multiplex）——决策：延后

sing-box 客户端默认 UDP 走 xudp(0x03)、multiplex 也走 0x03，anywhere 仅实现 0x02。
**临时互通约束（写入 vless-server.toml 注释）**：sing-box 客户端侧需配置
`packet_encoding = "packetaddr"`（走 0x02）且不启用 multiplex。
实现 XUDP 为独立立项（量级：帧格式 + 会话管理 + 与 mux 的关系梳理）。
仅当"sing-box 客户端零配置接入"成为产品目标时再排期。

### 2.2 UoT `isConnect=true` 流模式——决策：不做

sing `common/uot/client.go:51-77` 的流模式（TCP over UoT）anywhere 服务端不支持；
自家客户端只用 associate 模式，sing 生态客户端亦可用 associate 模式互通。无实际收益。

### 2.3 回退限速（utls LimitFallback）——决策：不做

回退路径只转发到固定 dest，非开放代理；滥用面仅限带宽占用与 dest 端信誉风险。
如需加固，优先考虑更简单的每 IP 连接数限制。

### 2.4 阶段 3：REALITY 字节保真——可选，排最后

ServerHello 借用 / 逐记录长度填充 / 假 NST 合成（utls `conn.go:532-549`）。
不影响互通与主动探测防御（已实现），只影响被动 DPI 在持有该 SNI 正常流量基线时的
指纹区分能力（GFW 级对手才有此能力）。若立项，顺带补 NO_TICKET 的 NST 缺口。

## 3. 知识存档（comparison 文档删除后易失的结论）

- anytls：帧/认证/SETTINGS/SYNACK/padding 算法与 sing-anytls 一致，双向互通；
  服务端 dial 失败无错误通知（行为差异，P3）。
- vless TCP/vision：请求头、响应头位置、Vision 帧与 xray/sing-box 三方一致，双向互通。
- vless UDP：anywhere(0x02) ↔ sing-box(0x02 packetaddr) 互通。
- REALITY：session_id 认证布局/KDF/AAD、一次性证书 HMAC、校验顺序与两家客户端一致；
  sing-box 客户端反而删掉了 MLKEM768 share 只留 x25519（`reality_client.go:146-158`），
  anywhere 两分支都支持。
- anywhere REALITY 回退比生态多 30s peek 超时 + 64KB 上限（加固项）；回退限速缺失（P3）。
- mless：自有协议，内层 vless 请求头与 sing-box 逐字节一致；帧/混淆层自有。
- 已知理论弱点（与 xray 相同）：Vision 首 UUID 帧门要求请求头后首个解密块 ≥21B 且以
  UUID 开头，依赖客户端 header+首帧同 record 写出。
