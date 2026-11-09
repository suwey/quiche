# anywhere IPv6 支持计划

> 背景：2026-11-09 实测开发机局域网无全球 v6（en0 仅 fe80::，路由器无 RA，
> curl -6 走的是 v4-mapped 假阳性）。上世界纯 v6 的服务很少（上游 DNS 已返回
> 240e: 真记录，外部世界双栈），anywhere 的 v4-only 现状在功能上无损失；
> 真正的风险是 **v6 泄漏**——物理网口一旦获得全球 v6（路由器开 v6 / 换网络），
> Happy Eyeballs 会让应用优先走 v6 绕过 TUN。因此顺序是：先防泄漏，再补功能。

## Phase 0 — macOS v6 泄漏防护（已完成，a4302d9a）

物理接口有全球 v6（2000::/3）且隧道是 v4-only 时，装 `::/1` + `8000::/1`
**reject 路由**（RTF_REJECT，回 ICMPv6 unreachable）：应用秒级回退 v4，不泄漏、
不悬挂。RA 中途到达由 route watcher 的 RTM_NEWADDR → reconcile 路径捕获。
链路本地（fe80::/64 /64 作用域路由更精确）不受影响。配置开关
`tun.ipv6_leak_guard`（默认 true）。验证脚本：`scripts/test_v6_leak_guard.sh`
（需 sudo）。

## Phase 1 — DNS AAAA 基础层（无 TUN 依赖，先行）

**范围**：`anywhere/src/dns/wire.rs`、`dns/mod.rs`。

1. `build_aaaa_response`：参照 `build_a_response`（本就为 hosts 表改造过，
   签名收 query + ip），承载 128-bit 地址。~~上游响应透传路径若逐字节重写，
   需同步支持 AAAA 记录类型~~（Phase 1 实测：上游透传是纯字节中继，唯一改写
   是缓存命中时的 apply_txn_id，与记录类型无关，无需改动）。
2. **hosts 表放开 v6**：`parse_hosts_table` 已解析 V6 只是丢弃（日志
   "IPv6 not supported yet"）；`hosts_lookup` 返回值改为枚举 v4/v6，AAAA 查询
   命中 v6 值、A 查询命中 v4 值；`0.0.0.0` 屏蔽语义扩展 `::` 同义。
   **跨族命中答空 NOERROR**（名字在表里但值是另一族）：否则 `0.0.0.0`/`::`
   屏蔽条目会被另一族的真地址绕过——Phase 1 实现补全的语义。
3. **AAAA 查询策略（关键决策）**：
   - fake-ip 开（现状默认）：AAAA → **空 NOERROR**（0 answer），A → fake-ip
     v4。这是 sing-box/clash 同款行为，避免 v4-only fake 池下应用拿到真实
     v6 绕过代理。Phase 2 落地 fake-ip v6 池后再切真映射。
   - fake-ip 关（真解析）：AAAA 走现有 upstream 链路真解析。
     （Phase 1 代码确认：改前 fake-ip 开关两种情况下 AAAA 都是空应答——
     `resolve_query` 开头无条件短路 type 28，位于 hosts/rules/cache/fake-ip
     之前；本阶段已改为按 fake-ip 开关区分。）
4. type 65 (HTTPS/SVCB) 维持现状（proxy plan 回空）。
5. 单测：wire 层编解码往返、hosts v4/v6/屏蔽、fake-ip 模式 AAAA 空。

**验收**：cargo test 全绿；fake-ip 模式下 dig AAAA 返回 0 answer、dig A 返回
fake-ip；hosts 配 v6 值时 AAAA 返回该值。

## Phase 2 — fake-ip v6 池 + TUN v6 数据面

**范围**：`dns/`（fake-ip 池）、`inbound/tun/handler`（包解析）、平台路由。

1. fake-ip v6 池：选一个 ULA 段（建议 `fdfe:dcba:9876::/64`，sing-box 惯例，
   便于对齐调试），A/AAAA 共享一张映射表（key: 域名 → {v4, v6} 或双向表
   分开），restore 路径（`TUN restore domain`）支持 v6 key。
2. tun handler：IPv6 包头解析（现有 v4 解析点扩展：固定 40B 头，无选项时
   直接取 dst），v6 目标命中 fake-ip 池 → 还原域名；UDP/53 over v6 同样劫持。
3. macOS platform：TUN 配 v6 地址（Phase 2 里 TUN addr 变为双栈，fake-ip v6
   池网关），`::/1` + `8000::/1` 指向 TUN —— 现有代码已按 `tun_addr.is_ipv6()`
   预留分支，leak guard 在该分支自动让位（Phase 0 已实现）。
4. Linux platform：`ip -6 route/rule` 策略路由 + ip6tables DNS redirect；
   与 v4 侧同构。
5. Android：VpnService `addAddress`/`addRoute` v6（ProxyVpnService.kt）。

**验收**：Mac 真机：dig AAAA 返回 fake-ip v6，curl -6 经 TUN 到真实 v6 站点
（需 v6 环境，或 Phase 3 的 docker 环境）；关 TUN 后无残留路由。

## Phase 3 — 策略、集成测试、文档

1. 配置：`tun.addr` 支持 v6 CIDR（`from_inbound_config` 已解析 v6，核对
   mask_len 上限）；dns fakeip v6 池段可配。
2. `domain_strategy` 等价物（DNS 层即可）：prefer_ipv4 / prefer_ipv6 /
   ipv4_only —— 控制真解析路径与 fake-ip 模式是否响应 AAAA。
3. **docker v6 环境方案——只写文档，暂不接入 harness**（2026-11-09 决定）：
   把配方写进本文档或独立手册页：`--ipv6` 桥接网（fd00:1986::/64）+ 目的地
   容器 + DNS 容器 + anywhere 容器（NET_ADMIN + /dev/net/tun）。何时接入
   `anywhere/harness` 与 CI 另行决策。
4. macOS 本机验证脚本扩展：`scripts/test_v6_leak_guard.sh` 增加"模拟全球
   v6 下 fake-ip v6 端到端"小节。
5. 文档：`docs/ipv6-plan.md` 勾掉完成项；`config` 示例补 v6 字段注释。

**验收**：无 v6 环境时默认行为与 Phase 0 完全一致；docker 配方在文档中完整
可复现（手工按配方执行通过即可，不做自动化）。

## 执行纪律

- 串行推进：Phase 1 → 2 → 3，每阶段一个子 agent，完成并 review 后才开下一个。
- 每阶段：cargo test 全绿 + clippy 无新告警 + 单独 commit。
- Phase 2 起涉及真机路由，agent 改完代码即可，真机验证由用户跑
  `scripts/test_v6_leak_guard.sh` 与正常启动观察。
- 不确定的行为（如 type 28 现有路径）先读代码确认，禁止按日志猜测。
