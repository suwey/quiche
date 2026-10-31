# 计划:REJECT 规则修复 + Windows 路由全面切换 iphlpapi

> 依据:2026-10-30 Windows 实机日志分析(`~/Downloads/anywhere.log`,43 分钟)。
> 核心发现:286 次 `No outbound tag 'none'` 导致连接黑洞(握手完成后静默丢弃,
> 客户端等满自身超时,是"非常卡"的首要因素);route.exe 子进程输出 GBK 乱码入日志。
> 本文档是实施合同:两个子任务由子 agent 顺序执行,完成后按验收标准核对。

## 0. 背景与问题定性

### 0.1 REJECT → `none` 黑洞

- `subscription.rs:982` 把 Clash 订阅的 `REJECT`/`REJECT-DROP` 规则目标映射为出站
  tag `"none"`,但 runner 识别的拒绝标签是字面量 `"reject"`(`runner.rs:42-46`),
  且注册表里不存在名为 `none` 的出站(`outbound/registry.rs` 没有 `type_ == "none"`
  分支)。
- 后果链:规则命中 → TCP 路径在 `runner.rs:1370-1375` 对未知 tag **只打 WARN 就
  return**,不调 `reset_tcp_stream`(reject 路径是有 RST 的,`runner.rs:1361-1368`);
  UDP 路径 `runner.rs:1244-1249` 同样裸 return,无 ICMP 不可达注入。而此时 TUN 层
  已经对客户端完成了三次握手(日志中 WARN 紧跟 `TUN TCP REV [SA]`),客户端认为
  连接已建立,发出 ClientHello 后石沉大海,要等浏览器自身 10-30s 超时。日志中
  受影响目标全是广告/CDN IP(101.91.111.x、180.163.150.x、23.222.3.x、
  202.101.48.x、142.251.x),43 分钟内 286 次。
- 既有用户配置(旧版本订阅转换生成)已把 `"none"` 写进 TOML 规则并持久化——只修
  转换不救存量,`is_reject_tag` 必须同时接受 `"none"` 作为遗留别名。

### 0.2 route.exe 依赖(Windows)

`src/inbound/tun/platform/windows.rs` 全部路由管理依赖 `route.exe` 子进程
(`run_cmd`,`mod.rs:31-45`,默认 `Stdio::inherit`):

- `cleanup_stale_routing()`(windows.rs:17-23):4 条 `route DELETE`(0.0.0.0/1、
  128.0.0.0/1、::/1、8000::/1),幂等靠 "找不到元素" 报错。
- `setup_routing()`(windows.rs:78-112):`route ADD 0.0.0.0 MASK 128.0.0.0 <tun>`
  等 4 条(按 tun_addr 家族二选一)。
- `cleanup_routing()`(windows.rs:117-152):对应 DELETE(带网关参数)。
- `primary_interface()`(windows.rs:271-296):解析 `route print 0.0.0.0` 文本找
  主接口——对含空格的接口名解析脆弱,且路由安装后调用有匹配到 /1 路由的隐患。

问题:① zh-CN 系统 route.exe 输出 OEM 代码页(936/GBK)字节,inherit 直写父进程
stderr(即日志)产生乱码;② 每条路由一个子进程(启动/关闭 8+ 次);③ 文本解析
脆弱;④ GUI 程序 spawn 控制台子进程未设 `CREATE_NO_WINDOW` 有黑框风险。

### 0.3 已决议

1. 任务 A 修 REJECT 转换 + 兼容存量 `none` + 未知 tag 兜底(见 §1)。
2. 任务 B 用 iphlpapi v2 API(`MIB_IPFORWARD_ROW2`/`CreateIpForwardEntry2`/
   `DeleteIpForwardEntry2`/`GetIpForwardTable2`)**彻底移除全部 route.exe 调用**;
   `route print` 解析同步替换为 `GetAdaptersAddresses` 枚举(见 §2)。
3. netsh(DNS hijack/restore/get_dns)**保留**:iphlpapi 没有 DNS 服务器配置 API
   (wireguard 用的 `SetInterfaceDnsSettings` 是 dnsapi 未导出文档的接口,不采)。
   仅给 netsh 输出补 OEM 代码页解码,消乱码(见 §2 B3)。
4. `run_cmd` 本体保留(macOS/Linux 仍用),Windows 不再调用。

## 1. 任务 A:REJECT 转换修复(子 agent #1)

改动文件:`src/subscription.rs`、`src/runner.rs`。

- **A1** `subscription.rs:982`:`"REJECT" | "REJECT-DROP" => Some("reject".to_string())`;
  同步更新 `map_rule_target` 的 doc 注释(`REJECT`/`REJECT-DROP` -> `reject`)。
- **A2** `runner.rs` `is_reject_tag`:曾临时接受 `"none"` 作为旧版订阅转换
  (2026-10 之前)写入存量 TOML 的遗留别名;**2026-11-01 按决议移除**,
  仅接受 `"reject"`——存量配置需重新导入订阅以重新生成规则(见 §7)。
- **A3** 未知 tag 兜底(两处调用点):
  - TCP(`runner.rs:1370-1376`):`registry.get` 失败时,先
    `reset_tcp_stream(&mut stream)` 再 return——任何配置笔误都不应造成静默黑洞。
  - UDP(`runner.rs:1244-1250`):保持静默丢弃(return),不引入 ICMP 注入改动。
  - 两处 WARN 都补上命中规则描述,便于下次定位:
    `log::warn!("No outbound tag '{tag}' (matched rule '{}')", rule_match.description)`。
- **A4** 测试:两文件均无现成 `mod tests`。新增:
  - `subscription.rs` 尾部 `#[cfg(test)]`:覆盖 `map_rule_target` 的
    DIRECT/REJECT/REJECT-DROP/PASS/未知组名(进 skips)五类;断言 REJECT 系列现在
    返回 `"reject"` 且**不再返回** `"none"`。
  - `runner.rs` 尾部 `#[cfg(test)]`:覆盖 `is_reject_tag("reject")`、
    `is_reject_tag("none")` 为真,`"direct"`/`"auto"`/`""` 为假。
- **验收**:`cargo check -p anywhere` 通过;`cargo test -p anywhere --lib
  subscription::` 与 `--lib runner::` 通过(宿主 macOS,这两处无平台 cfg)。

## 2. 任务 B:Windows 路由 iphlpapi 化(子 agent #2)

改动文件:`src/inbound/tun/platform/windows.rs`(+ 新文件
`src/inbound/tun/platform/windows_route.rs`)、`Cargo.toml`。
全部新代码 `#[cfg(target_os = "windows")]`(windows_route.rs 整文件挂 cfg)。

- **B1** 新建 `windows_route.rs`,提供四个纯 iphlpapi 函数(不用子进程、不解析文本):
  - `adapter_index_by_name(name: &str) -> Option<u32>`:`GetAdaptersAddresses`
    (AF_UNSPEC,缓冲区不足按 `ERROR_BUFFER_OVERFLOW` 重试的标准循环),对
    FriendlyName 与 Description 做 `to_lowercase` 相等匹配(AlsoAcceptable:
    `if_nametoindex` 兜底,`Win32_Networking_WinSock` 已启用)。拿
    `IfIndex`/`Luid`。找不到返回 None。
  - `route_add(prefix: IpAddr, prefix_len: u8, iface_index: u32, next_hop: IpAddr)
    -> Result<(), u32>`:填充 `MIB_IPFORWARD_ROW2`(**先 `Default::default()` 再
    逐字段赋值**),`InterfaceLuid` 或 `InterfaceIndex` 二选一(另一个置 0)、
    `DestinationPrefix`(si_family 按 prefix 家族)、`NextHop` = TUN 地址、
    `Metric = 1`、`Protocol = MIB_IPPROTO_NETMGMT`、`SitePrefixLength = 0xFF`
    (已知坑:非法值会 `ERROR_INVALID_PARAMETER`)、ValidLifetime/PreferredLifetime
    = 0xFFFFFFFF(永久)。调 `CreateIpForwardEntry2`,非 0 返回码如实上抛。
  - `route_delete(prefix, prefix_len, iface_index, next_hop) -> Result<(), u32>`:
    同上填行后 `DeleteIpForwardEntry2`;`ERROR_NOT_FOUND` 视为成功(幂等)。
  - `routes_delete_by_prefix(family, &[(prefix, prefix_len)]) -> usize`:
    `GetIpForwardTable2(family)` 枚举,命中前缀集合的行逐条
    `DeleteIpForwardEntry2`,返回删除数。供 stale 清理用(等价于旧
    `route DELETE <prefix>` 的全局语义,逐条 INFO 日志)。
- **B2** `windows.rs` 重接:
  - `cleanup_stale_routing()`:改调 `routes_delete_by_prefix`,日志汇总删除条数;
    删掉 4 条 `run_cmd("route", ...)`。
  - `setup_routing()`:先 `adapter_index_by_name(&self.iface_name)`(失败即返回
    明确错误,不再靠网关解析);按 `self.tun_addr` 家族装两条 /1
    (V4: 0.0.0.0/1+128.0.0.0/1;V6: ::/1+8000::/1),NextHop = tun_addr。
    在 manager 内**保存已装路由行参数**(prefix+len+iface_index+next_hop)供精确
    清理。语义与旧版一致:仍只装 tun_addr 对应家族,不动另一族。
  - `cleanup_routing()`:用保存的参数逐条 `route_delete`(B1 已幂等)。
  - `primary_interface()` 重写:仍返回 `Option<String>`(netsh DNS 还要接口名),
    但实现改为 `GetAdaptersAddresses` 枚举:过滤 `OperStatus == IfOperStatusUp`、
    `IfType` 非 loopback/tunnel(常量在 `Win32_NetworkManagement_Ndis`,若无则
    手写数值 24/53 并注释)、排除自身 TUN 适配器名,取 `GetIpInterfaceEntry`
    (0.0.0.0/0,即 family+index+prefix 0)中 default-route 存在且 metric 最小者;
    IPv6 时查 ::/0。**禁止缓存**(与 `outbound/common.rs:133` 的 LazyLock 不同:
    DNS hijack 在路由安装之后调用,必须现查)。
  - netsh 三处(`setup_dns_hijack`/`restore_dns`/`get_dns`)逻辑不动,仅 stderr/
    stdout 解码改走 B3。
- **B3** OEM 代码页解码(windows.rs 内私有函数):
  `decode_cmd_output(&[u8]) -> String`:`GetOEMCP()`(feature
  `Win32_Globalization`)→ `MultiByteToWideChar(cp, 0, bytes)` → UTF-16 →
  `String::from_utf16_lossy`。不用 encoding_rs/codepage crate(为零依赖新增)。
  UTF-8 Beta 系统 `GetOEMCP()` 返回 65001,路径自动正确。Cargo.toml 给
  windows-sys 追加 feature `"Win32_Globalization"`(以及 B2 需要的
  `"Win32_NetworkManagement_Ndis"`,以编译为准)。
- **B4** `mod.rs` 的 `run_cmd` 不动(macOS/Linux 继续用,已有 `#[allow(dead_code)]`);
  Windows 侧确认不再有 `run_cmd("route", ...)` 残留(`grep -rn 'route' windows.rs`
  只允许注释出现)。
- **验收**:
  - `cargo check -p anywhere --target x86_64-pc-windows-gnu` 零错误零新警告
    (target 已安装,本条是 Windows 代码的硬门禁);
  - `cargo check -p anywhere`(宿主)与 `cargo test -p anywhere --lib` 不回归;
  - `grep -c 'Command::new("route")\|run_cmd("route"' src/inbound/tun/platform/windows.rs`
    为 0。

## 3. 实施顺序与执行方式

1. 子 agent #1 执行任务 A → 宿主 `cargo check` + `cargo test` 验收。
2. 通过后子 agent #2 执行任务 B → `cargo check --target x86_64-pc-windows-gnu`
   + 宿主 check/test 验收。
3. 两任务改动集不相交(A: subscription.rs/runner.rs;B: windows.rs/
   windows_route.rs/Cargo.toml),顺序执行仅为满足审计与回滚清晰。

## 4. 风险与回滚

- `CreateIpForwardEntry2` 与 route.exe 一样要求管理员权限,权限面无变化。
- 未知 tag TCP 改为 RST:行为变化仅影响"配置错误"场景(把黑洞变成快速失败),
  正常配置无感。
- `is_reject_tag("none")` 长期保留:存量 TOML 规则不会自我修复。
- 路由清理语义:旧 `route DELETE <prefix>` 是全局删除;`routes_delete_by_prefix`
  保持同语义(按前缀全删)并逐条日志,便于出问题从日志还原现场。
- 回滚:两任务独立 commit,revert 单个 commit 即可。
- Windows 实机回归清单(用户执行):TUN 启停各一次,`route print` 确认 /1 路由
  装卸;断网重开确认 stale 清理;DNS hijack 生效且退出还原;zh-CN 日志无乱码。

## 5. 补录:实机回归暴露的适配器解析回归(2026-10-31 已修复)

**现象**:v1.2.1 新包(2026-10-31 11:00)在 Windows 上完全不代理。日志
(16:06:12):`Failed to set up routing: TUN adapter 'tun0' not found via
GetAdaptersAddresses (routing not installed)`。系统流量与系统 DNS 全部绕过
TUN(整份日志唯一一条中继是 10.0.0.255:137 NetBIOS 广播——TUN 子网本地广播)。

**根因**:`setup_routing` 用 manager 持有的内部标签 `"tun0"`
(`tun/mod.rs:142`)去 `GetAdaptersAddresses` 匹配 FriendlyName,但:

- `tun-0.8.13/src/platform/windows/device.rs:40`:anywhere 在 Windows 未设置
  `tun_name`,适配器以 crate 默认名 **"wintun"** 创建;
- 旧 route.exe 路径从不依赖该名字(路由由网关地址解析接口),`iface_name`
  仅用于日志——B2 把它当成 FriendlyName 用是引入的回归。

**修复**(windows_route.rs / windows.rs):

- 新增 `adapter_index_by_addr(tun_addr)`:按适配器自身单播地址(即我们赋给
  TUN 的 10.0.0.1)匹配——与命名无关的唯一稳定锚点;内部标签仅作 fallback;
- `find_tun_adapter()`:地址优先、名字兜底,共轮询 ≤3s(200ms 步长),覆盖
  WintunCreateAdapter 返回后适配器尚未完全注册的窗口;
- `setup_routing` 改调 `find_tun_adapter`,安装成功的 INFO 日志带
  `matched by address|name` 便于实机确认。

**教训**:替换"从解析结果反查接口"的旧实现时,新锚点必须选取与旧实现等价或
更强的标识;本例中网关地址(旧)≈ 自身单播地址(新)可用,而内部标签(弱)
不可用。实机回归必须在跨平台改动合入后立刻做,不能只靠编译通过。

## 6. 补录:DNS hijack 激活暴露 Windows loopback 死路(2026-11-01 已修复)

**现象**:路由修复后的 v1.2.1(2026-10-31 16:25 包)路由/代理全部正常
(`matched by address, ifindex 11`),但系统浏览不可用。日志零条
`TUN DNS hijack:` / `DNS resolve:`(DEBUG 级),浏览器 TCP 一个都没建立。

**根因**:对比三个版本发现——Oct 30 旧版(一切"正常"的那晚)的
`Windows DNS hijack failed: netsh set dns failed:` 是**常年失败**:旧
`primary_interface()` 用 `parts[3..].join(" ")` 解析 `route print`,把 metric
拼进接口名(如 `"WLAN 2 25"`),netsh 拒绝 → **系统 DNS 从未被改过**。新实现
修好了名字 → hijack 首次真正生效 → 系统 DNS = 10.0.0.1。但 10.0.0.1 是
Windows 本机地址:**发往本机 IP 的包走 loopback 路径,永不经过 wintun**,
查询到 10.0.0.1:53 落在本机 UDP 栈上无人监听(resolver 在 :1053)→ 全系统
解析死亡。旧状态(hijack 失败)反而正确:/1 分流路由会把**所有目的地**的
udp/53 吸进 TUN,`handler.rs` 按 `dst_port == 53` 拦截,与系统 DNS 配置无关。

**修复**(windows.rs / windows_route.rs / tun/mod.rs / Cargo.toml):

- 彻底移除 Windows 的 netsh DNS hijack 全套:`setup_dns_hijack` /
  `restore_dns` / `get_dns` / `decode_cmd_output`(GetOEMCP 解码)及
  `WindowsTunManager` 的 `dns_changed`/`original_dns` 字段;
- windows_route.rs 移除随之死亡的 `primary_interface` /
  `best_default_route_index` / `interface_metric`;Cargo.toml 移除
  `Win32_Globalization` feature(Windows 上自此**零子进程**);
- `WindowsTunManager::new(name, addr)`、`setup_routing(&bypass_ips)` 签名
  相应缩减;系统 DNS 不再被修改——顺带消除"崩溃未清理 → 系统 DNS 残留
  10.0.0.1 死解析器"的隐患(auto_hijack 配置在 Windows 成为 no-op,
  DNS 拦截由 TUN 层无条件完成)。

**教训**:修复"失败的路径"之前,先确认该路径此前是否真的成功执行过——
本例 hijack 的 WARN 在所有历史日志里都存在,而 TUN :53 拦截设计从未依赖它。
新增功能激活一条从未跑通过的代码路径时,必须在实机验证该路径本身。

## 7. 补录:移除遗留 `none` 别名(2026-11-01 决议)

§1 A2 曾为存量配置兼容让 `is_reject_tag` 同时接受 `"none"`。实机验证通过后,
按用户决议**移除该别名**,项目内 REJECT 语义统一为唯一的 `"reject"` tag:

- `runner.rs`:`is_reject_tag` 收紧为 `tag == REJECT_TAG`,测试同步更新;
- 存量影响:旧订阅导入生成的 `outbound = "none"` 规则在升级后不再被识别为
  reject,会落入"未知 tag"路径——TCP 已是 A3 的 RST 快速失败(非黑洞),
  UDP 静默丢弃,并有 `No outbound tag 'none' (matched rule ...)` WARN 提示。
  **处置:在设备上重新导入订阅**即可按新映射重新生成全部规则;
- `openrung.rs` / `macos.rs` 中的 `"none"` 字面量为无关语义(缺省值标记、
  路由文本过滤),不属此次统一范围。

## 8. 补录:日志与 UDP 拨号优化批次(2026-11-01)

实机 8 分钟日志(§7 之后的验证)确认链路稳定后,落地一批低风险优化:

- **urltest 缓存 UDP 不可用**(`urltest.rs`):`UrlTestState` 新增
  `udp_unsupported` 位图,子节点 `dial_udp` 返回 `ERR_UDP_NOT_SUPPORTED` 时置位,
  后续 QUIC 拨号直接跳过——全 mless 组从"每次 UDP 拨号轮询全部子节点"变为
  "每组每节点只试一次"。**刻意不在 `test_latency` 时清除**(UDP 能力是结构性
  的,不会恢复;`failed` 位仍按原语义清除)。全员不可用(或全部命中缓存)时
  返回 canonical 的 `ERR_UDP_NOT_SUPPORTED` 而非笼统的
  "all urltest children unavailable",供调用方精准分级;真实错误仍返回后者,
  保持 ERROR 可见性。
- **runner QUIC 失败日志降级**(`runner.rs`):`dial_udp` 失败消息含
  `ERR_UDP_NOT_SUPPORTED` 时降为 debug(ICMP port-unreachable 注入逻辑不变,
  浏览器照常快速回退 TCP);其余失败维持 ERROR。
- **ChannelLogger 零订阅者跳过格式化**(`ui/log.rs`):广播通道无接收者时直接
  返回,不再为每条日志做双份格式化(env_logger 侧照常输出)。
- **mless 热路径日志降 trace**(`multiplexer.rs`):每 32KB 下行块的
  `recv stream#` 与 `DATA stream# [hex]` 改 `trace!`(DEBUG 级日志从
  ~2.5MB/43min 量级回落;诊断时用 `RUST_LOG=trace` 仍可见)。
- **TUN `FWD/REV` 日志维持 debug**:核查确认其已按连接级事件(SYN/FIN/RST)
  过滤而非逐包,6.7k 行/43min ≈ 连接数,诊断价值高,不降级。
- 未做(留档):mless 池掉线 slot 后台保温重连(现有按需重连已满足);
  微软遥测直连超时属订阅规则层(建议对 `events.data.microsoft.com` 等加
  REJECT);netsh→iphlpapi 读 DNS 随 §6 的 netsh 整体移除而失效。
