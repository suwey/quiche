# anywhere conformance harness

黑盒矩阵测试：把真实 `anywhere` 二进制分发到各平台，从节点池里逐个取节点
（以 tag = "test" 注入模板）跑 G/Y/X 三站连通性，汇总成 HTML 报告。
协议栈的平台差异（交叉编译 BoringSSL、CA 证书、socket 行为）由真实二进制
在真实机器上暴露，`cargo test` 的进程内回环测试覆盖不到这一层。

仅测试网络协议，无法测试tun和ui相关的功能。

## 使用

```sh
# 真实节点矩阵（分发测试）：全节点测单个平台
python3 anywhere/harness/conformance.py -c ~/anywhere-test -r ~/quiche/releases -p windows

# 多平台（可带 -arch 后缀）
python3 anywhere/harness/conformance.py -c ~/anywhere-test -r ~/quiche/releases -p windows-x64,android-arm64

# 自环测试（与分发测试解耦）：设备连自己的 anywhere server，逐协议测
python3 anywhere/harness/conformance.py -c ~/anywhere-test -p mac -s

# 只测一个节点 / 持续模式 / 覆盖每站点探测次数 / 只生成配置不运行
python3 anywhere/harness/conformance.py -c ~/anywhere-test -n yt
python3 anywhere/harness/conformance.py -c ~/anywhere-test -d 30
python3 anywhere/harness/conformance.py -c ~/anywhere-test -C 6
python3 anywhere/harness/conformance.py -c ~/anywhere-test --dry-run
```

- `-c` 配置目录（见 config/），`-r` releases 目录（`build_on_mac.sh --releases`
  的产物；平台段没写 `file=` 时从这里按 arch 取）。
- HTML 报告（内联 SVG 图表：按站点分组的 p50 柱状对比图 + 逐节点探测
  时间线）写在 `-c` 目录；逐次运行的产物（final 配置、client 日志、
  results.json 含逐次采样序列）在 `<c>/run/<时间戳>/`。退出码 0 仅当
  全部节点通过。

## 配置目录契约（config/ 是脱敏示例）

| 文件 | 作用 |
|---|---|
| `config.toml` | 客户端公共模板。`##test node##` 占位符处注入节点；tun 不放进模板（矩阵全走 socks5） |
| `outbounds.toml` | 真实节点池（分发测试用），逐个测试。tag 缺省自动命名；urltest/direct 跳过 |
| `server.toml` | 自环服务端模板。`##test inbound##` 占位符处注入 inbound；`[[users]]` 密码由 harness 每轮随机生成 |
| `inbounds.toml` | 自环 inbound 池，与 outbounds.toml 对偶（anytls / vless / mless-ws / vless-reality / shadowsocks-2022；quic 注释备用） |
| `test.toml` | `[test]` 参数 + 各平台传输段（有段才测） |
| `<平台>.toml` | 可选覆盖：table 深合并、数组/标量整体替换；缺文件/空文件 = 用模板 |

arch 解析：CLI `-p <p>-<arch>` > toml `[<p>] arch` > 单架构平台自动默认；
CLI 与 toml 的 arch 冲突时直接报错不跑。

## 自环测试（-s，与分发测试解耦）

设备上同时跑 anywhere 的 server 和 client：`curl → socks5 → client →
127.0.0.1 的 server inbound → direct 出站`。分发矩阵证明协议栈跨平台可用，
自环失败则指向 **inbound（服务端）实现**，两者互补。

- 装配：从 `inbounds.toml` 逐块取 inbound 替换 `server.toml` 占位符，每协议
  重启一次 server；client 侧自动生成配对 outbound——随机 UUID 两侧同值、
  reality x25519 密钥对现场生成并配对公钥、ws path 从服务端镜像、自签证书
  配 `insecure = true`（mless 关 tls_fragment）。两份配置均 round-trip 自检。
- 探测目标 `[test] self_sites`（默认仅 `https://www.baidu.com/`）：server 的
  出口在本机网络，必须可直连——污染/被墙目标由真实节点矩阵覆盖。
- 报告行名 `self:<协议>`，时间线全协议合并为一张图。
- 池里注释条目（quic：client outbound 字段待对齐）在实现后取消注释即进入
  自环。shadowsocks-2022 的密码走统一 `[[users]]` 契约：harness 每轮生成
  `"iPSK:用户PSK"` 复合值，服务端 users 表与客户端 outbound 同值同写法。

平台传输方式：

- **mac**：本地子进程，curl 直接打本机 socks5。
- **android**：裸二进制（`cargo ndk` 的 bin，不是 .apk）push 到
  `/data/local/tmp`，`adb shell` 前台运行（shell uid，无 root、无 UI 点击），
  `adb forward` 把 socks5 拉回 mac 由本机 curl 驱动。
- **windows / linux**：免密 ssh。**部署目录 = `<平台>.toml` 里 `[ui] serve_path`
  的上一层**（如 `serve_path = "D:/rust/ui"` → 发到 `D:/rust/`），二进制与
  `ui/` 均以 tgz 推送、远端 `tar` 解压，逐节点 final 配置单文件推送，
  `serve_path` 必须配置且原值不改写。
  部署目录**必须已存在**（harness 只探测不创建，不存在直接报错，防止
  serve_path 笔误悄悄建错目录）。`ui/` 严格镜像：先删除远端 `<部署目录>/ui`
  （目标严格限定为 serve_path 本身，必须以 `/ui` 结尾、禁 `..` 与通配符），
  再推 `ui.tgz` 解压；其余文件只覆盖不删除。client 跑在自带 `ssh -L`
  隧道的会话前台，杀会话即停。

所有远端分发（windows/linux/android）都是压缩包先行：tgz 推送、远端解压、
删除远端包，避免大文件单连接长传输和逐小文件推送的抖动问题。

测试链路（分发）：curl → socks5(设备) → anywhere client → 真实节点 → G/Y/X。
测试链路（自环）：curl → socks5 → client → 127.0.0.1 server → direct → self_sites。
判定：每站点成功率 ≥ pass_ratio 且至少一次成功；首个请求单独记 `first_ms`
（含握手），不混入稳态 p50。

采样两种模式（`duration_s > 0` 优先于 `count`，判定规则相同）：

- **count 模式**（默认 `count = 4`）：每站点固定次数，快，回归用；count 模式
  不设总时长上限，慢节点也拿满同样本数。
- **duration 模式**（`duration_s = 30` 或 CLI `--duration 30`）：按
  `interval_ms` 匀速探测满时长，样本 ≈ duration/interval，时间线图表是真正
  的时间序列，抖动/断流/慢节点一目了然。

## 建立私有测试目录

```sh
cp -R anywhere/harness/config ~/anywhere-test   # 仓库外，个人目录
# 编辑 ~/anywhere-test/{test.toml,outbounds.toml} 填真实值
```

**仓库里的 outbounds.toml 已脱敏**（server/password/sni/reality/wss 等均为
占位值）。真实节点值只存在于你的私有目录，永远不要提交进仓库；
`~/anywhere-test` 风格的私有目录不要放在 git 管辖内。
