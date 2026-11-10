# anywhere IPv6 参考手册

> 支持历史（Phase 0–3，2026-11-09/10 实施，commit 见 git log 的 a4302d9a…18dd82be）
> 与执行计划原文已删，需要时从 git 历史找回 `docs/ipv6-plan.md`。
> 背景：开发机局域网无全球 v6（路由器无 RA），上世界纯 v6 服务很少，v4-only
> 功能无损失；真正的风险是物理网口获得全球 v6 后 Happy Eyeballs 让应用绕过
> TUN——因此默认 v4-only + 泄漏防护，双栈经配置显式启用。

## 现状一览

- **默认行为与全 v4 时代一致**：不配 `addr6` 时 TUN 只有 v4，fake-ip AAAA 回
  空 NOERROR（sing-box/clash 同款）。
- **泄漏防护**（macOS，默认开）：物理接口出现全球 v6（2000::/3）且隧道
  v4-only 时，装 `::/1` + `8000::/1` **reject 路由**（ICMPv6 unreachable，
  应用秒级回退 v4）。RA 中途到达由 route watcher 捕获；链路本地不受影响；
  双栈时自动让位。
- **双栈数据面**：`tun.addr6` 启用后，TUN 配 v6 地址并接管 `::/1`+`8000::/1`，
  fake-ip AAAA 应答 v6 fake，IPv6 包（含扩展头链）与 v4 同路径 NAT/relay。
  三平台齐备：macOS 双栈接口、Linux `ip -6` 策略路由 + ip6tables DNS
  redirect、Android VpnService addAddress/addRoute。

## 配置字段速查

| 字段 | 默认 | 说明 |
|---|---|---|
| `tun.addr` | `10.0.0.1/24` | v4 CIDR；v4 上限 /32。若直接给 v6 CIDR 则成为主地址 |
| `tun.addr6` | 不配 | v6 CIDR（上限 /128）；**双栈总开关**；`""` 显式关闭 |
| `tun.ipv6_leak_guard` | `true` | v4-only 时的 reject 路由防泄漏（仅 macOS） |
| `dns.fakeip` | `198.18.0.0/15` | fake-ip v4 池 |
| `dns.fakeip_inet6_range` | `fdfe:dcba:9876::/64` | fake-ip v6 池；::1 保留给 TUN，::2 起分配；/1…/126 可配 |
| `dns.domain_strategy` | `prefer_ipv4` | `prefer_ipv4` / `prefer_ipv6`（DoH 引导 AAAA 优先）/ `ipv4_only`（AAAA 一律空，只查 A） |
| `dns.hosts` | 无 | 静态表，双族支持；v4 答 A、v6 答 AAAA；**跨族命中答空**（防 `0.0.0.0`/`::` 屏蔽被另一族绕过）；优先于规则/缓存/上游/策略 |

完整示例：`config/vless-client-v6.toml`（双栈启用版）与
`config/vless-client.toml`（注释版）。

## 未决事项

1. **真机验证待跑**：`sudo scripts/test_v6_leak_guard.sh`（v4-only 防泄漏 +
   运行中加/摘全球 v6 别名的动态路径 + addr6 端到端核对清单）。
2. **docker v6 自动化另行决策**：配方只作手工复现（见下），何时接入
   `anywhere/harness` 与 CI 未定。
3. **mless keepalive 通知丢失竞态（可选加固，2026-11-10 发现）**：唤醒风暴时
   claim 循环可能快于其余 slot 的 EOF 处理，`notify_waiters` 因无注册等待者而
   丢失，兜底的 10s sweep 又撞上再次入睡，次要 slot 的重连推迟到下次唤醒
   （单活 slot 承载全部流量，真唤醒后 ~3s 全恢复，无用户可见影响）。加固法：
   `join_all` 完成后立即再扫一轮而非先睡 10s。

## 附录 — docker 双栈 v6 环境配方（仅文档，未接 harness/CI）

> 2026-11-09 决定：本节只是手工复现配方，不进 `anywhere/harness`，不写
> CI 配置；何时自动化另行决策。需 **Linux 宿主机**（Docker Desktop 的
> vmnet 对自定义 `--ipv6` 桥接网支持不完整）与 docker ≥ 20.10（用户自定义
> 网络支持 `--ipv6 --subnet`）。
>
> 拓扑（同一 docker 网 `v6net`）：nginx 目的地（v6）← dnsmasq（AAAA 指向
> 目的地）← anywhere TUN 容器（双栈网关）← 经 anytls 连到 anywhere 代理
> 服务端容器。代理出站是必须的：**fake-ip 只在非 direct 计划上应答**
> （`resolve_query` 的 fake-ip 分支要求 `outbound_tag != "direct"`），
> 纯 direct 规则下 dig AAAA 会返回真 v6，测不到 fake-ip v6 链路。

> 下文 `$REPO` = 本仓库根目录（`git rev-parse --show-toplevel`）。

### 0. 镜像准备

`cargo build -p anywhere --release` 产物 + 最简镜像（仓库当前没有 anywhere
专用 Dockerfile）。容器里需要 `ip`/`iptables`/`ip6tables`（Linux platform
用 rtnetlink 建路由、shell 调 iptables）：

```dockerfile
FROM alpine:3.20
RUN apk add -q iproute2 iptables ca-certificates bind-tools curl
COPY anywhere /usr/local/bin/anywhere
ENTRYPOINT ["anywhere"]
```

```bash
docker build -t anywhere-v6 -f Dockerfile.anywhere .
```

### 1. 双栈网络与目的地容器

```bash
docker network create --ipv6 \
  --subnet fd00:1986::/64 --subnet 10.198.6.0/24 v6net

# 目的地：v6 可达的服务（nginx:alpine 默认监听 ::，含 v6）
docker run -d --name v6-dst --network v6net --ip6 fd00:1986::10 nginx:alpine
docker exec v6-dst wget -qO- http://localhost/ >/dev/null && echo dst-ok
```

### 2. DNS 容器（dnsmasq，AAAA 指向目的地）

```bash
cat > /tmp/v6-dnsmasq.conf <<'EOF'
port=53
no-resolv
no-hosts
log-queries
address=/v6.test/fd00:1986::10
EOF
docker run -d --name v6-dns --network v6net --ip6 fd00:1986::53 \
  -v /tmp/v6-dnsmasq.conf:/etc/dnsmasq.conf \
  alpine:3.20 sh -c 'apk add -q dnsmasq && exec dnsmasq -C /etc/dnsmasq.conf -d'

# 验证：应答 fd00:1986::10
docker run --rm --network v6net alpine:3.20 \
  nslookup -type=AAAA v6.test fd00:1986::53
```

### 3. 代理服务端容器（anytls，经 v4 直连；域名解析留给服务端）

证书用仓库自带的 `anywhere/config/{cert.pem,key.pem}`（客户端走
`insecure = true`，自签即可）。配置 `v6-server.toml`：

```toml
[[users]]
name = "alice"
password = "secret"

[[inbounds]]
type = "anytls"
listen = "0.0.0.0:8443"
cert = "/etc/anywhere/cert.pem"
key = "/etc/anywhere/key.pem"

[[outbounds]]
type = "direct"
tag = "direct-out"

[[rules]]
outbound = "direct-out"
```

```bash
docker run -d --name v6-server --network v6net --ip 10.198.6.3 \
  --ip6 fd00:1986::11 --dns fd00:1986::53 \
  -v "$PWD/v6-server.toml:/etc/anywhere.toml" \
  -v "$REPO/anywhere/config/cert.pem:/etc/anywhere/cert.pem:ro" \
  -v "$REPO/anywhere/config/key.pem:/etc/anywhere/key.pem:ro" \
  anywhere-v6 -c /etc/anywhere.toml
```

`--dns` 指向 dnsmasq 很关键：隧道把域名 `v6.test` 送过代理后，由服务端
容器自己解析（应得真 AAAA `fd00:1986::10`）。老版本 docker 不认 v6
`--dns` 时改为 `docker exec v6-server sh -c "echo 'nameserver fd00:1986::53' > /etc/resolv.conf"`。

### 4. anywhere TUN 容器（双栈网关，fake-ip v6 在这里生效）

配置 `anywhere-v6.toml`（`addr6` 显式启用 v6 数据面；`tun.addr6` 不配则
仍是 v4-only——保持默认 v4-only 原则）：

```toml
[dns]
fakeip = "198.18.0.0/15"
# fakeip_inet6_range 默认即 fdfe:dcba:9876::/64；domain_strategy 默认 prefer_ipv4
direct = ["fd00:1986::53"]

[[inbounds]]
type = "tun"
tag = "tun-in"
addr = "10.0.0.1/24"
addr6 = "fdfe:dcba:9876::1/64"

[[outbounds]]
type = "anytls"
tag = "proxy"
server = "10.198.6.3:8443"
password = "secret"
insecure = true

[[rules]]
outbound = "proxy"
```

启动（`NET_ADMIN` + `/dev/net/tun` 是 TUN 与 ip6tables 的前提）：

```bash
docker run -d --name v6-anywhere --network v6net --ip 10.198.6.2 \
  --ip6 fd00:1986::2 --cap-add NET_ADMIN --device /dev/net/tun \
  --dns fd00:1986::53 \
  -v "$PWD/anywhere-v6.toml:/etc/anywhere.toml" \
  anywhere-v6 -c /etc/anywhere.toml
```

### 5. 验证命令序列（v6-anywhere 容器内执行）

```bash
# dig AAAA → fake-ip v6（池从 ::2 起；::1 是 TUN 自己的 addr6，不分配）
docker exec v6-anywhere dig +short AAAA v6.test          # fdfe:dcba:9876::2
docker exec v6-anywhere dig +short A v6.test             # 198.18.0.2

# curl -6 → 包进 TUN → 还原域名 v6.test → anytls 隧道 → 服务端真解析 →
# 连 fd00:1986::10；期望 nginx 页面
docker exec v6-anywhere curl -6 -s http://v6.test/ | head -3
docker exec v6-anywhere curl -4 -s http://v6.test/ >/dev/null && echo v4-ok

# 路由观察：::/1 + 8000::/1 指向 tun0；关掉 anywhere 后无残留
docker exec v6-anywhere netstat -rn | grep -E '::/1|8000::/1|fdfe:dcba:9876'
docker exec v6-anywhere ip -6 route show table all | grep fdfe:dcba:9876
```

原理链路：容器内 curl/dig → DNS（ip6tables OUTPUT REDIRECT → ::1:1053
劫持）→ fake v6 应答 → curl 连 `fdfe:dcba:9876::2` → ip -6 策略路由进
TUN → restore 域名 → proxy 出站把域名送过隧道（fake-ip 只出现在非
direct 计划，`resolved_ip` 被代理出站忽略）→ 服务端容器经 dnsmasq 真解析
`fd00:1986::10` → 直连 nginx → 页面原路返回。

对照实验：把 `[[rules]]` 的 `outbound` 改成 `"direct"` 再重跑，dig AAAA
应返回**真 v6** `fd00:1986::10`（fake-ip 分支让位），curl -6 变成 TUN v6
数据面的"真 IP 直连"路径——两条 v6 数据路径都能在这套环境里验证。
