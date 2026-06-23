# 协议说明

## 客户端

### 认证

本协议基于 TLS 协议，TLS 握手完成后客户端立即发送认证请求：

| sha256(password) | padding0 length | padding0 |
|--|--|--|
| 32 Bytes | Big-Endian uint16 | 可变长度 |

认证成功服务器会进入会话循环，认证失败服务器会关闭连接。

### 会话

认证完成后，客户端&服务器在 TLS 协议之上开启会话层事件循环，会话层 frame 格式如下：

| command | streamId | data length | data |
|--|--|--|--|
| uint8 | Big-Endian uint32 | Big-Endian uint16 | 可变长度 |

**客户端每次开启新会话必须立即发送 `cmdSettings`。**

#### command

```
	// Since version 1

	cmdWaste               = 0 // Paddings
	cmdSYN                 = 1 // stream open
	cmdPSH                 = 2 // data push
	cmdFIN                 = 3 // stream close, a.k.a EOF mark
	cmdSettings            = 4 // Settings（客户端向服务器发送）
	cmdAlert               = 5 // Alert（服务器向客户端发送）
	cmdUpdatePaddingScheme = 6 // update padding scheme（服务器向客户端发送）

	// Since version 2

	cmdSYNACK         = 7  // Server reports to the client that the stream has been opened
	cmdHeartRequest   = 8  // Keep alive command
	cmdHeartResponse  = 9  // Keep alive command
	cmdServerSettings = 10 // Settings (Server send to client)
```

对于不同类型的 command，除非下方说明有提到，否则该类型 command 不应也不能携带 data。

#### cmdWaste

任意一方收到 cmdWaste 后都应将其 data 完整读出并无声丢弃。

#### cmdHeartRequest

任意一方收到 cmdHeartRequest 后，应向对方发送 cmdHeartResponse

#### cmdSYN

客户端通知服务器打开一条新的 Stream。客户端应为每个 Stream 生成在 Session 内单调递增的 streamId。

#### cmdSYNACK

若客户端上报的版本 `v` >= 2，服务器收到 cmdSYN 后应在代理出站连接 TCP 握手完成后，发送带有对应 streamId 的 cmdSYNACK 回包。

如果您的服务器软件架构不支持回报出站连接状态，也可以在收到 cmdSYN 后直接发送 cmdSYNACK。

cmdSYNACK 若不带有 data，则表示代理 stream 握手成功。若带有 data，则 data 代表错误信息。客户端收到错误信息后必须关闭对应 stream。

#### cmdPSH

本命令的 data 承载 Stream 的传输数据。

#### cmdFIN

通知对方关闭对应 streamId 的 Stream。

- Session 正常时，本端收到 cmdFIN，关闭本地 Stream 后，不需要向对端回复 cmdFIN。
- Session 关闭时，不需要发送 cmdFIN。

#### cmdSettings

其 data 目前为：

```
v=2
client=netbrain/0.0.1
padding-md5=(md5)
```

> 采用 UTF-8 编码，key 与 value 之间用 `=` 连接，两者均为 string 类型。不同项目之间用 `\n` 分割。

- `v` 是客户端实现的协议版本号 （目前为 `2`）
- `client` 是客户端软件名称与版本号
- `padding-md5` 是客户端当前 `paddingScheme` 的 md5 （小写 hex 编码）

#### cmdServerSettings

其 data 目前为：

```
v=2
```

- `v` 是服务器实现的协议版本号 （目前为 `2`）

#### cmdAlert

其 data 为服务器发送的警告文本信息，客户端需要将其读出并打印到日志，然后双方关闭会话。

#### cmdUpdatePaddingScheme

当服务器收到客户端的 `padding-md5` 不同于服务器时，会发送 `cmdUpdatePaddingScheme` 向客户端请求更新，其 data 目前格式如下：

> Default Padding Schme

```
stop=8
0=30-30
1=100-400
2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000
3=9-9,500-1000
4=500-1000
5=500-1000
6=500-1000
7=500-1000
```

- 客户端应在 Client 对象存储 `paddingScheme`，即服务器下发的 `paddingScheme` 只作用于连接到该服务器的 Client
- 客户端第一次会话连接使用默认的 `paddingScheme`，如果收到 `cmdUpdatePaddingScheme` 后续新建会话则必须使用服务器下发的 `paddingScheme`

#### paddingScheme 具体含义与实现

> stop

`stop` 表示在第几个包停止处理 padding 比如: `stop=8` 代表只处理第 `0~7` 个包。

> padding0

`padding0` 也就是第 `0` 个包，处于认证部分，不支持分包。客户端应将该长度的 padding 与 sha265(password) 一并发送。

提示：认证部分的开销为 34 字节。

> padding1 开始

- padding1 开始处于会话部分，采用策略分包和/或填充：如果分包发送完之后，用户数据仍然有剩余，则直接发送剩余数据。如果分包发送完之前，用户数据已发送完毕，则发送 `cmdWaste` 携带数据(建议用 0)做填充。
- 策略示例：上述 paddingScheme 将包 `2` 将分成 5 个尺寸在 400-500 / 500-1000 的包发送（这里的尺寸指 TLS PlainText 的尺寸，不计算 TLS 加密等开销）。
- 策略中的 `c` 是检查符号，含义：若上一个分包发送完毕后，用户数据已无剩余，则直接对本次 Write TLS 返回，不再发送后续的填充包。
- 包计数器以 Write TLS 的次数为准，包 `1` 应该包括：`cmdSettings` 和首个 Stream 的 `cmdSYN + cmdPSH(代理目标地址)`
- 包 `2` 应该是代理自用户的第一个数据包，比如 TLS ClientHello。
- 假如在 stop 之前的某个包的发送策略没有被 PaddingScheme 定义，那么直接发送该包。

参考处理逻辑在 `func (s *Session) writeConn()`

### 复用

**客户端必须实现会话层复用功能。** 总体架构为：

> TCP Proxy -> Stream -> Session -> TLS -> TCP

复用的具体逻辑：

创建新的会话层之前必须检查是否有“空闲”的会话，如果有则取 `Seq` 最大的会话，在该 Session 上开启 Stream 承载用户代理请求。

如果没有空闲的会话，则创建新的会话，Session 的序号 `Seq` 在一个 Client 内应单调递增。

Stream 在代理中继完毕被关闭时，如果对应 Session 的事件循环未遇到错误，则将 Session 放入“空闲会话池”，并且设置 Session 的空闲起始时间为 now。

定期（如 30s）检查会话池，关闭并删除持续空闲超过一定时间（如 60s）的会话。

> 以上复用策略高度概括：优先复用最新的会话，优先清理最老的会话。

### 代理

对于 TCP，每个 Stream 打开后，客户端向服务器发送 [SocksAddr](https://tools.ietf.org/html/rfc1928#section-5) 格式表示代理请求的目标地址，然后开始双向代理中继。

对于 UDP，参考uot.md，相当于代理请求 TCP `sp.v2.udp-over-tcp.arpa`。

## 服务器

### 认证

服务器基于 TLS Server 运行，对于每个 Accpted TLS Connection 认证的方式为：

读出第一个数据包，校验认证请求（包括完整读出 padding0），如果符合，则开始会话循环。如果不符合，则直接关闭连接
### 会话

会话层格式和命令见客户端。

对于一个新 Session，如果服务器在收到客户端的 `cmdSettings` 之前收到 `cmdSYN`，必须拒绝此次会话。

服务器有权拒绝未正确实现本协议（包括但不限于 `cmdUpdatePaddingScheme` 和连接复用）、版本过旧（有已知问题）的客户端连接。

当服务器拒绝这类客户端时，必须发送 `cmdAlert` 说明原因，然后关闭 Session。

当客户端上报的版本 `v` >= 2，服务器收到 cmdSettings 后应立即发送 cmdServerSettings。

### 代理

代理中继完毕后，服务器关闭 Stream 但不要关闭 Session。

服务器可以定期清理长期无上下行的 Session。

对于目标地址为 `sp.v2.udp-over-tcp.arpa` 的请求，则应该使用 sing-box udp-over-tcp 协议处理。

### 客户端

- `password` 必选，string 类型，协议认证的密码。
- `idleSessionCheckInterval` 可选，time.Duration 类型，检查空闲会话的间隔时间。
- `idleSessionTimeout` 可选，time.Duration 类型，在检查中，关闭空闲时间超过此时长的会话。
- `minIdleSession` 可选，int 类型，在检查中，至少保留前 n 个空闲会话不关闭，即为后续代理保留一定数量的“预备会话”。

### 服务器

- `paddingScheme` 可选，string 类型，填充方案。