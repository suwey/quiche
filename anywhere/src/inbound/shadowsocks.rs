// SPDX-License-Identifier: BSD-2-Clause
// Copyright © The anywhere project contributors.

//! Shadowsocks 2022 (AEAD-2022) inbound server.
//!
//! 仅支持 SS2022 加密方法（与 [`crate::outbound::shadowsocks`] outbound
//! 共享加密原语）：
//! - 2022-blake3-aes-128-gcm
//! - 2022-blake3-aes-256-gcm
//! - 2022-blake3-chacha20-poly1305
//!
//! 协议细节对齐 sing-box 所用 `sing-shadowsocks` `shadowaead_2022` 服务端
//! (`service.go` / `service_multi.go` / `protocol.go`)：
//!
//! - **TCP**：读取 salt（60s 回放过滤）+ 加密定长请求头
//!   (type=0 / timestamp / 变长头长度)，再解密变长头
//!   (SOCKS 地址 + padding + early data)，之后按 shadowio 分块
//!   (`2B 长度 || 载荷`，各自 AEAD) 双向转发。响应在首次 `write` 时惰性发出：
//!   `salt || enc(type=1 + timestamp + 请求 salt 回显 + 首块长度) || enc(载荷分块)`。
//! - **UDP**：AES 方法为 `ECB(sessionId||packetId) || AEAD(type/timestamp/…)`，
//!   chacha 方法为 `nonce24 || XChaCha(sessionId||packetId||type/…)`；
//!   按来源地址维护会话（滑动窗口防回放，双窗口处理客户端 sessionId 轮换），
//!   响应附带服务器自己的 sessionId / 包号与客户端 sessionId 回显。
//! - **用户**：与 anytls / vless 等 inbound 一致，从顶层 `[[users]]` 读取。
//!   每个用户的 `password` 与 outbound 的 password 同构——colon 分隔的
//!   多段 base64 PSK（单段即单用户；多段时末段派生会话密钥、前面各段为
//!   EIH 身份链，客户端 password 填同样的串）。服务端逐个用户条目尝试
//!   （校验 EIH 链 + 解密定长头）完成识别。

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use std::time::Duration;
use std::time::Instant;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use async_trait::async_trait;
use chacha20poly1305::XChaCha20Poly1305;
use chacha20poly1305::aead::Aead;
use chacha20poly1305::aead::KeyInit;
use chacha20poly1305::aead::Nonce;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::net::TcpStream;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

use crate::config::InboundConfig;
use crate::inbound::Destination;
use crate::inbound::Inbound;
use crate::inbound::InboundConn;
use crate::outbound::shadowsocks::cipher::AesEcb;
use crate::outbound::shadowsocks::cipher::CipherMethod;
use crate::outbound::shadowsocks::cipher::identity_subkey;
use crate::outbound::shadowsocks::cipher::MethodKind;
use crate::outbound::shadowsocks::cipher::SsAead;
use crate::outbound::shadowsocks::cipher::HEADER_TYPE_CLIENT;
use crate::outbound::shadowsocks::cipher::HEADER_TYPE_SERVER;
use crate::outbound::shadowsocks::cipher::MAX_PACKET_SIZE;
use crate::outbound::shadowsocks::cipher::NONCE_SIZE;
use crate::outbound::shadowsocks::cipher::OVERHEAD;
use crate::outbound::shadowsocks::cipher::PACKET_NONCE_SIZE;
use crate::outbound::shadowsocks::cipher::REQUEST_HEADER_FIXED_CHUNK_LENGTH;
use crate::outbound::shadowsocks::cipher::TIMESTAMP_TOLERANCE_SECS;
use crate::outbound::shadowsocks::cipher::psk_identity_hash;
use crate::outbound::shadowsocks::cipher::increase_nonce;
use crate::outbound::shadowsocks::cipher::session_subkey;
use crate::outbound::shadowsocks::packet::SlidingWindow;
use crate::outbound::shadowsocks::packet::compute_padding_len;
use crate::outbound::shadowsocks::socks::deserialize_socks_addr;
use crate::outbound::shadowsocks::socks::serialize_socks_addr;

/// sing `PacketMinimalHeaderSize`: UDP 包长度的廉价预检下限（完整性由
/// AEAD 校验兜底）。
const PACKET_MINIMAL_HEADER_SIZE: usize = 30;

/// TCP salt 回放过滤窗口（sing `replay.NewSimple(60s)`）。
const REPLAY_TIMEOUT: Duration = Duration::from_secs(60);

/// UDP 会话空闲扫描间隔与阈值。runner 侧转发在 ~2min 空闲后关闭，
/// 会话条目多保留一段时间以维持回放窗口。
const UDP_SWEEP_INTERVAL: Duration = Duration::from_secs(60);
const UDP_IDLE_AFTER: Duration = Duration::from_secs(300);

/// 每个 UDP 会话的包队列容量；满则丢包（UDP 语义）。
const UDP_QUEUE_CAPACITY: usize = 64;

// ─── helpers ────────────────────────────────────────────────────────────────

/// 用系统 CSPRNG 填充随机字节（与 outbound 相同约定：失败即 panic）。
fn fill_random(buf: &mut [u8]) {
    getrandom::fill(buf).expect("getrandom: system CSPRNG failed");
}

/// 当前 Unix 时间戳（秒）。
fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before UNIX epoch")
        .as_secs()
}

fn bad_request(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.into())
}

/// 校验请求/响应时间戳偏差（±30s，sing `ErrBadTimestamp`）。
fn check_timestamp(epoch: u64) -> io::Result<()> {
    let diff = (now_secs() as i64 - epoch as i64).abs();
    if diff > TIMESTAMP_TOLERANCE_SECS {
        return Err(bad_request(format!(
            "bad timestamp: received {epoch}, diff {diff}s"
        )));
    }
    Ok(())
}

// ─── ReplayFilter ───────────────────────────────────────────────────────────

/// TCP 请求 salt 回放过滤器，镜像 sing `replay.SimpleFilter`：
/// 窗口期内出现过的 salt 拒绝，定期清理过期条目。
struct ReplayFilter {
    pool: HashMap<Vec<u8>, Instant>,
    last_clean: Instant,
}

impl ReplayFilter {
    fn new() -> Self {
        Self {
            pool: HashMap::new(),
            last_clean: Instant::now(),
        }
    }

    /// `true` = 窗口期内首次出现（记录并放行）。
    fn check_at(&mut self, salt: &[u8], now: Instant) -> bool {
        if now.duration_since(self.last_clean) > REPLAY_TIMEOUT {
            self.pool
                .retain(|_, added| now.duration_since(*added) <= REPLAY_TIMEOUT);
            self.last_clean = now;
        }
        let seen = matches!(self.pool.get(salt), Some(added) if
            now.duration_since(*added) <= REPLAY_TIMEOUT);
        if !seen {
            self.pool.insert(salt.to_vec(), now);
        }
        !seen
    }

    fn check(&mut self, salt: &[u8]) -> bool {
        self.check_at(salt, Instant::now())
    }
}

// ─── SsService ──────────────────────────────────────────────────────────────

/// 用户条目：password 与 outbound 同构（colon 分隔的多段 base64 PSK）。
/// 末段派生会话密钥；前面各段为 EIH 身份链（仅 AES 方法，客户端对多段
/// password 会逐段写入 EIH 块）。
struct SsUser {
    psks: Vec<Vec<u8>>,
}

impl SsUser {
    /// 该用户请求头中 EIH 块的总字节数（(段数 - 1) * 16）。
    fn eih_len(&self) -> usize {
        16 * (self.psks.len() - 1)
    }

    /// 尝试用该用户识别 TCP 请求头。
    ///
    /// `rest` 为 salt 之后的部分：`[EIH 块...] || enc(定长头 11B)`。多段时
    /// 逐段校验 EIH 链（block_i = AES(ik(psk_i, salt), blake3(psk_{i+1})[:16])），
    /// 再用末段派生的会话 AEAD 解密定长头。命中返回
    /// `(会话 PSK, 读 AEAD, 定长头明文)`。
    fn try_handshake(
        &self, kind: MethodKind, ksl: usize, salt: &[u8], rest: &[u8],
    ) -> Option<(Vec<u8>, SsAead, Vec<u8>)> {
        let eih_len = self.eih_len();
        if rest.len() < eih_len + REQUEST_HEADER_FIXED_CHUNK_LENGTH + OVERHEAD {
            return None;
        }
        for i in 0..self.psks.len() - 1 {
            let subkey = identity_subkey(&self.psks[i], salt, ksl);
            let mut block = rest[i * 16..(i + 1) * 16].try_into().ok()?;
            AesEcb::new(&subkey).decrypt_block(&mut block);
            if block != psk_identity_hash(&self.psks[i + 1]) {
                return None;
            }
        }
        let session_psk = self.psks.last()?.clone();
        let key = session_subkey(&session_psk, salt, ksl);
        let aead = SsAead::new(kind, &key).ok()?;
        let fixed = aead
            .open(&[0u8; NONCE_SIZE], &rest[eih_len..eih_len + REQUEST_HEADER_FIXED_CHUNK_LENGTH + OVERHEAD])
            .ok()?;
        Some((session_psk, aead, fixed))
    }

    /// 尝试用该用户识别 AES UDP 请求包。命中返回
    /// `(会话 PSK, sessionId, packetId, 请求体明文)`。
    ///
    /// anywhere outbound 的多段 UDP 包不写 EIH 块（包头 ECB 用首段，请求体
    /// AEAD 用末段，体从 16 偏移开始）；sing 客户端则会在包头后写 EIH 块。
    /// 两种布局都接受：先试 16 偏移，失败且存在 EIH 段时校验 EIH 链后
    /// 再试 16 + eih_len 偏移。
    fn try_udp_packet_aes(
        &self, kind: MethodKind, ksl: usize, packet: &[u8],
    ) -> Option<(Vec<u8>, u64, u64, Vec<u8>)> {
        let eih_len = self.eih_len();
        // 包头(16) + AEAD tag 下限。
        if packet.len() < 16 + OVERHEAD {
            return None;
        }
        // 包头：sessionId(8) || packetId(8)，AES-ECB 加密（密钥 = 首段 PSK）。
        let mut hdr = [0u8; 16];
        hdr.copy_from_slice(&packet[..16]);
        AesEcb::new(&self.psks[0]).decrypt_block(&mut hdr);

        let session_psk = self.psks.last()?;
        let key = session_subkey(session_psk, &hdr[0..8], ksl);
        let aead = SsAead::new(kind, &key).ok()?;

        // anywhere 布局：无 EIH，体从 16 偏移开始。
        if let Ok(body) = aead.open(&hdr[4..16], &packet[16..]) {
            return Some((
                session_psk.clone(),
                u64::from_be_bytes(hdr[0..8].try_into().ok()?),
                u64::from_be_bytes(hdr[8..16].try_into().ok()?),
                body,
            ));
        }

        // sing 布局：EIH 链 block_i = AES(psk_i, blake3(psk_{i+1})[:16] ⊕ 原始包头)，
        // 体从 16 + eih_len 偏移开始。
        if eih_len > 0
            && packet.len() >= 16 + eih_len + OVERHEAD
            && (0..self.psks.len() - 1).all(|i| {
                let Ok(mut block) =
                    packet[16 + i * 16..32 + i * 16].try_into()
                else {
                    return false;
                };
                AesEcb::new(&self.psks[i]).decrypt_block(&mut block);
                for (b, h) in block.iter_mut().zip(hdr.iter()) {
                    *b ^= h;
                }
                block == psk_identity_hash(&self.psks[i + 1])
            })
        {
            if let Ok(body) = aead.open(&hdr[4..16], &packet[16 + eih_len..]) {
                return Some((
                    session_psk.clone(),
                    u64::from_be_bytes(hdr[0..8].try_into().ok()?),
                    u64::from_be_bytes(hdr[8..16].try_into().ok()?),
                    body,
                ));
            }
        }
        None
    }
}

/// SS2022 服务端共享状态（TCP / UDP 共用）。
struct SsService {
    kind: MethodKind,
    ksl: usize,
    /// 用户列表（来自顶层 `[[users]]`，password 与 outbound 同构）。
    users: Vec<SsUser>,
    replay: StdMutex<ReplayFilter>,
}

impl SsService {
    /// 解析 method + 用户 password 列表（来自顶层 `[[users]]`）。
    /// 每条 password 用 outbound 的 [`CipherMethod::new`] 解析（同构格式：
    /// colon 分隔多段 PSK；chacha 仅支持单段）。
    fn from_parts(
        method: &str, user_passwords: &[impl AsRef<str>],
    ) -> Result<Self, String> {
        if user_passwords.is_empty() {
            return Err("shadowsocks inbound: no user passwords".to_string());
        }
        let kind = MethodKind::from_name(method)
            .map_err(|e| format!("shadowsocks inbound: {e}"))?;
        let ksl = kind.key_salt_length();
        let users = user_passwords
            .iter()
            .enumerate()
            .map(|(i, pw)| {
                let parsed = CipherMethod::new(method, pw.as_ref())
                    .map_err(|e| {
                        format!("shadowsocks inbound: user #{i}: {e}")
                    })?;
                Ok(SsUser { psks: parsed.psk_list() })
            })
            .collect::<Result<Vec<_>, String>>()?;

        Ok(Self {
            kind,
            ksl,
            users,
            replay: StdMutex::new(ReplayFilter::new()),
        })
    }

    /// TCP salt 回放检查（`true` = 首次出现，放行）。
    fn check_salt(&self, salt: &[u8]) -> bool {
        self.replay.lock().expect("replay filter lock").check(salt)
    }
}

// ─── ShadowsocksInbound ─────────────────────────────────────────────────────

/// 服务端 Shadowsocks 2022 inbound：一个监听地址同时服务 TCP 与 UDP。
pub struct ShadowsocksInbound {
    conn_rx: mpsc::Receiver<InboundConn>,
}

impl ShadowsocksInbound {
    /// 从配置创建 inbound：`listen` / `method`，用户 PSK 取自顶层
    /// `[[users]]`（`passwords`，与其他 inbound 相同——每个用户的 password
    /// 即其 base64 PSK，客户端 password 也只是单个 PSK）。非 PSK 形状的
    /// 用户密码跳过（vless 约定）；一个可用 PSK 都没有则不启动。
    /// TCP 监听与 UDP 会话分发各自以后台任务运行；`None` 表示配置不可用。
    pub fn from_config(
        config: &InboundConfig, passwords: Vec<String>,
    ) -> Option<Self> {
        let listen = config.listen.clone()?;
        let method = config.method.as_deref()?;

        if let Err(e) = MethodKind::from_name(method) {
            log::error!("shadowsocks inbound: {e}");
            return None;
        }
        let user_passwords: Vec<String> = passwords
            .into_iter()
            .filter_map(|pw| {
                match CipherMethod::new(method, &pw) {
                    Ok(_) => Some(pw),
                    Err(e) => {
                        log::debug!(
                            "shadowsocks inbound: [[users]] password is not \
                             usable ({e}), skipping"
                        );
                        None
                    },
                }
            })
            .collect();
        if user_passwords.is_empty() {
            log::error!(
                "shadowsocks inbound: no [[users]] password parses as PSK(s)"
            );
            return None;
        }

        let service = match SsService::from_parts(method, &user_passwords) {
            Ok(s) => Arc::new(s),
            Err(e) => {
                log::error!("{e}");
                return None;
            },
        };

        let (conn_tx, conn_rx) = mpsc::channel(256);

        let tcp_service = service.clone();
        let tcp_tx = conn_tx.clone();
        let tcp_listen = listen.clone();
        tokio::spawn(async move {
            run_tcp_listener(tcp_listen, tcp_service, tcp_tx).await;
        });

        tokio::spawn(async move {
            run_udp_dispatcher(listen, service, conn_tx).await;
        });

        Some(Self { conn_rx })
    }
}

#[async_trait]
impl Inbound for ShadowsocksInbound {
    async fn accept(&mut self) -> Option<InboundConn> {
        self.conn_rx.recv().await
    }
}

// ─── TCP ────────────────────────────────────────────────────────────────────

async fn run_tcp_listener(
    listen: String, service: Arc<SsService>, conn_tx: mpsc::Sender<InboundConn>,
) {
    let listener = match TcpListener::bind(&listen).await {
        Ok(l) => l,
        Err(e) => {
            log::error!("shadowsocks inbound: failed to bind tcp {listen}: {e}");
            return;
        },
    };
    log::info!("shadowsocks inbound (tcp) listening on {listen}");

    loop {
        let (tcp, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                log::warn!("shadowsocks inbound: tcp accept error: {e}");
                tokio::time::sleep(Duration::from_secs(1)).await;
                continue;
            },
        };
        let service = service.clone();
        let tx = conn_tx.clone();
        tokio::spawn(async move {
            handle_tcp_conn(tcp, peer, service, tx).await;
        });
    }
}

async fn handle_tcp_conn(
    tcp: TcpStream, peer: SocketAddr, service: Arc<SsService>,
    conn_tx: mpsc::Sender<InboundConn>,
) {
    match SsServerStream::accept(tcp, &service).await {
        Ok((stream, destination)) => {
            log::info!(
                "shadowsocks inbound: tcp connect to {destination} from {peer}"
            );
            let conn = InboundConn::Tcp {
                destination,
                stream: Box::new(stream),
                source: peer,
                type_: "shadowsocks".to_string(),
                sniff: false,
            };
            if conn_tx.send(conn).await.is_err() {
                log::debug!("shadowsocks inbound: runner gone, dropping tcp conn");
            }
        },
        Err(e) => {
            log::debug!(
                "shadowsocks inbound: tcp handshake from {peer} failed: {e}"
            );
        },
    }
}

/// 响应方向状态（首次 `write` 时建立）。
struct WriteState {
    aead: SsAead,
    nonce: [u8; NONCE_SIZE],
}

/// 服务端 SS2022 TCP 流。请求头在 [`SsServerStream::accept`] 中解密，
/// 之后按 shadowio 分块双向转发（relay 循环以 `select!` 驱动，read/write
/// 不会并发调用）。
struct SsServerStream {
    conn: TcpStream,
    kind: MethodKind,
    /// 本会话密钥派生所用 PSK（单用户 = 服务端 PSK；多用户 = 匹配的用户 PSK）。
    session_psk: Vec<u8>,
    /// 客户端请求 salt，响应头需原样回显。
    request_salt: Vec<u8>,
    // ── read（客户端 → 服务端）──
    read_aead: SsAead,
    read_nonce: [u8; NONCE_SIZE],
    /// 已解密未消费的载荷（含请求变长头中的 early data）。
    read_buf: Vec<u8>,
    read_buf_pos: usize,
    // ── write（服务端 → 客户端）──
    write_state: Option<WriteState>,
}

impl SsServerStream {
    /// 请求头握手：读取 salt（回放过滤）→ 定长请求头（nonce 0）→
    /// 变长头（nonce 1，含目标地址 / padding / early data）。
    /// 返回就绪的流与目标地址。
    async fn accept(
        mut conn: TcpStream, svc: &SsService,
    ) -> io::Result<(Self, Destination)> {
        let ksl = svc.ksl;
        // 先读最小头：salt + 加密定长头（11B 明文 + tag）。多段用户的请求
        // 在两者之间还会插 EIH 块——识别失败且存在更长条目时按 16 字节
        // 步进补读再试（命中的条目恰好消费整个缓冲，无需回吐）。
        let mut header = vec![0u8; ksl + REQUEST_HEADER_FIXED_CHUNK_LENGTH + OVERHEAD];
        conn.read_exact(&mut header).await?;

        let salt = header[..ksl].to_vec();
        if !svc.check_salt(&salt) {
            return Err(bad_request("salt not unique"));
        }

        // 定长请求头（nonce 0）：type(1) || timestamp(8) || varLen(2)。
        // 逐用户条目尝试（EIH 链校验 + 定长头解密），命中即确定会话用户，
        // 后续密钥均取该用户 password 的末段 PSK。
        let (session_psk, read_aead, fixed) = loop {
            let mut min_unmet: Option<usize> = None;
            let mut matched = None;
            for user in &svc.users {
                let need =
                    ksl + user.eih_len() + REQUEST_HEADER_FIXED_CHUNK_LENGTH + OVERHEAD;
                if header.len() < need {
                    min_unmet = Some(match min_unmet {
                        Some(m) => m.min(need),
                        None => need,
                    });
                    continue;
                }
                if let Some(hit) =
                    user.try_handshake(svc.kind, ksl, &salt, &header[ksl..])
                {
                    matched = Some(hit);
                    break;
                }
            }
            match matched {
                Some(hit) => break hit,
                None => match min_unmet {
                    Some(need) => {
                        let before = header.len();
                        header.resize(need, 0);
                        conn.read_exact(&mut header[before..]).await?;
                    },
                    None => {
                        return Err(bad_request(
                            "invalid request: no user key matches",
                        ));
                    },
                },
            }
        };
        let mut read_nonce = [0u8; NONCE_SIZE];
        increase_nonce(&mut read_nonce);

        if fixed[0] != HEADER_TYPE_CLIENT {
            return Err(bad_request(format!(
                "bad header type: expected {HEADER_TYPE_CLIENT}, got {}",
                fixed[0]
            )));
        }
        let epoch = u64::from_be_bytes(fixed[1..9].try_into().expect("timestamp"));
        check_timestamp(epoch)?;
        let var_len = u16::from_be_bytes([fixed[9], fixed[10]]) as usize;

        // 变长头（nonce 1）：socksaddr || paddingLen(2) || padding || earlyData。
        let mut enc_var = vec![0u8; var_len + OVERHEAD];
        conn.read_exact(&mut enc_var).await?;
        let var = read_aead
            .open(&read_nonce, &enc_var)
            .map_err(|e| bad_request(format!("decrypt variable header: {e}")))?;
        increase_nonce(&mut read_nonce);

        let (destination, addr_len) = deserialize_socks_addr(&var)
            .map_err(|e| bad_request(format!("socks addr: {e}")))?;
        if var.len() < addr_len + 2 {
            return Err(bad_request("variable header too short for padding length"));
        }
        let padding_len =
            u16::from_be_bytes([var[addr_len], var[addr_len + 1]]) as usize;
        let after_addr = &var[addr_len + 2..];
        if after_addr.len() < padding_len {
            return Err(bad_request("bad request: damaged padding"));
        }
        let early_data = &after_addr[padding_len..];
        if padding_len == 0 && early_data.is_empty() {
            // sing `ErrNoPadding`：变长头必须带 padding 或载荷之一。
            return Err(bad_request("bad request: missing payload or padding"));
        }

        let request_salt = salt.to_vec();
        Ok((
            Self {
                conn,
                kind: svc.kind,
                session_psk,
                request_salt,
                read_aead,
                read_nonce,
                read_buf: early_data.to_vec(),
                read_buf_pos: 0,
                write_state: None,
            },
            destination,
        ))
    }

    /// 读取一个 shadowio 数据分块并解密。空块被跳过（sing shadowio 语义）。
    /// `None` = 连接关闭（EOF）。
    async fn read_chunk(&mut self) -> io::Result<Option<Vec<u8>>> {
        loop {
            let mut enc_len = [0u8; 2 + OVERHEAD];
            match self.conn.read_exact(&mut enc_len).await {
                Ok(_) => {},
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                    return Ok(None);
                },
                Err(e) => return Err(e),
            }
            let len_plain = self
                .read_aead
                .open(&self.read_nonce, &enc_len)
                .map_err(|e| bad_request(format!("decrypt chunk length: {e}")))?;
            increase_nonce(&mut self.read_nonce);
            let len = u16::from_be_bytes([len_plain[0], len_plain[1]]) as usize;
            if len == 0 {
                continue;
            }

            let mut enc_payload = vec![0u8; len + OVERHEAD];
            match self.conn.read_exact(&mut enc_payload).await {
                Ok(_) => {},
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                    return Ok(None);
                },
                Err(e) => return Err(e),
            }
            let payload = self
                .read_aead
                .open(&self.read_nonce, &enc_payload)
                .map_err(|e| bad_request(format!("decrypt chunk payload: {e}")))?;
            increase_nonce(&mut self.read_nonce);
            return Ok(Some(payload));
        }
    }

    /// 首次写出：响应头 + 首批载荷。
    ///
    /// 布局：`salt || enc(type=1 + ts + 请求salt回显 + 首块长度) || enc(首块载荷)`。
    /// 首块长度取载荷与单块上限的较小值；剩余载荷按普通数据分块继续。
    async fn write_response(&mut self, payload: &[u8]) -> io::Result<()> {
        let ksl = self.request_salt.len();
        let mut salt = vec![0u8; ksl];
        fill_random(&mut salt);
        let aead = SsAead::new(
            self.kind,
            &session_subkey(&self.session_psk, &salt, ksl),
        )
        .expect("session subkey length");
        let mut nonce = [0u8; NONCE_SIZE];

        let first_len = payload.len().min(MAX_PACKET_SIZE);
        let mut fixed = Vec::with_capacity(1 + 8 + ksl + 2);
        fixed.push(HEADER_TYPE_SERVER);
        fixed.extend_from_slice(&now_secs().to_be_bytes());
        fixed.extend_from_slice(&self.request_salt);
        fixed.extend_from_slice(&(first_len as u16).to_be_bytes());

        let enc_fixed = aead.seal(&nonce, &fixed);
        increase_nonce(&mut nonce);

        let mut out = Vec::with_capacity(ksl + enc_fixed.len() + first_len + OVERHEAD);
        out.extend_from_slice(&salt);
        out.extend_from_slice(&enc_fixed);
        let enc_first = aead.seal(&nonce, &payload[..first_len]);
        increase_nonce(&mut nonce);
        out.extend_from_slice(&enc_first);
        self.conn.write_all(&out).await?;

        self.write_state = Some(WriteState { aead, nonce });
        if first_len < payload.len() {
            self.write_data_chunks(&payload[first_len..]).await?;
        }
        Ok(())
    }

    /// 按 shadowio 分块写出 `buf`（每块消耗两个 nonce：长度块、载荷块）。
    async fn write_data_chunks(&mut self, mut buf: &[u8]) -> io::Result<()> {
        let state = self.write_state.as_mut().expect("write state");
        while !buf.is_empty() {
            let chunk_len = buf.len().min(MAX_PACKET_SIZE);
            let (chunk, rest) = buf.split_at(chunk_len);

            let enc_len =
                state.aead.seal(&state.nonce, &(chunk_len as u16).to_be_bytes());
            increase_nonce(&mut state.nonce);
            let enc_payload = state.aead.seal(&state.nonce, chunk);
            increase_nonce(&mut state.nonce);

            self.conn.write_all(&enc_len).await?;
            self.conn.write_all(&enc_payload).await?;
            buf = rest;
        }
        Ok(())
    }
}

#[async_trait]
impl crate::relay::StreamRelay for SsServerStream {
    async fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            // 先消费已解密的缓冲（early data 或上一分块剩余）。
            if self.read_buf_pos < self.read_buf.len() {
                let avail = self.read_buf.len() - self.read_buf_pos;
                let n = avail.min(buf.len());
                buf[..n].copy_from_slice(
                    &self.read_buf[self.read_buf_pos..self.read_buf_pos + n],
                );
                self.read_buf_pos += n;
                if self.read_buf_pos >= self.read_buf.len() {
                    self.read_buf = Vec::new();
                    self.read_buf_pos = 0;
                }
                return Ok(n);
            }
            match self.read_chunk().await? {
                Some(payload) => {
                    self.read_buf = payload;
                    self.read_buf_pos = 0;
                },
                None => return Ok(0),
            }
        }
    }

    async fn write(&mut self, buf: &[u8]) -> io::Result<()> {
        if buf.is_empty() {
            return Ok(());
        }
        if self.write_state.is_none() {
            self.write_response(buf).await?;
        } else {
            self.write_data_chunks(buf).await?;
        }
        Ok(())
    }

    async fn shutdown(&mut self) -> io::Result<()> {
        self.conn.shutdown().await
    }
}

// ─── UDP ────────────────────────────────────────────────────────────────────

/// 按方法解析 UDP 请求包（无会话状态参与；回放检查在会话 accept 阶段）。
fn parse_udp_request(svc: &SsService, packet: &[u8]) -> io::Result<UdpRequest> {
    match svc.kind {
        MethodKind::ChaCha20Poly1305 => parse_udp_request_chacha(svc, packet),
        _ => parse_udp_request_aes(svc, packet),
    }
}

/// 解析后的 UDP 请求：包头字段 + AEAD 解密后的请求体 + 识别出的用户 PSK。
struct UdpRequest {
    /// 客户端会话 id。
    session_id: u64,
    packet_id: u64,
    /// 请求体明文：type(1) || timestamp(8) || paddingLen(2) || padding || socksaddr || payload。
    body: Vec<u8>,
    /// 识别出的用户 PSK（响应方向密钥派生用）。
    psk: Vec<u8>,
}

/// AES 方法请求：`ECB(sessionId||packetId) || [EIH 块...] || AEAD(请求体)`。
/// 逐用户条目尝试（包头 ECB + EIH 链 + 请求体 AEAD），命中即识别用户。
fn parse_udp_request_aes(
    svc: &SsService, packet: &[u8],
) -> io::Result<UdpRequest> {
    if packet.len() < PACKET_MINIMAL_HEADER_SIZE {
        return Err(bad_request("packet too short"));
    }

    for user in &svc.users {
        if let Some((psk, session_id, packet_id, body)) =
            user.try_udp_packet_aes(svc.kind, svc.ksl, packet)
        {
            return Ok(UdpRequest {
                session_id,
                packet_id,
                body,
                psk,
            });
        }
    }
    Err(bad_request("invalid request: no user key matches"))
}

/// chacha 方法请求：`nonce24 || XChaCha(sessionId||packetId||请求体)`，
/// PSK 直接作密钥。逐用户 PSK 尝试解密，命中即识别用户。
fn parse_udp_request_chacha(
    svc: &SsService, packet: &[u8],
) -> io::Result<UdpRequest> {
    if packet.len() < PACKET_NONCE_SIZE + PACKET_MINIMAL_HEADER_SIZE {
        return Err(bad_request("packet too short"));
    }
    let n: Nonce<XChaCha20Poly1305> = packet[..PACKET_NONCE_SIZE]
        .try_into()
        .expect("nonce must be 24 bytes");
    // chacha 不支持 EIH，用户条目恒为单段 PSK。
    for user in &svc.users {
        let psk = &user.psks[0];
        let cipher = XChaCha20Poly1305::new_from_slice(psk)
            .expect("invalid PSK length for XChaCha20Poly1305");
        let Ok(plain) = cipher.decrypt(&n, &packet[PACKET_NONCE_SIZE..]) else {
            continue;
        };
        if plain.len() < 16 {
            return Err(bad_request("decrypted packet too short"));
        }
        return Ok(UdpRequest {
            session_id: u64::from_be_bytes(
                plain[0..8].try_into().expect("session id"),
            ),
            packet_id: u64::from_be_bytes(
                plain[8..16].try_into().expect("packet id"),
            ),
            body: plain[16..].to_vec(),
            psk: psk.clone(),
        });
    }
    Err(bad_request("invalid request: no user key matches"))
}

/// 请求体：type(1) || timestamp(8) || paddingLen(2) || padding || socksaddr || payload。
fn parse_udp_body(body: &[u8]) -> io::Result<(Vec<u8>, Destination)> {
    if body.len() < 1 + 8 + 2 {
        return Err(bad_request("packet body too short"));
    }
    if body[0] != HEADER_TYPE_CLIENT {
        return Err(bad_request(format!(
            "bad header type: expected {HEADER_TYPE_CLIENT}, got {}",
            body[0]
        )));
    }
    let epoch = u64::from_be_bytes(body[1..9].try_into().expect("timestamp"));
    check_timestamp(epoch)?;
    let padding_len = u16::from_be_bytes([body[9], body[10]]) as usize;
    let offset = 11 + padding_len;
    if offset > body.len() {
        return Err(bad_request("padding length exceeds body"));
    }
    let (dest, addr_len) = deserialize_socks_addr(&body[offset..])
        .map_err(|e| bad_request(format!("socks addr: {e}")))?;
    Ok((body[offset + addr_len..].to_vec(), dest))
}

/// 单个客户端来源的 UDP 会话核心状态：解密方向的回放窗口 +
/// 响应方向的服务器 sessionId / 包号 / 密钥。
struct UdpSessionCore {
    kind: MethodKind,
    /// 响应所用 PSK（= 最近识别的用户 PSK；单用户 = 服务端 PSK）。
    psk: Vec<u8>,
    // ── 客户端 → 服务端 ──
    session_id: u64,
    window: SlidingWindow,
    /// 上一客户端会话（sessionId 轮换后退位，保留其回放窗口）。
    last_session_id: u64,
    last_window: SlidingWindow,
    // ── 服务端 → 客户端 ──
    server_session_id: u64,
    server_packet_id: u64,
    /// 最近活动时间（空闲扫描用）。
    last_activity: Instant,
}

impl UdpSessionCore {
    fn new(kind: MethodKind, psk: Vec<u8>, session_id: u64) -> Self {
        let mut id_bytes = [0u8; 8];
        fill_random(&mut id_bytes);
        Self {
            kind,
            psk,
            session_id,
            window: SlidingWindow::new(),
            last_session_id: 0,
            last_window: SlidingWindow::new(),
            server_session_id: u64::from_be_bytes(id_bytes),
            server_packet_id: 0,
            last_activity: Instant::now(),
        }
    }

    /// 窗口检查 → 解析请求体 → 窗口标记；客户端 sessionId 变化时轮换会话
    /// （新窗口 + 重建服务端会话；旧窗口退位保留，抑制跨会话回放）。
    fn accept(&mut self, req: UdpRequest) -> io::Result<(Vec<u8>, Destination)> {
        let is_current = req.session_id == self.session_id;
        let is_previous = !is_current && req.session_id == self.last_session_id;
        if !is_current && !is_previous {
            self.last_session_id =
                std::mem::replace(&mut self.session_id, req.session_id);
            self.last_window =
                std::mem::take(&mut self.window);
            let mut id_bytes = [0u8; 8];
            fill_random(&mut id_bytes);
            self.server_session_id = u64::from_be_bytes(id_bytes);
            self.server_packet_id = 0;
            self.psk = req.psk;
        }

        // sing 顺序：check → AEAD 解密 → add → 解析字段；解密已在
        // parse_udp_request 完成，此处只差解析。
        if is_current {
            if !self.window.check(req.packet_id) {
                return Err(bad_request("packet id not unique"));
            }
        } else if is_previous && !self.last_window.check(req.packet_id) {
            return Err(bad_request("packet id not unique"));
        }

        let parsed = parse_udp_body(&req.body);

        // 解密成功即计数（解析失败同样标记，与 sing 一致）。
        if is_previous {
            self.last_window.add(req.packet_id);
        } else {
            self.window.add(req.packet_id);
        }
        self.last_activity = Instant::now();

        parsed
    }

    /// 构建服务端响应包并推进包号（sing `serverPacketWriter.WritePacket`）。
    ///
    /// AES：`ECB(服务器sessionId||包号) || AEAD(type=1+ts+客户端sessionId+padding+addr+载荷)`，
    /// AEAD key = `SessionKey(psk, 服务器 sessionId 字节)`，nonce = 未加密包头[4..16]。
    /// chacha：`nonce24 || XChaCha(上述全部字段)`，PSK 直接作密钥。
    fn build_response(&mut self, payload: &[u8], dest: &Destination) -> Vec<u8> {
        let packet_id = self.server_packet_id;
        self.server_packet_id = packet_id.wrapping_add(1);
        let padding_len = compute_padding_len(payload.len(), dest.port);
        let addr = serialize_socks_addr(dest);

        match self.kind {
            MethodKind::ChaCha20Poly1305 => {
                let mut nonce = [0u8; PACKET_NONCE_SIZE];
                fill_random(&mut nonce);
                let mut plain = Vec::with_capacity(
                    16 + 1 + 8 + 2 + padding_len + addr.len() + payload.len(),
                );
                plain.extend_from_slice(&self.server_session_id.to_be_bytes());
                plain.extend_from_slice(&packet_id.to_be_bytes());
                plain.push(HEADER_TYPE_SERVER);
                plain.extend_from_slice(&now_secs().to_be_bytes());
                // 客户端 sessionId 回显（sing `remoteSessionId`）。
                plain.extend_from_slice(&self.session_id.to_be_bytes());
                plain.extend_from_slice(&(padding_len as u16).to_be_bytes());
                plain.extend_from_slice(&vec![0u8; padding_len]);
                plain.extend_from_slice(&addr);
                plain.extend_from_slice(payload);

                let cipher = XChaCha20Poly1305::new_from_slice(&self.psk)
                    .expect("invalid PSK length for XChaCha20Poly1305");
                let n: Nonce<XChaCha20Poly1305> = nonce.into();
                let sealed = cipher
                    .encrypt(&n, plain.as_ref())
                    .expect("XChaCha20Poly1305 encryption failed");
                let mut out = Vec::with_capacity(PACKET_NONCE_SIZE + sealed.len());
                out.extend_from_slice(&nonce);
                out.extend_from_slice(&sealed);
                out
            },
            _ => {
                let mut hdr = [0u8; 16];
                hdr[0..8].copy_from_slice(&self.server_session_id.to_be_bytes());
                hdr[8..16].copy_from_slice(&packet_id.to_be_bytes());

                let mut body = Vec::with_capacity(
                    1 + 8 + 8 + 2 + padding_len + addr.len() + payload.len(),
                );
                body.push(HEADER_TYPE_SERVER);
                body.extend_from_slice(&now_secs().to_be_bytes());
                // 客户端 sessionId 回显。
                body.extend_from_slice(&self.session_id.to_be_bytes());
                body.extend_from_slice(&(padding_len as u16).to_be_bytes());
                body.extend_from_slice(&vec![0u8; padding_len]);
                body.extend_from_slice(&addr);
                body.extend_from_slice(payload);

                let key = session_subkey(&self.psk, &hdr[0..8], self.psk.len());
                let aead = SsAead::new(self.kind, &key)
                    .expect("session subkey length");
                let sealed = aead.seal(&hdr[4..16], &body);

                // 包头最后 ECB 加密（AEAD nonce 必须取未加密包头）。
                AesEcb::new(&self.psk).encrypt_block(&mut hdr);
                let mut out = Vec::with_capacity(16 + sealed.len());
                out.extend_from_slice(&hdr);
                out.extend_from_slice(&sealed);
                out
            },
        }
    }
}

/// dispatcher 持有的会话句柄：共享核心状态 + 发往 relay 的包队列。
#[derive(Clone)]
struct UdpSessionHandle {
    core: Arc<StdMutex<UdpSessionCore>>,
    queue_tx: mpsc::Sender<(Vec<u8>, Destination)>,
}

/// UDP 会话分发：从监听 socket 收包，按来源地址路由到会话；
/// 新来源首次成功解密时向 runner 提交一个 [`InboundConn::Udp`]。
async fn run_udp_dispatcher(
    listen: String, service: Arc<SsService>, conn_tx: mpsc::Sender<InboundConn>,
) {
    let socket = match UdpSocket::bind(&listen).await {
        Ok(s) => Arc::new(s),
        Err(e) => {
            log::error!("shadowsocks inbound: failed to bind udp {listen}: {e}");
            return;
        },
    };
    log::info!("shadowsocks inbound (udp) listening on {listen}");

    let mut sessions: HashMap<SocketAddr, UdpSessionHandle> = HashMap::new();
    let mut buf = vec![0u8; 65535];
    let mut sweep = tokio::time::interval(UDP_SWEEP_INTERVAL);
    sweep.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            received = socket.recv_from(&mut buf) => {
                let (n, source) = match received {
                    Ok(v) => v,
                    Err(e) => {
                        log::warn!("shadowsocks inbound: udp recv error: {e}");
                        tokio::time::sleep(Duration::from_secs(1)).await;
                        continue;
                    },
                };
                if let Err(e) = handle_udp_packet(
                    &socket, &service, &mut sessions, &buf[..n], source, &conn_tx,
                )
                .await
                {
                    log::debug!(
                        "shadowsocks inbound: udp packet from {source}: {e}"
                    );
                } else {
                    log::trace!(
                        "shadowsocks inbound: udp packet from {source} handled"
                    );
                }
            },
            _ = sweep.tick() => {
                let before = sessions.len();
                sessions.retain(|_, h| {
                    h.core.lock().map(|c| c.last_activity.elapsed() < UDP_IDLE_AFTER)
                        .unwrap_or(false)
                });
                if sessions.len() != before {
                    log::debug!(
                        "shadowsocks inbound: swept {} idle udp sessions",
                        before - sessions.len()
                    );
                }
            },
        }
    }
}

/// 处理一个 UDP 包：解析 → 会话窗口检查 → 入队（新来源先建立会话并提交
/// `InboundConn::Udp`）。解析失败仅丢弃该包，不影响会话。
async fn handle_udp_packet(
    socket: &Arc<UdpSocket>, service: &SsService,
    sessions: &mut HashMap<SocketAddr, UdpSessionHandle>, packet: &[u8],
    source: SocketAddr, conn_tx: &mpsc::Sender<InboundConn>,
) -> io::Result<()> {
    let req = parse_udp_request(service, packet)?;

    let mut new_relay = None;
    let handle = match sessions.get(&source) {
        Some(h) => h.clone(),
        None => {
            let (queue_tx, queue_rx) = mpsc::channel(UDP_QUEUE_CAPACITY);
            let core = Arc::new(StdMutex::new(UdpSessionCore::new(
                service.kind,
                req.psk.clone(),
                req.session_id,
            )));
            let h = UdpSessionHandle { core, queue_tx };
            sessions.insert(source, h.clone());
            new_relay = Some(queue_rx);
            h
        },
    };

    let (payload, dest) = {
        let mut core = handle.core.lock().expect("udp session lock");
        core.accept(req)?
    };

    if let Some(queue_rx) = new_relay.take() {
        let conn = InboundConn::Udp {
            initial_destination: dest.clone(),
            packet: Box::new(SsServerPacketRelay {
                socket: socket.clone(),
                source,
                core: handle.core.clone(),
                queue_rx,
                initial_dest: dest.clone(),
            }),
            source,
            type_: "shadowsocks".to_string(),
        };
        if conn_tx.send(conn).await.is_err() {
            sessions.remove(&source);
            return Ok(());
        }
    }

    match handle.queue_tx.try_send((payload, dest)) {
        Ok(()) => {},
        Err(mpsc::error::TrySendError::Full(_)) => {
            log::debug!(
                "shadowsocks inbound: udp queue full for {source}, dropping"
            );
        },
        Err(mpsc::error::TrySendError::Closed(_)) => {
            log::debug!("shadowsocks inbound: udp relay gone for {source}");
            sessions.remove(&source);
        },
    }
    Ok(())
}

/// 服务端 UDP 会话的 [`PacketRelay`]：解密后的客户端包来自 dispatcher
/// 队列；响应包用会话核心状态加密后发回客户端地址。
struct SsServerPacketRelay {
    socket: Arc<UdpSocket>,
    source: SocketAddr,
    core: Arc<StdMutex<UdpSessionCore>>,
    queue_rx: mpsc::Receiver<(Vec<u8>, Destination)>,
    initial_dest: Destination,
}

#[async_trait]
impl crate::relay::PacketRelay for SsServerPacketRelay {
    async fn read_packet(
        &mut self, buf: &mut [u8],
    ) -> io::Result<(usize, Destination)> {
        match self.queue_rx.recv().await {
            Some((payload, dest)) => {
                let n = payload.len().min(buf.len());
                if n < payload.len() {
                    log::warn!(
                        "shadowsocks inbound: udp payload {} exceeds buffer {}, truncated",
                        payload.len(),
                        buf.len()
                    );
                }
                buf[..n].copy_from_slice(&payload[..n]);
                log::trace!("shadowsocks inbound: udp relay read {} bytes for {dest}", n);
                Ok((n, dest))
            },
            // 队列关闭 = 会话已被清理（空闲扫描），会话结束。
            None => {
                log::trace!("shadowsocks inbound: udp relay queue closed");
                Ok((0, self.initial_dest.clone()))
            },
        }
    }

    async fn write_packet(
        &mut self, buf: &[u8], dest: &Destination,
    ) -> io::Result<()> {
        let packet = {
            let mut core = self.core.lock().expect("udp session lock");
            core.build_response(buf, dest)
        };
        log::trace!(
            "shadowsocks inbound: udp reply {} bytes to {source}",
            packet.len(),
            source = self.source
        );
        self.socket.send_to(&packet, self.source).await?;
        Ok(())
    }

    async fn close(&mut self) -> io::Result<()> {
        Ok(())
    }
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inbound::Address;
    use crate::outbound::shadowsocks::cipher::MAX_PADDING_LENGTH;
    use crate::outbound::shadowsocks::cipher::CipherMethod;
    use crate::outbound::shadowsocks::packet::SsUdpRelay;
    use crate::outbound::shadowsocks::stream::SsTcpStream;
    use crate::relay::PacketRelay;
    use crate::relay::StreamRelay;
    use base64::Engine;
    use tokio::net::UdpSocket;

    // ── helpers ────────────────────────────────────────────────────────────

    fn b64(data: &[u8]) -> String {
        base64::engine::general_purpose::STANDARD.encode(data)
    }

    fn psk_of_len(len: usize, fill: u8) -> String {
        b64(&vec![fill; len])
    }

    fn test_dest() -> Destination {
        Destination::new(Address::Domain("example.com".to_string()), 443)
    }

    /// Create a connected loopback TCP pair `(client, server)`.
    async fn make_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let connect =
            tokio::spawn(async move { TcpStream::connect(addr).await.unwrap() });
        let (server, _) = listener.accept().await.unwrap();
        let client = connect.await.unwrap();
        (client, server)
    }

    /// 手工构造客户端 TCP 请求（镜像 outbound `SsTcpStream::do_handshake_write`，
    /// 单 PSK 请求格式）：`salt || enc(fixed) || enc(varHeader)`。
    fn build_client_request(
        kind: MethodKind, psk: &[u8], salt: &[u8], ts: u64, dest: &Destination,
        padding_len: usize, early_data: &[u8],
    ) -> Vec<u8> {
        let aead = SsAead::new(
            kind,
            &session_subkey(psk, salt, kind.key_salt_length()),
        )
        .unwrap();
        let mut nonce = [0u8; NONCE_SIZE];

        let addr = serialize_socks_addr(dest);
        let var_header_len = addr.len() + 2 + padding_len + early_data.len();
        let mut fixed = Vec::with_capacity(REQUEST_HEADER_FIXED_CHUNK_LENGTH);
        fixed.push(HEADER_TYPE_CLIENT);
        fixed.extend_from_slice(&ts.to_be_bytes());
        fixed.extend_from_slice(&(var_header_len as u16).to_be_bytes());
        let enc_fixed = aead.seal(&nonce, &fixed);
        increase_nonce(&mut nonce);

        let mut var = addr;
        var.extend_from_slice(&(padding_len as u16).to_be_bytes());
        var.extend_from_slice(&vec![0u8; padding_len]);
        var.extend_from_slice(early_data);
        let enc_var = aead.seal(&nonce, &var);

        let mut out = salt.to_vec();
        out.extend_from_slice(&enc_fixed);
        out.extend_from_slice(&enc_var);
        out
    }

    /// 手工构造单用户 AES UDP 请求包：`ECB(hdr) || AEAD(body)`。
    fn build_udp_request_aes(
        kind: MethodKind, psk: &[u8], session_id: u64, packet_id: u64,
        dest: &Destination, payload: &[u8], padding_len: usize,
    ) -> Vec<u8> {
        let mut hdr = [0u8; 16];
        hdr[0..8].copy_from_slice(&session_id.to_be_bytes());
        hdr[8..16].copy_from_slice(&packet_id.to_be_bytes());

        let addr = serialize_socks_addr(dest);
        let mut body =
            Vec::with_capacity(11 + padding_len + addr.len() + payload.len());
        body.push(HEADER_TYPE_CLIENT);
        body.extend_from_slice(&now_secs().to_be_bytes());
        body.extend_from_slice(&(padding_len as u16).to_be_bytes());
        body.extend_from_slice(&vec![0u8; padding_len]);
        body.extend_from_slice(&addr);
        body.extend_from_slice(payload);

        let key = session_subkey(psk, &hdr[0..8], psk.len());
        let aead = SsAead::new(kind, &key).unwrap();
        let sealed = aead.seal(&hdr[4..16], &body);

        AesEcb::new(psk).encrypt_block(&mut hdr);
        let mut out = hdr.to_vec();
        out.extend_from_slice(&sealed);
        out
    }

    /// 构造一段合法的 UDP 请求体明文（供直接测试 accept/parse 路径）。
    fn udp_body_for(dest: &Destination, payload: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        body.push(HEADER_TYPE_CLIENT);
        body.extend_from_slice(&now_secs().to_be_bytes());
        body.extend_from_slice(&0u16.to_be_bytes());
        body.extend_from_slice(&serialize_socks_addr(dest));
        body.extend_from_slice(payload);
        body
    }

    // ── ReplayFilter ───────────────────────────────────────────────────────

    #[test]
    fn replay_filter_accepts_once() {
        let mut f = ReplayFilter::new();
        assert!(f.check(b"salt-a"));
        assert!(!f.check(b"salt-a"), "replay must be rejected");
        assert!(f.check(b"salt-b"), "different salt must be accepted");
    }

    #[test]
    fn replay_filter_expires() {
        let mut f = ReplayFilter::new();
        let now = Instant::now();
        assert!(f.check_at(b"salt", now));
        // 窗口内重放拒绝。
        assert!(!f.check_at(b"salt", now + Duration::from_secs(30)));
        // 超过窗口后同一 salt 再次放行（并触发清理）。
        assert!(f.check_at(b"salt", now + Duration::from_secs(61)));
        assert!(!f.check_at(b"salt", now + Duration::from_secs(62)));
    }

    // ── SsService::from_parts ──────────────────────────────────────────────

    #[test]
    fn service_parses_valid_configs() {
        // 单段 password = 单 PSK 用户。
        let svc =
            SsService::from_parts("2022-blake3-aes-128-gcm", &[psk_of_len(16, 1)])
                .unwrap();
        assert_eq!(svc.ksl, 16);
        assert_eq!(svc.users.len(), 1);
        assert_eq!(svc.users[0].psks.len(), 1);
        assert_eq!(svc.users[0].eih_len(), 0);

        // 多个用户条目（各单段）。
        let svc = SsService::from_parts(
            "2022-blake3-aes-256-gcm",
            &[psk_of_len(32, 1), psk_of_len(32, 2), psk_of_len(32, 3)],
        )
        .unwrap();
        assert_eq!(svc.users.len(), 3);

        // 与 outbound 同构：colon 多段 password（iPSK:用户PSK），EIH 链 1 块。
        let two = format!("{}:{}", psk_of_len(32, 1), psk_of_len(32, 2));
        let svc =
            SsService::from_parts("2022-blake3-aes-256-gcm", &[two]).unwrap();
        assert_eq!(svc.users[0].psks.len(), 2);
        assert_eq!(svc.users[0].eih_len(), 16);
    }

    #[test]
    fn service_rejects_bad_configs() {
        // 未知方法
        assert!(SsService::from_parts("aes-256-cfb", &[psk_of_len(32, 1)]).is_err());
        // 空 PSK 列表
        assert!(
            SsService::from_parts("2022-blake3-aes-256-gcm", &[] as &[String])
                .is_err()
        );
        // 空 PSK
        assert!(SsService::from_parts("2022-blake3-aes-256-gcm", &["".to_string()])
            .is_err());
        // PSK 长度不符
        assert!(SsService::from_parts(
            "2022-blake3-aes-256-gcm",
            &[psk_of_len(16, 1)]
        )
        .is_err());
        // colon 多段中某段长度不符
        let bad_chain = format!("{}:{}", psk_of_len(32, 1), psk_of_len(16, 2));
        assert!(SsService::from_parts("2022-blake3-aes-256-gcm", &[bad_chain])
            .is_err());
        // chacha 不支持多段（与 outbound 一致）
        let two = format!("{}:{}", psk_of_len(32, 1), psk_of_len(32, 2));
        assert!(SsService::from_parts("2022-blake3-chacha20-poly1305", &[two])
            .is_err());
    }

    // ── TCP 握手 ───────────────────────────────────────────────────────────

    #[tokio::test]
    async fn tcp_accept_parses_request_and_early_data() {
        let kind = MethodKind::Aes128Gcm;
        let psk = psk_of_len(16, 0x42);
        let svc = SsService::from_parts("2022-blake3-aes-128-gcm", &[&psk])
            .unwrap();
        let (mut client, server) = make_pair().await;

        let salt = [0x5Au8; 16];
        let early = b"GET / HTTP/1.1".to_vec();
        let request = build_client_request(
            kind,
            &base64::engine::general_purpose::STANDARD.decode(&psk).unwrap(),
            &salt,
            now_secs(),
            &test_dest(),
            32,
            &early,
        );

        let (mut stream, dest) = {
            use tokio::io::AsyncWriteExt;
            client.write_all(&request).await.unwrap();
            drop(client); // 写端关闭（FIN），请求字节已缓冲
            SsServerStream::accept(server, &svc).await.unwrap()
        };
        assert_eq!(dest, test_dest());

        // early data 立即可读。
        let mut buf = vec![0u8; 128];
        let n = stream.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], &early[..]);
    }

    #[tokio::test]
    async fn tcp_rejects_salt_replay() {
        let kind = MethodKind::Aes256Gcm;
        let psk = psk_of_len(32, 0x42);
        let svc =
            SsService::from_parts("2022-blake3-aes-256-gcm", &[&psk])
                .unwrap();
        let psk_bytes =
            base64::engine::general_purpose::STANDARD.decode(&psk).unwrap();
        let salt = [0x77u8; 32];
        let request = build_client_request(
            kind, &psk_bytes, &salt, now_secs(), &test_dest(), 16, b"hi",
        );

        let (mut client, server) = make_pair().await;
        {
            use tokio::io::AsyncWriteExt;
            client.write_all(&request).await.unwrap();
            drop(client);
        }
        let (_stream, _dest) =
            SsServerStream::accept(server, &svc).await.unwrap();

        // 同一 salt 的第二个连接被拒绝。
        let (mut client2, server2) = make_pair().await;
        {
            use tokio::io::AsyncWriteExt;
            client2.write_all(&request).await.unwrap();
            drop(client2);
        }
        let err = SsServerStream::accept(server2, &svc)
            .await
            .err()
            .expect("accept should fail");
        assert!(err.to_string().contains("salt not unique"), "{err}");
    }

    #[tokio::test]
    async fn tcp_rejects_unknown_psk() {
        let kind = MethodKind::Aes256Gcm;
        let real_psk = [0x42u8; 32];
        let svc = SsService::from_parts(
            "2022-blake3-aes-256-gcm",
            &[b64(&real_psk)],
        )
        .unwrap();
        let wrong_psk = [0x00u8; 32];
        let request = build_client_request(
            kind, &wrong_psk, &[0u8; 32], now_secs(), &test_dest(), 16, b"hi",
        );

        let (mut client, server) = make_pair().await;
        {
            use tokio::io::AsyncWriteExt;
            client.write_all(&request).await.unwrap();
            drop(client);
        }
        let err = SsServerStream::accept(server, &svc)
            .await
            .err()
            .expect("accept should fail");
        assert!(err.to_string().contains("no user key matches"), "{err}");
    }

    #[tokio::test]
    async fn tcp_rejects_bad_timestamp() {
        let kind = MethodKind::Aes256Gcm;
        let psk = psk_of_len(32, 0x42);
        let svc =
            SsService::from_parts("2022-blake3-aes-256-gcm", &[&psk])
                .unwrap();
        let psk_bytes =
            base64::engine::general_purpose::STANDARD.decode(&psk).unwrap();
        let request = build_client_request(
            kind,
            &psk_bytes,
            &[1u8; 32],
            now_secs() - 120, // 超过 30s 容差
            &test_dest(),
            16,
            b"hi",
        );

        let (mut client, server) = make_pair().await;
        {
            use tokio::io::AsyncWriteExt;
            client.write_all(&request).await.unwrap();
            drop(client);
        }
        let err = SsServerStream::accept(server, &svc)
            .await
            .err()
            .expect("accept should fail");
        assert!(err.to_string().contains("timestamp"), "{err}");
    }

    #[tokio::test]
    async fn tcp_rejects_missing_padding_and_payload() {
        let kind = MethodKind::Aes256Gcm;
        let psk = psk_of_len(32, 0x42);
        let svc =
            SsService::from_parts("2022-blake3-aes-256-gcm", &[&psk])
                .unwrap();
        let psk_bytes =
            base64::engine::general_purpose::STANDARD.decode(&psk).unwrap();
        // padding = 0 且无 early data → sing ErrNoPadding。
        let request = build_client_request(
            kind, &psk_bytes, &[2u8; 32], now_secs(), &test_dest(), 0, b"",
        );

        let (mut client, server) = make_pair().await;
        {
            use tokio::io::AsyncWriteExt;
            client.write_all(&request).await.unwrap();
            drop(client);
        }
        let err = SsServerStream::accept(server, &svc)
            .await
            .err()
            .expect("accept should fail");
        assert!(
            err.to_string().contains("missing payload or padding"),
            "{err}"
        );
    }

    /// 多用户：每个用户的 PSK 都能独立完成握手（逐 PSK 尝试识别）。
    #[tokio::test]
    async fn tcp_accept_each_user_psk() {
        let kind = MethodKind::Aes256Gcm;
        let psk_a = psk_of_len(32, 0x11);
        let psk_b = psk_of_len(32, 0x22);
        let svc =
            SsService::from_parts("2022-blake3-aes-256-gcm", &[psk_a, psk_b])
                .unwrap();

        for (i, psk) in [psk_of_len(32, 0x11), psk_of_len(32, 0x22)]
            .into_iter()
            .enumerate()
        {
            let salt = [i as u8 + 1; 32];
            let early = format!("user {i} early data").into_bytes();
            let request = build_client_request(
                kind,
                &base64::engine::general_purpose::STANDARD.decode(&psk).unwrap(),
                &salt,
                now_secs(),
                &test_dest(),
                8,
                &early,
            );

            let (mut client, server) = make_pair().await;
            {
                use tokio::io::AsyncWriteExt;
                client.write_all(&request).await.unwrap();
                drop(client);
            }
            let (mut stream, dest) =
                SsServerStream::accept(server, &svc).await.unwrap();
            assert_eq!(dest, test_dest());
            let mut buf = vec![0u8; 128];
            let n = stream.read(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], &early[..], "user {i}");
        }
    }

    // ── TCP 全链路（真实 outbound 客户端流）────────────────────────────────

    async fn tcp_loopback(method_name: &str) {
        let ksl = if method_name == "2022-blake3-aes-128-gcm" { 16 } else { 32 };
        let psk = psk_of_len(ksl, 0x42);
        tcp_loopback_with(method_name, &psk, &psk).await;
    }

    /// `server_user_password` 与 `client_password` 同串（镜像设计）：
    /// 单段 = 单 PSK；colon 多段 = iPSK:用户PSK（EIH 链 + 末段会话密钥）。
    async fn tcp_loopback_with(
        method_name: &str, server_user_password: &str, client_password: &str,
    ) {
        let svc =
            SsService::from_parts(method_name, &[server_user_password]).unwrap();
        let method =
            CipherMethod::new(method_name, client_password).expect("client method");
        let dest = test_dest();

        let (client_conn, server_conn) = make_pair().await;

        let payload1 = b"hello early".to_vec();
        let payload2 = vec![0x5Bu8; 40000]; // 超过请求缓冲 → early + 分块
        let mut expected = payload1.clone();
        expected.extend_from_slice(&payload2);
        let response1: &[u8] = b"HTTP/1.1 200 OK";
        let response2: &[u8] = &vec![0x77u8; 17000]; // 首块 + 后续分块

        let client_task = tokio::spawn(async move {
            let mut s = SsTcpStream::new(client_conn, method, dest);
            s.write(&payload1).await.unwrap();
            s.write(&payload2).await.unwrap();
            s.shutdown().await.unwrap();
            let mut got = Vec::new();
            let mut buf = vec![0u8; 4096];
            loop {
                let n = s.read(&mut buf).await.unwrap();
                if n == 0 {
                    break;
                }
                got.extend_from_slice(&buf[..n]);
            }
            got
        });

        let (mut server, parsed_dest) =
            SsServerStream::accept(server_conn, &svc).await.unwrap();
        assert_eq!(parsed_dest, test_dest());

        // 读到 EOF（客户端 shutdown），校验请求载荷。
        let mut received = Vec::new();
        let mut buf = vec![0u8; 8192];
        loop {
            let n = server.read(&mut buf).await.unwrap();
            if n == 0 {
                break;
            }
            received.extend_from_slice(&buf[..n]);
        }
        assert_eq!(received, expected);

        // 响应：首次写（响应头 + 首块）+ 后续写（数据分块）。
        server.write(response1).await.unwrap();
        server.write(response2).await.unwrap();
        drop(server); // 客户端读到 EOF

        let got = client_task.await.unwrap();
        let mut expected_resp = response1.to_vec();
        expected_resp.extend_from_slice(response2);
        assert_eq!(got, expected_resp);
    }

    #[tokio::test]
    async fn tcp_loopback_aes128() {
        tcp_loopback("2022-blake3-aes-128-gcm").await;
    }

    #[tokio::test]
    async fn tcp_loopback_aes256() {
        tcp_loopback("2022-blake3-aes-256-gcm").await;
    }

    #[tokio::test]
    async fn tcp_loopback_chacha20() {
        tcp_loopback("2022-blake3-chacha20-poly1305").await;
    }

    // ── UDP ────────────────────────────────────────────────────────────────

    /// 单用户 UDP 双向往返：真实 `SsUdpRelay` 作为客户端。
    async fn udp_loopback(method_name: &str) {
        let psk = psk_of_len(32, 0x77);
        udp_loopback_with(method_name, &psk, &psk).await;
    }

    /// UDP 双向往返（server 用户条目与 client password 同串，支持多段）。
    async fn udp_loopback_with(
        method_name: &str, server_user_password: &str, client_password: &str,
    ) {
        let svc =
            SsService::from_parts(method_name, &[server_user_password]).unwrap();
        let method =
            CipherMethod::new(method_name, client_password).unwrap();

        let server_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server_sock.local_addr().unwrap();
        let client_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client_sock.connect(server_addr).await.unwrap();
        let mut relay = SsUdpRelay::new(client_sock, method);

        let dest = Destination::new(Address::Ipv4([8, 8, 8, 8]), 53);
        let payload = b"hello ss2022 udp";

        // 客户端 → 服务端。
        relay.write_packet(payload, &dest).await.unwrap();
        let mut buf = vec![0u8; 65535];
        let (n, from) = server_sock.recv_from(&mut buf).await.unwrap();
        let first_packet = buf[..n].to_vec();
        let req = parse_udp_request(&svc, &first_packet).unwrap();
        let mut core =
            UdpSessionCore::new(svc.kind, req.psk.clone(), req.session_id);
        let (got, got_dest) = core.accept(req).unwrap();
        assert_eq!(&got, payload);
        assert_eq!(got_dest, dest);

        // 服务端 → 客户端（响应头含客户端 sessionId 回显）。
        let reply = b"pong from server";
        let packet = core.build_response(reply, &dest);
        server_sock.send_to(&packet, from).await.unwrap();
        let mut rbuf = vec![0u8; 65535];
        let (rn, rdest) = relay.read_packet(&mut rbuf).await.unwrap();
        assert_eq!(&rbuf[..rn], reply);
        assert_eq!(rdest, dest);

        // 同会话第二个包正常。
        relay.write_packet(b"second", &dest).await.unwrap();
        let (n, _) = server_sock.recv_from(&mut buf).await.unwrap();
        let req = parse_udp_request(&svc, &buf[..n]).unwrap();
        core.accept(req).unwrap();

        // 重放第一个包 → 回放拒绝。
        let req = parse_udp_request(&svc, &first_packet).unwrap();
        let err = core.accept(req).expect_err("accept should fail");
        assert!(err.to_string().contains("packet id not unique"), "{err}");
    }

    #[tokio::test]
    async fn udp_loopback_aes256() {
        udp_loopback("2022-blake3-aes-256-gcm").await;
    }

    #[tokio::test]
    async fn udp_loopback_chacha20() {
        udp_loopback("2022-blake3-chacha20-poly1305").await;
    }

    /// 多用户 UDP：每个用户的 PSK 都能解析各自的包，未知 PSK 拒绝。
    #[tokio::test]
    async fn udp_multi_user_requests() {
        let kind = MethodKind::Aes256Gcm;
        let psk_a = psk_of_len(32, 0x11);
        let psk_b = psk_of_len(32, 0x22);
        let svc =
            SsService::from_parts("2022-blake3-aes-256-gcm", &[psk_a, psk_b])
                .unwrap();
        let dest = Destination::new(Address::Ipv4([1, 1, 1, 1]), 443);

        for (i, psk_bytes) in [[0x11u8; 32], [0x22u8; 32]]
            .into_iter()
            .enumerate()
        {
            let packet = build_udp_request_aes(
                kind,
                &psk_bytes,
                0x0102030405060708 + i as u64,
                i as u64,
                &dest,
                format!("packet from user {i}").as_bytes(),
                0,
            );
            let req = parse_udp_request(&svc, &packet).unwrap();
            assert_eq!(req.psk, psk_bytes, "须识别为发起用户的 PSK");
            let mut core =
                UdpSessionCore::new(svc.kind, req.psk.clone(), req.session_id);
            let (payload, got_dest) = core.accept(req).unwrap();
            assert_eq!(got_dest, dest);
            assert_eq!(payload, format!("packet from user {i}").as_bytes());
        }

        // 未知 PSK → 拒绝。
        let packet = build_udp_request_aes(
            kind,
            &[0x99u8; 32],
            0x1111111111111111,
            0,
            &dest,
            b"x",
            0,
        );
        let err = parse_udp_request(&svc, &packet)
            .err()
            .expect("parse should fail");
        assert!(err.to_string().contains("no user key matches"), "{err}");
    }

    #[tokio::test]
    async fn udp_session_rotation() {
        let kind = MethodKind::Aes256Gcm;
        let psk_bytes = [0x77u8; 32];
        let dest = Destination::new(Address::Domain("dns.google".to_string()), 53);

        let mut core = UdpSessionCore::new(kind, psk_bytes.to_vec(), 100);
        // 会话 100, packetId 0。
        let req = UdpRequest {
            session_id: 100,
            packet_id: 0,
            body: udp_body_for(&dest, b"a"),
            psk: psk_bytes.to_vec(),
        };
        core.accept(req).unwrap();
        // 会话 100, packetId 1。
        let req = UdpRequest {
            session_id: 100,
            packet_id: 1,
            body: udp_body_for(&dest, b"b"),
            psk: psk_bytes.to_vec(),
        };
        core.accept(req).unwrap();

        // 轮换到会话 200（新窗口）。
        let req = UdpRequest {
            session_id: 200,
            packet_id: 0,
            body: udp_body_for(&dest, b"c"),
            psk: psk_bytes.to_vec(),
        };
        core.accept(req).unwrap();
        assert_eq!(core.session_id, 200);
        assert_eq!(core.last_session_id, 100);

        // 会话 100 的包仍按其旧窗口校验（重放被拒）。
        let req = UdpRequest {
            session_id: 100,
            packet_id: 0,
            body: udp_body_for(&dest, b"d"),
            psk: psk_bytes.to_vec(),
        };
        let err = core.accept(req).expect_err("accept should fail");
        assert!(err.to_string().contains("packet id not unique"), "{err}");

        // 会话 100 的新 packetId 可用（旧窗口）。
        let req = UdpRequest {
            session_id: 100,
            packet_id: 2,
            body: udp_body_for(&dest, b"e"),
            psk: psk_bytes.to_vec(),
        };
        core.accept(req).unwrap();
    }

    #[test]
    fn parse_udp_body_validates() {
        let dest = test_dest();
        let body = udp_body_for(&dest, b"payload");
        let (payload, parsed) = parse_udp_body(&body).unwrap();
        assert_eq!(payload, b"payload");
        assert_eq!(parsed, dest);

        // 带 padding。
        let mut padded = udp_body_for(&dest, b"p");
        padded[9..11].copy_from_slice(&24u16.to_be_bytes());
        padded.splice(11..11, vec![0u8; 24]);
        let (payload, _) = parse_udp_body(&padded).unwrap();
        assert_eq!(payload, b"p");

        // 坏 header type。
        let mut bad = udp_body_for(&dest, b"x");
        bad[0] = HEADER_TYPE_SERVER;
        assert!(parse_udp_body(&bad).is_err());

        // 坏时间戳。
        let mut bad = udp_body_for(&dest, b"x");
        let old = (now_secs() - 3600).to_be_bytes();
        bad[1..9].copy_from_slice(&old);
        assert!(parse_udp_body(&bad).is_err());

        // padding 越界。
        let mut bad = udp_body_for(&dest, b"x");
        bad[9..11].copy_from_slice(&900u16.to_be_bytes());
        assert!(parse_udp_body(&bad).is_err());

        // 体长不足。
        assert!(parse_udp_body(&[0u8; 5]).is_err());
    }

    #[tokio::test]
    async fn udp_request_too_short() {
        let svc =
            SsService::from_parts("2022-blake3-aes-256-gcm", &[psk_of_len(32, 1)])
                .unwrap();
        let err = parse_udp_request(&svc, &[0u8; 10])
            .err()
            .expect("parse should fail");
        assert!(err.to_string().contains("packet too short"), "{err}");

        let chacha = SsService::from_parts(
            "2022-blake3-chacha20-poly1305",
            &[psk_of_len(32, 1)],
        )
        .unwrap();
        let err = parse_udp_request(&chacha, &[0u8; 40])
            .err()
            .expect("parse should fail");
        assert!(err.to_string().contains("packet too short"), "{err}");
    }

    // ── 多段 password（outbound 同构）─────────────────────────────────────

    /// 服务端用户条目与客户端 password 同为 "iPSK:用户PSK"：真实 outbound
    /// 生成 EIH 链，服务端校验链并用末段派生会话密钥，双向通。
    #[tokio::test]
    async fn tcp_loopback_multi_segment_password() {
        let ipsk = psk_of_len(32, 0x11);
        let user_psk = psk_of_len(32, 0x22);
        let password = format!("{ipsk}:{user_psk}");
        tcp_loopback_with("2022-blake3-aes-256-gcm", &password, &password).await;
    }

    /// 多段 password 的 UDP 双向往返（EIH 块 + 末段会话密钥）。
    #[tokio::test]
    async fn udp_loopback_multi_segment_password() {
        let ipsk = psk_of_len(32, 0x11);
        let user_psk = psk_of_len(32, 0x22);
        let password = format!("{ipsk}:{user_psk}");
        udp_loopback_with("2022-blake3-aes-256-gcm", &password, &password).await;
    }

    /// 三段 password（iPSK:u1:u2，两条 EIH + 末段会话密钥）。
    #[tokio::test]
    async fn tcp_loopback_three_segment_password() {
        let password = format!(
            "{}:{}:{}",
            psk_of_len(32, 0x11),
            psk_of_len(32, 0x22),
            psk_of_len(32, 0x33)
        );
        tcp_loopback_with("2022-blake3-aes-256-gcm", &password, &password).await;
    }

    /// iPSK 不匹配的多段客户端被拒绝（EIH 链校验失败 → no user key matches）。
    #[tokio::test]
    async fn tcp_rejects_wrong_identity_psk() {
        let user_psk = psk_of_len(32, 0x22);
        let server_password = format!("{}:{}", psk_of_len(32, 0x11), user_psk);
        let client_password =
            format!("{}:{}", psk_of_len(32, 0x99), user_psk); // iPSK 不同
        let svc =
            SsService::from_parts("2022-blake3-aes-256-gcm", &[server_password])
                .unwrap();
        let method =
            CipherMethod::new("2022-blake3-aes-256-gcm", &client_password)
                .unwrap();
        let dest = test_dest();

        let (client_conn, server_conn) = make_pair().await;
        let client_task = tokio::spawn(async move {
            let mut s = SsTcpStream::new(client_conn, method, dest);
            s.write(b"hello").await.unwrap();
            let mut buf = vec![0u8; 64];
            s.read(&mut buf).await
        });

        let err = SsServerStream::accept(server_conn, &svc)
            .await
            .err()
            .expect("accept should fail");
        assert!(err.to_string().contains("no user key matches"), "{err}");
        // 客户端读响应失败（服务端已断开）。
        assert!(client_task.await.unwrap().is_err());
    }

    // ── 常量一致性 ─────────────────────────────────────────────────────────

    #[test]
    fn constants_match_sing() {
        assert_eq!(PACKET_MINIMAL_HEADER_SIZE, 30);
        assert_eq!(MAX_PADDING_LENGTH, 900);
        assert_eq!(MAX_PACKET_SIZE, 16383);
    }
}
