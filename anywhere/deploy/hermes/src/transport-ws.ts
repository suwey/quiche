// WebSocket 多路复用通道（自定义帧 + 流ID + AES-XOR 混淆）。
// 使用 DO hibernation 模式：由 DO 的 webSocketMessage / webSocketClose 驱动。

import { log } from './state';
import { 帧首帧标记, 帧关闭标记, WS早期数据最大字节, WS早期数据最大头长度 } from './state';
import { 编码帧, 解码Varint, 数据转Uint8Array, 拼接字节数据, isSpeedTestSite, closeSocketQuietly } from './utils';
import { 解析魏烈思请求, 解码WS早期数据 } from './protocol';
import { forwardataTCP, forwardataudp, 创建请求TCP连接器 } from './forward';
import type { RemoteConnWrapper } from './forward';
import type { TCPSocket, TCPConnector } from './types';

interface StreamRecord {
	remoteConn: RemoteConnWrapper;
	关闭标记: boolean;
	// 上行写入串行链：保证同一流的多个 ws 帧按到达顺序写入远端 socket。
	// WritableStream writer 是独占锁，并发 getWriter() 会抛错丢数据。
	上行写入链: Promise<void>;
}

/** `处理WS请求` 返回给 DO 的交接信息。 */
export interface WSHandoff {
	response: Response;
	serverSock: WebSocket;
	session: WebSocketSession;
}

/** 单条 WebSocket 连接的全部状态，供 DO hibernation 模式使用。 */
export class WebSocketSession {
	readonly serverSock: WebSocket;
	readonly yourUUID: string;
	private readonly tcpConnector: TCPConnector;

	private 混淆密钥: Uint8Array;
	private 发送计数器 = 0n;
	private 接收计数器 = 0n;
	private readonly 空闲超时ms = 120_000;
	private 空闲定时器: ReturnType<typeof setTimeout> | null = null;
	private 流映射 = new Map<number, StreamRecord>();
	private 流待发队列 = new Map<number, Uint8Array[]>();
	// 发送串行链：保证 serverSock.send 调用顺序与 counter 分配顺序一致。
	// counter 在调用方同步分配后立即返回 promise，加密 (await digest) 与其他流
	// 并行计算；只有最后的 send 串行——这样慢加密不会阻塞快加密的发送。
	private 发送串行链: Promise<void> = Promise.resolve();
	// 诊断 + 流控：追踪发送字节累计、自上次宏任务让出以来的字节预算。
	private 累计发送字节 = 0;
	private 上次诊断字节 = 0;
	private 上次诊断时间 = Date.now();
	// 自上次 setTimeout 让出以来已 send 的字节数。超阈值强制让 CF I/O 泵。
	private 自上次让出字节 = 0;
	private readonly 让出阈值字节 = 64 * 1024;

	constructor(
		serverSock: WebSocket, 混淆密钥: Uint8Array,
		yourUUID: string, tcpConnector: TCPConnector,
	) {
		this.serverSock = serverSock;
		this.混淆密钥 = 混淆密钥;
		this.yourUUID = yourUUID;
		this.tcpConnector = tcpConnector;
		this.重置空闲超时();
	}

	/** 处理来自客户端的 WebSocket 消息（由 DO 的 webSocketMessage 调用）。 */
	handleMessage(message: string | ArrayBuffer): void {
		const data = 数据转Uint8Array(
			message as ArrayBuffer | ArrayBufferView | Uint8Array,
		);
		this.处理传入帧(data).catch(() => {});
	}

	/** 处理 WebSocket 关闭（由 DO 的 webSocketClose 调用）。 */
	handleClose(): void {
		for (const [, s] of this.流映射) {
			try { s.remoteConn.socket?.close(); } catch { /* ignore */ }
		}
		this.流映射.clear();
		this.流待发队列.clear();
		clearTimeout(this.空闲定时器 ?? null);
		this.空闲定时器 = null;
	}

	/** 处理 WebSocket 错误（由 DO 的 webSocketError 调用）。 */
	handleError(): void {
		this.handleClose();
	}

	/** 处理 sec-websocket-protocol 早期数据（在 fetch() 返回前调用）。 */
	processEarlyData(earlyDataHeader: string): void {
		(async () => {
			try {
				const ec = 解码WS早期数据(
					earlyDataHeader, this.yourUUID,
					WS早期数据最大字节, WS早期数据最大头长度,
				);
				if (ec?.byteLength) {
					const data = 数据转Uint8Array(ec);
					let 流ID: number;
					let flags: number;
					let payload: Uint8Array;
					try {
						const r1 = 解码Varint(data, 0);
						流ID = r1.value;
						const sidLen = r1.bytesRead;
						flags = data[sidLen];
						payload = data.subarray(sidLen + 1);
					} catch {
						return;
					}
					if (流ID !== 0 && payload.byteLength > 0 &&
						!(flags & 帧关闭标记)) {
						payload = await this.解密有效载荷(flags, payload);
					}
					if (流ID !== 0 && flags & 帧首帧标记) {
						this.处理首帧(流ID, payload)
							.catch((err) => log(`[流#${流ID}] 错误: ${err}`));
					}
				}
			} catch { /* ignore */ }
		})();
	}

	private 重置空闲超时(): void {
		clearTimeout(this.空闲定时器 ?? null);
		this.空闲定时器 = setTimeout(() => {
			log('[空闲] 超时关闭');
			closeSocketQuietly(this.serverSock);
		}, this.空闲超时ms);
	}

	private 加密并发送(
		streamId: number, flags: number, raw: Uint8Array | null,
	): Promise<void> {
		const payload = raw || new Uint8Array(0);
		// counter 分配是同步的，立刻就绪——此时调用方的 counter 即为协议顺序。
		// 加密本身（await crypto.subtle.digest）可与其他流并行。
		// 只有最后的 serverSock.send 需要按 counter 顺序串行，所以串行链
		// await 的是"密文 ready"这个 promise，而不是整个加密过程。
		let ciphertextPromise: Promise<Uint8Array>;
		if (payload.byteLength > 0) {
			const counter = this.发送计数器++;
			ciphertextPromise = this.异步加密(counter, payload);
		} else {
			ciphertextPromise = Promise.resolve(payload);
		}

		const 本次任务 = this.发送串行链.then(async () => {
			const enc = await ciphertextPromise;
			const frame = 编码帧(streamId, flags, enc);
			try {
				this.serverSock.send(frame);
				this.累计发送字节 += frame.byteLength;
				this.自上次让出字节 += frame.byteLength;
				// 周期性诊断：每 50MB 或 30s 一行（仅高流量场景偶现）。
				const now = Date.now();
				if (
					this.累计发送字节 - this.上次诊断字节 >= 50 * 1024 * 1024 ||
					now - this.上次诊断时间 >= 30_000
				) {
					const 周期字节 = this.累计发送字节 - this.上次诊断字节;
					const 周期毫秒 = now - this.上次诊断时间;
					if (周期字节 > 0) {
						const 速率MBps = (周期字节 / 1024 / 1024) / (周期毫秒 / 1000);
						log(`[WS发送] ${速率MBps.toFixed(2)}MB/s, 总计 ${(this.累计发送字节 / 1024 / 1024).toFixed(1)}MB`);
					}
					this.上次诊断字节 = this.累计发送字节;
					this.上次诊断时间 = now;
				}
				// 流控：累计 send 字节超过阈值时让出宏任务，让 CF runtime
				// 把 WS 内部 buffer 写到 TCP。microtask (await Promise.resolve)
				// 优先级太高，不给 I/O 泵机会。
				if (this.自上次让出字节 >= this.让出阈值字节) {
					this.自上次让出字节 = 0;
					await new Promise<void>(resolve => setTimeout(resolve, 0));
				}
			} catch (err) {
				log(`[WS发送] send 失败: ${(err as { message?: string })?.message ?? err}`);
			}
		});
		this.发送串行链 = 本次任务.catch(() => { /* ignore */ });
		return 本次任务;
	}

	private async 异步加密(
		counter: bigint, payload: Uint8Array,
	): Promise<Uint8Array> {
		const counterBytes = new Uint8Array(8);
		new DataView(counterBytes.buffer).setBigUint64(0, counter, true);
		const hash = new Uint8Array(
			await crypto.subtle.digest(
				'SHA-256',
				new Uint8Array([...this.混淆密钥, ...counterBytes]),
			),
		);
		const enc = new Uint8Array(payload.byteLength);
		for (let i = 0; i < payload.byteLength; i++) {
			enc[i] = payload[i] ^ hash[i % 32];
		}
		return enc;
	}

	private 发送帧到客户端(
		streamId: number, flags: number, data: Uint8Array | null,
	): Promise<void> {
		if (this.serverSock.readyState !== WebSocket.OPEN) {
			return Promise.resolve();
		}
		return this.加密并发送(streamId, flags, data);
	}

	private 关闭流(streamId: number): void {
		log(`[流#${streamId}] 关闭流 called, exists=${this.流映射.has(streamId)}`);
		const s = this.流映射.get(streamId);
		if (s) {
			// CLOSE frame must respect the send order: enqueue on the
			// serial chain so it arrives AFTER any pending data frames.
			// Bypassing the chain would let CLOSE overtake data still being
			// encrypted, causing the client to see early stream termination
			// and drop subsequent (in-flight) bytes.
			const closeTask = this.发送串行链.then(() => {
				const frame = 编码帧(streamId, 帧关闭标记, new Uint8Array(0));
				try { this.serverSock.send(frame); } catch { /* ignore */ }
			});
			this.发送串行链 = closeTask.catch(() => { /* ignore */ });
			try { s.remoteConn.socket?.close(); } catch { /* ignore */ }
			this.流映射.delete(streamId);
			this.流待发队列.delete(streamId);
		}
		this.重置空闲超时();
	}

	private 创建StreamWS(streamId: number) {
		const self = this;
		return {
			get readyState(): number { return self.serverSock.readyState; },
			send: (
				data: Uint8Array | ArrayBuffer | ArrayBufferView,
			): Promise<void> => {
				return self.发送帧到客户端(
					streamId, 0, 数据转Uint8Array(data),
				);
			},
			close: (): void => { self.关闭流(streamId); },
		};
	}

	private 创建RemoteConn(streamId: number): RemoteConnWrapper {
		const self = this;
		let _socket: TCPSocket | null = null;
		const wrapper: RemoteConnWrapper = {
			connectingPromise: null,
			retryConnect: null,
			socketWritePromise: null as Promise<void> | null,
			get socket() { return _socket; },
			set socket(value: TCPSocket | null) {
				_socket = value;
				if (value) {
					const pending = self.流待发队列.get(streamId);
					if (pending && pending.length > 0) {
						const arr = pending.splice(0);
						self.流待发队列.delete(streamId);
						wrapper.socketWritePromise = (async () => {
							try {
								const writer = value.writable.getWriter();
								for (const pkt of arr) {
									try { await writer.write(pkt); }
									catch { /* ignore */ }
								}
								try { writer.releaseLock(); }
								catch { /* ignore */ }
							} catch { /* ignore */ }
							finally { wrapper.socketWritePromise = null; }
						})();
					}
				}
			},
		};
		return wrapper;
	}

	private 解密有效载荷(
		flags: number, payload: Uint8Array,
	): Promise<Uint8Array> {
		if (!payload || payload.byteLength === 0 || flags & 帧关闭标记) {
			return Promise.resolve(payload);
		}
		// counter 分配是同步的，立刻就绪——调用顺序 = WS 消息到达顺序 = 协议顺序。
		// 加密用 sync counter + async digest，让多帧解密可以并行计算。
		const counter = this.接收计数器++;
		return this.异步解密(counter, payload);
	}

	private async 异步解密(
		counter: bigint, payload: Uint8Array,
	): Promise<Uint8Array> {
		const counterBytes = new Uint8Array(8);
		new DataView(counterBytes.buffer).setBigUint64(0, counter, true);
		const hash = new Uint8Array(
			await crypto.subtle.digest(
				'SHA-256',
				new Uint8Array([...this.混淆密钥, ...counterBytes]),
			),
		);
		const dec = new Uint8Array(payload.byteLength);
		for (let i = 0; i < payload.byteLength; i++) {
			dec[i] = payload[i] ^ hash[i % 32];
		}
		return dec;
	}

	private async 处理首帧(
		streamId: number, payload: Uint8Array,
	): Promise<void> {
		const 流WS = this.创建StreamWS(streamId);
		const 流remoteConn = this.创建RemoteConn(streamId);
		this.流映射.set(streamId, {
			remoteConn: 流remoteConn, 关闭标记: false,
			上行写入链: Promise.resolve(),
		});

		try {
			const 解析结果 = 解析魏烈思请求(payload, this.yourUUID);
			if (解析结果.hasError) {
				log(`[流#${streamId}] 魏烈思解析失败: ${解析结果.message}`);
				this.关闭流(streamId);
				return;
			}
			const { port, hostname, version, isUDP, rawClientData } = 解析结果;
			if (isSpeedTestSite(hostname)) {
				this.关闭流(streamId);
				return;
			}
			if (isUDP) {
				if (port !== 53) {
					this.关闭流(streamId);
					return;
				}
				log(`[流#${streamId}] UDP DNS -> 8.8.4.4:53`);
				let tcpDNS查询: Uint8Array = rawClientData;
				if (rawClientData.byteLength < 2 ||
					((rawClientData[0] << 8) | rawClientData[1]) !==
						rawClientData.byteLength - 2) {
					tcpDNS查询 = new Uint8Array(rawClientData.byteLength + 2);
					tcpDNS查询[0] = (rawClientData.byteLength >>> 8) & 0xff;
					tcpDNS查询[1] = rawClientData.byteLength & 0xff;
					tcpDNS查询.set(rawClientData, 2);
				}
				const dns响应上下文 = { 缓存: new Uint8Array(0) };
				await forwardataudp(
					tcpDNS查询, 流WS, null, null,
					(dnsRespChunk) => {
						const 当前响应块 = 数据转Uint8Array(dnsRespChunk);
						const 响应输入 = dns响应上下文.缓存.byteLength
							? 拼接字节数据(
								dns响应上下文.缓存, 当前响应块,
							)
							: 当前响应块;
						const 响应帧列表: Uint8Array[] = [];
						let responseCursor = 0;
						while (
							responseCursor + 2 <= 响应输入.byteLength
						) {
							const dnsLen = (
								响应输入[responseCursor] << 8
							) | 响应输入[responseCursor + 1];
							const dnsStart = responseCursor + 2;
							const dnsEnd = dnsStart + dnsLen;
							if (dnsEnd > 响应输入.byteLength) break;
							响应帧列表.push(
								响应输入.slice(dnsStart, dnsEnd),
							);
							responseCursor = dnsEnd;
						}
						dns响应上下文.缓存 = 响应输入.slice(responseCursor);
						return 响应帧列表.length
							? 响应帧列表
							: new Uint8Array(0);
					},
					this.tcpConnector,
				);
				this.关闭流(streamId);
				return;
			}
			const respHeader = new Uint8Array([version ?? 0, 0]);
			log(`[流#${streamId}] TCP ${hostname}:${port}`);
			await forwardataTCP(
				hostname, port, rawClientData, 流WS, respHeader,
				流remoteConn, this.yourUUID, null, this.tcpConnector,
			);
			log(`[流#${streamId}] TCP 转发结束，关闭流`);
			this.关闭流(streamId);
		} catch (err) {
			log(
				`[流#${streamId}] 错误: ${
					(err as { message?: string })?.message || err
				}`,
			);
			this.关闭流(streamId);
		}
	}

	private async 处理传入帧(data: Uint8Array): Promise<void> {
		if (data.byteLength === 0) return;
		let 流ID: number;
		let flags: number;
		let payload: Uint8Array;
		try {
			const r1 = 解码Varint(data, 0);
			流ID = r1.value;
			const sidLen = r1.bytesRead;
			flags = data[sidLen];
			const r2 = 解码Varint(data, sidLen + 1);
			const payloadLen = r2.value;
			const payloadStart = sidLen + 1 + r2.bytesRead;
			payload = data.subarray(payloadStart, payloadStart + payloadLen);
		} catch {
			return;
		}

		this.重置空闲超时();
		if (流ID === 0) return;

		// 解密在这里启动（sync counter 分配，async digest），返回 promise。
		// 多帧解密可并行计算，但 counter 已按调用顺序锁定。
		const 明文Promise = payload.byteLength > 0 && !(flags & 帧关闭标记)
			? this.解密有效载荷(flags, payload)
			: Promise.resolve(payload);

		if (flags & 帧关闭标记) {
			const s = this.流映射.get(流ID);
			if (s) {
				try { s.remoteConn.socket?.close(); } catch { /* ignore */ }
			}
			this.流映射.delete(流ID);
			this.流待发队列.delete(流ID);
			this.重置空闲超时();
			return;
		}

		if (flags & 帧首帧标记) {
			// 首帧需要解密后才能解析协议，正常 await。首帧之间不存在串行约束。
			明文Promise
				.then((plain) => this.处理首帧(流ID, plain))
				.catch((err) => log(`[流#${流ID}] 错误: ${err}`));
			return;
		}

		const s = this.流映射.get(流ID);
		if (!s || s.关闭标记) return;
		// 同步在流写入链上预占位：保证上行写入按 ws 到达顺序，即使解密乱序完成。
		const 等待pending = s.remoteConn.socketWritePromise
			? s.remoteConn.socketWritePromise.catch(() => { /* ignore */ })
			: Promise.resolve();
		const 本次写入 = Promise.all([s.上行写入链, 等待pending]).then(async () => {
			if (s.关闭标记) return;
			const plain = await 明文Promise;
			const targetSocket = s.remoteConn.socket;
			if (!targetSocket || plain.byteLength === 0) {
				if (plain.byteLength > 0) {
					log(`[流#${流ID}] 上行排队 ${plain.byteLength}B (socket未就绪)`);
					let queue = this.流待发队列.get(流ID);
					if (!queue) {
						queue = [];
						this.流待发队列.set(流ID, queue);
					}
					queue.push(plain);
				}
				return;
			}
			const writer = targetSocket.writable.getWriter();
			try { await writer.write(plain); }
			catch (err) {
				log(
					`[流#${流ID}] 上行写入失败: ${
						(err as { message?: string })?.message ?? err
					}`,
				);
			}
			finally { try { writer.releaseLock(); } catch { /* ignore */ } }
		});
		s.上行写入链 = 本次写入.catch(() => { /* ignore */ });
	}
}

export async function 处理WS请求(
	request: Request, yourUUID: string, _url: URL,
): Promise<WSHandoff> {
	void _url;
	const WS套接字对 = new WebSocketPair();
	const [clientSock, serverSockRaw] = Object.values(WS套接字对);
	const serverSock = serverSockRaw as WebSocket;
	serverSock.binaryType = 'arraybuffer';

	const 混淆密钥 = new Uint8Array(
		await crypto.subtle.digest(
			'SHA-256',
			new TextEncoder().encode(yourUUID + 'anywhere-obfuscation-v1'),
		),
	);
	// 在 fetch() 期间捕获 TCP connector，之后 DO hibernation 时 request.fetcher 不可用。
	const tcpConnector = 创建请求TCP连接器(request);
	const session = new WebSocketSession(
		serverSock, 混淆密钥, yourUUID, tcpConnector,
	);

	const earlyDataHeader =
		request.headers.get('sec-websocket-protocol') || '';
	if (earlyDataHeader) {
		session.processEarlyData(earlyDataHeader);
	}

	return {
		response: new Response(
			null,
			{
				status: 101, webSocket: clientSock,
				headers: { 'Sec-WebSocket-Extensions': '' },
			} as ResponseInit & { webSocket: WebSocket },
		),
		serverSock,
		session,
	};
}
