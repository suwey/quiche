// XHTTP 传输：可插拔架构（M5 重写）
//
// 使用与 WebSocket 相同的 mless 帧协议（stream_id + flags + encrypted payload），
// 通过 HTTP POST body 上行、HTTP response body 下行。
//
// 可插拔层：
// - ProtocolHandler: VLESS / Trojan 首包解析
// - CryptoHandler: AheadXor (SHA-256 CTR XOR) / None
// - ObfuscationHandler: XPadding 校验/生成 / None

import { log } from './state';
import { 帧首帧标记, 帧关闭标记 } from './state';
import { TOKENS } from './tokens';
import { 数据转Uint8Array, 有效数据长度, isSpeedTestSite, sha224, closeSocketQuietly, 编码帧, 解码Varint, 拼接字节数据 } from './utils';
import { UUID字节匹配, BLESS文本解码器 } from './protocol';
import { 创建上行写入队列, forwardataTCP, forwardataudp, 转发木马UDP数据 } from './forward';
import type { RemoteConnWrapper } from './forward';
import type { TCPSocket } from './types';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface XhttpFirstPacket {
	协议: string;
	hostname: string;
	port: number;
	isUDP: boolean;
	rawData: Uint8Array;
	respHeader: Uint8Array | null;
}

type ParsePartial = { 状态: 'need_more' | 'invalid' } | { 状态: 'ok'; 结果: XhttpFirstPacket };

interface ParsedFrame {
	streamId: number;
	flags: number;
	payload: Uint8Array;
}

// ---------------------------------------------------------------------------
// Pluggable interfaces
// ---------------------------------------------------------------------------

/** 协议处理器：解析首包、判断 UDP 权限 */
interface ProtocolHandler {
	/** 尝试解析首包 */
	parseFirstPacket(data: Uint8Array, token: string): ParsePartial;
	/** 是否允许 UDP */
	isUDPAllowed(result: XhttpFirstPacket): boolean;
}

/** 加密处理器 */
interface CryptoHandler {
	decrypt(data: Uint8Array): Promise<Uint8Array>;
	encrypt(data: Uint8Array): Promise<Uint8Array>;
}

/** 混淆处理器 */
interface ObfuscationHandler {
	/** 校验请求 padding */
	validateRequestPadding(request: Request): boolean;
	/** 生成响应 padding */
	generateResponsePadding(): { header: string; value: string } | null;
}

// ---------------------------------------------------------------------------
// Protocol handlers (reuse existing parsing logic)
// ---------------------------------------------------------------------------

class VlessHandler implements ProtocolHandler {
	parseFirstPacket(data: Uint8Array, token: string): ParsePartial {
		return 尝试解析魏烈思首包(data, token);
	}
	isUDPAllowed(result: XhttpFirstPacket): boolean {
		return result.port === 53;
	}
}

class TrojanHandler implements ProtocolHandler {
	parseFirstPacket(data: Uint8Array, token: string): ParsePartial {
		return 尝试解析木马首包(data, token);
	}
	isUDPAllowed(result: XhttpFirstPacket): boolean {
		return true; // Trojan UDP 全端口允许
	}
}

// ---------------------------------------------------------------------------
// VLESS / Trojan first packet parsing (preserved from original)
// ---------------------------------------------------------------------------

function 尝试解析魏烈思首包(data: Uint8Array, token: string): ParsePartial {
	const decoder = BLESS文本解码器;
	const length = data.byteLength;
	if (length < 18) return { 状态: 'need_more' };
	if (!UUID字节匹配(data, 1, token)) return { 状态: 'invalid' };

	const optLen = data[17];
	const cmdIndex = 18 + optLen;
	if (length < cmdIndex + 1) return { 状态: 'need_more' };

	const cmd = data[cmdIndex];
	if (cmd !== 1 && cmd !== 2) return { 状态: 'invalid' };

	const portIndex = cmdIndex + 1;
	if (length < portIndex + 3) return { 状态: 'need_more' };

	const port = (data[portIndex] << 8) | data[portIndex + 1];
	const addressType = data[portIndex + 2];
	const addressIndex = portIndex + 3;
	let headerLen = -1;
	let hostname = '';

	if (addressType === 1) {
		if (length < addressIndex + 4) return { 状态: 'need_more' };
		hostname = `${data[addressIndex]}.${data[addressIndex + 1]}.${data[addressIndex + 2]}.${data[addressIndex + 3]}`;
		headerLen = addressIndex + 4;
	} else if (addressType === 2) {
		if (length < addressIndex + 1) return { 状态: 'need_more' };
		const domainLen = data[addressIndex];
		if (length < addressIndex + 1 + domainLen) return { 状态: 'need_more' };
		hostname = decoder.decode(data.subarray(addressIndex + 1, addressIndex + 1 + domainLen));
		headerLen = addressIndex + 1 + domainLen;
	} else if (addressType === 3) {
		if (length < addressIndex + 16) return { 状态: 'need_more' };
		const ipv6: string[] = [];
		for (let i = 0; i < 8; i++) {
			const base = addressIndex + i * 2;
			ipv6.push(((data[base] << 8) | data[base + 1]).toString(16));
		}
		hostname = ipv6.join(':');
		headerLen = addressIndex + 16;
	} else return { 状态: 'invalid' };

	if (!hostname) return { 状态: 'invalid' };

	return {
		状态: 'ok',
		结果: {
			协议: 'vless',
			hostname,
			port,
			isUDP: cmd === 2,
			rawData: data.subarray(headerLen),
			respHeader: new Uint8Array([data[0], 0]),
		},
	};
}

function 尝试解析木马首包(data: Uint8Array, token: string): ParsePartial {
	const 密码哈希 = sha224(token);
	const 密码哈希字节 = new TextEncoder().encode(密码哈希);
	const length = data.byteLength;
	if (length < 58) return { 状态: 'need_more' };
	if (data[56] !== 0x0d || data[57] !== 0x0a) return { 状态: 'invalid' };
	for (let i = 0; i < 56; i++) {
		if (data[i] !== 密码哈希字节[i]) return { 状态: 'invalid' };
	}

	const socksStart = 58;
	if (length < socksStart + 2) return { 状态: 'need_more' };
	const cmd = data[socksStart];
	if (cmd !== 1 && cmd !== 3) return { 状态: 'invalid' };
	const isUDP = cmd === 3;

	const atype = data[socksStart + 1];
	let cursor = socksStart + 2;
	let hostname = '';

	if (atype === 1) {
		if (length < cursor + 4) return { 状态: 'need_more' };
		hostname = `${data[cursor]}.${data[cursor + 1]}.${data[cursor + 2]}.${data[cursor + 3]}`;
		cursor += 4;
	} else if (atype === 3) {
		if (length < cursor + 1) return { 状态: 'need_more' };
		const domainLen = data[cursor];
		if (length < cursor + 1 + domainLen) return { 状态: 'need_more' };
		hostname = BLESS文本解码器.decode(data.subarray(cursor + 1, cursor + 1 + domainLen));
		cursor += 1 + domainLen;
	} else if (atype === 4) {
		if (length < cursor + 16) return { 状态: 'need_more' };
		const ipv6: string[] = [];
		for (let i = 0; i < 8; i++) {
			const base = cursor + i * 2;
			ipv6.push(((data[base] << 8) | data[base + 1]).toString(16));
		}
		hostname = ipv6.join(':');
		cursor += 16;
	} else return { 状态: 'invalid' };

	if (!hostname) return { 状态: 'invalid' };
	if (length < cursor + 4) return { 状态: 'need_more' };

	const port = (data[cursor] << 8) | data[cursor + 1];
	if (data[cursor + 2] !== 0x0d || data[cursor + 3] !== 0x0a) return { 状态: 'invalid' };
	const dataOffset = cursor + 4;

	return {
		状态: 'ok',
		结果: {
			协议: 'trojan',
			hostname,
			port,
			isUDP,
			rawData: data.subarray(dataOffset),
			respHeader: null,
		},
	};
}

// ---------------------------------------------------------------------------
// Crypto handlers (extracted from WebSocketSession)
// ---------------------------------------------------------------------------

class AheadXorHandler implements CryptoHandler {
	private key: Uint8Array;
	private sendCounter = 0n;
	private recvCounter = 0n;

	constructor(uuid: string) {
		// Key = SHA-256(uuid_string || "anywhere-obfuscation-v1")
		// Matches client's Obfuscation::new(uuid_str)
		this.key = new Uint8Array(
			new ArrayBuffer(0), // placeholder, set in async init
		);
		// Store UUID for async key derivation
		this._uuid = uuid;
	}

	private _uuid: string;
	private _initialized = false;

	private async init(): Promise<void> {
		if (this._initialized) return;
		this.key = new Uint8Array(
			await crypto.subtle.digest(
				'SHA-256',
				new TextEncoder().encode(this._uuid + 'anywhere-obfuscation-v1'),
			),
		);
		this._initialized = true;
	}

	async decrypt(data: Uint8Array): Promise<Uint8Array> {
		if (data.byteLength === 0) return data;
		await this.init();
		const counter = this.recvCounter++;
		return this.xorWithKeystream(counter, data);
	}

	async encrypt(data: Uint8Array): Promise<Uint8Array> {
		if (data.byteLength === 0) return data;
		await this.init();
		const counter = this.sendCounter++;
		return this.xorWithKeystream(counter, data);
	}

	private async xorWithKeystream(counter: bigint, payload: Uint8Array): Promise<Uint8Array> {
		const counterBytes = new Uint8Array(8);
		new DataView(counterBytes.buffer).setBigUint64(0, counter, true);
		const hash = new Uint8Array(
			await crypto.subtle.digest(
				'SHA-256',
				new Uint8Array([...this.key, ...counterBytes]),
			),
		);
		const result = new Uint8Array(payload.byteLength);
		for (let i = 0; i < payload.byteLength; i++) {
			result[i] = payload[i] ^ hash[i % 32];
		}
		return result;
	}
}

class NoCryptoHandler implements CryptoHandler {
	async decrypt(data: Uint8Array): Promise<Uint8Array> { return data; }
	async encrypt(data: Uint8Array): Promise<Uint8Array> { return data; }
}

// ---------------------------------------------------------------------------
// Obfuscation handlers (XPadding auto-detect)
// ---------------------------------------------------------------------------

class XPaddingHandler implements ObfuscationHandler {
	// Default config: matches client's XPaddingConfig::default()
	private readonly minBytes = 100;
	private readonly maxBytes = 1000;

	validateRequestPadding(request: Request): boolean {
		// Auto-detect: check Referer for x_padding query param, or X-Padding header
		const referer = request.headers.get('Referer') || '';
		let padding: string | null = null;

		// Try Referer URL query: ?x_padding=...
		if (referer) {
			const match = referer.match(/[?&]x_padding=([^&]+)/);
			if (match) padding = decodeURIComponent(match[1]);
		}

		// Try X-Padding header
		if (!padding) {
			padding = request.headers.get('X-Padding');
		}

		// No padding present = valid (padding is optional)
		if (!padding) return true;

		// Validate length range
		const len = padding.length;
		return len >= this.minBytes && len <= this.maxBytes;
	}

	generateResponsePadding(): { header: string; value: string } | null {
		const len = this.minBytes + Math.floor(Math.random() * (this.maxBytes - this.minBytes + 1));
		return { header: 'X-Padding', value: 'X'.repeat(len) };
	}
}

class NoObfuscationHandler implements ObfuscationHandler {
	validateRequestPadding(_: Request): boolean { return true; }
	generateResponsePadding(): { header: string; value: string } | null { return null; }
}

// ---------------------------------------------------------------------------
// Frame parser (handles partial frames across chunk boundaries)
// ---------------------------------------------------------------------------

class FrameParser {
	private buffer: Uint8Array = new Uint8Array(0);

	/** Append data and return all complete frames parsed from the buffer. */
	feed(data: Uint8Array): ParsedFrame[] {
		if (data.byteLength === 0) return [];

		// Append to buffer
		if (this.buffer.byteLength === 0) {
			this.buffer = data.slice();
		} else {
			this.buffer = 拼接字节数据(this.buffer, data);
		}

		const frames: ParsedFrame[] = [];
		let offset = 0;

		while (offset < this.buffer.byteLength) {
			const frame = this.tryParseFrame(this.buffer, offset);
			if (!frame) break; // Need more data
			frames.push(frame.frame);
			offset += frame.consumed;
		}

		// Keep remaining bytes
		if (offset > 0) {
			this.buffer = this.buffer.slice(offset);
		}

		return frames;
	}

	private tryParseFrame(
		data: Uint8Array,
		offset: number,
	): { frame: ParsedFrame; consumed: number } | null {
		try {
			const r1 = 解码Varint(data, offset);
			const streamId = r1.value;
			const sidLen = r1.bytesRead;
			const flagsOffset = offset + sidLen;

			if (flagsOffset >= data.byteLength) return null; // Need more data
			const flags = data[flagsOffset];

			const r2 = 解码Varint(data, flagsOffset + 1);
			const payloadLen = Number(r2.value);
			const payloadStart = flagsOffset + 1 + r2.bytesRead;
			const payloadEnd = payloadStart + payloadLen;

			if (payloadEnd > data.byteLength) return null; // Need more data

			return {
				frame: {
					streamId,
					flags,
					payload: data.slice(payloadStart, payloadEnd),
				},
				consumed: payloadEnd - offset,
			};
		} catch {
			return null; // Invalid varint, need more data
		}
	}

	/** Get any remaining buffered data (for debugging). */
	get remaining(): number {
		return this.buffer.byteLength;
	}
}

// ---------------------------------------------------------------------------
// Main handler (M5 rewrite: mless frames over HTTP)
// ---------------------------------------------------------------------------

export async function 处理XHTTP请求(request: Request, yourUUID: string): Promise<Response> {
	if (!request.body) return new Response('Bad Request', { status: 400 });

	// 1. Create pluggable handlers
	const cryptoHandler: CryptoHandler = new AheadXorHandler(yourUUID);
	const obfHandler: ObfuscationHandler = new XPaddingHandler();
	const protocolHandlers: ProtocolHandler[] = [
		new TrojanHandler(),
		new VlessHandler(),
	];

	// 2. Validate request padding
	if (!obfHandler.validateRequestPadding(request)) {
		return new Response('Bad Request', { status: 400 });
	}

	// 3. Build response headers
	const responseHeaders = new Headers({
		'Content-Type': 'application/octet-stream',
		'X-Accel-Buffering': 'no',
		'Cache-Control': 'no-store',
	});
	const padding = obfHandler.generateResponsePadding();
	if (padding) responseHeaders.set(padding.header, padding.value);

	// 4. Set up streaming response
	const reader = request.body.getReader();
	const frameParser = new FrameParser();

	// Remote connection state
	const remoteConnWrapper: RemoteConnWrapper = {
		socket: null, connectingPromise: null, retryConnect: null, socketWritePromise: null,
	};
	let 当前写入Socket: TCPSocket | null = null;
	let 远端写入器: WritableStreamDefaultWriter<Uint8Array> | null = null;

	const 释放远端写入器 = (): void => {
		if (远端写入器) {
			try { 远端写入器.releaseLock(); } catch { /* ignore */ }
			远端写入器 = null;
		}
		当前写入Socket = null;
	};

	const 获取远端写入器 = (): WritableStreamDefaultWriter<Uint8Array> | null => {
		const socket = remoteConnWrapper.socket;
		if (!socket) return null;
		if (socket !== 当前写入Socket) {
			释放远端写入器();
			当前写入Socket = socket;
			远端写入器 = socket.writable.getWriter();
		}
		return 远端写入器;
	};

	let XHTTP上行写入队列: ReturnType<typeof 创建上行写入队列> | null = null;

	// Stream state (for stream-one: single stream)
	let firstFrameProcessed = false;
	let isUDP = false;
	let respHeader: Uint8Array | null = null;
	const 木马UDP上下文 = { 缓存: new Uint8Array(0) };

	return new Response(
		new ReadableStream<Uint8Array>({
			async start(controller) {
				let 已关闭 = false;

				// Bridge: writes encrypted mless frames to the response stream
				const xhttpBridge = {
					readyState: WebSocket.OPEN,
					send(data: Uint8Array | ArrayBuffer | ArrayBufferView): void {
						if (已关闭) return;
						try {
							const chunk = 数据转Uint8Array(data);
							// Encrypt and encode as DATA frame (streamId=1 for stream-one)
							cryptoHandler.encrypt(chunk).then((enc) => {
								const frame = 编码帧(1, 0, enc);
								try { controller.enqueue(frame); }
								catch { /* controller closed */ }
							}).catch(() => {});
						} catch {
							已关闭 = true;
							xhttpBridge.readyState = WebSocket.CLOSED;
						}
					},
					close(): void {
						if (已关闭) return;
						已关闭 = true;
						xhttpBridge.readyState = WebSocket.CLOSED;
						// Send CLOSE frame
						const closeFrame = 编码帧(1, 帧关闭标记, new Uint8Array(0));
						try { controller.enqueue(closeFrame); } catch { /* ignore */ }
						try { controller.close(); } catch { /* ignore */ }
					},
				};

				const 上行写入队列 = (XHTTP上行写入队列 = 创建上行写入队列({
					获取写入器: 获取远端写入器,
					释放写入器: 释放远端写入器,
					重试连接: async () => {
						if (typeof remoteConnWrapper.retryConnect !== 'function') throw new Error('retry unavailable');
						await remoteConnWrapper.retryConnect();
					},
					关闭连接: () => {
						try { remoteConnWrapper.socket?.close(); } catch { /* ignore */ }
						closeSocketQuietly(xhttpBridge);
					},
					名称: 'XHTTP上行',
				}));

				const 写入远端 = async (payload: Uint8Array, allowRetry = true): Promise<boolean> => {
					const r = 上行写入队列.写入并等待(payload, allowRetry);
					return r === true ? true : await r;
				};

				// Process a decrypted FIRST frame: parse protocol, connect remote
				const processFirstFrame = async (payload: Uint8Array): Promise<void> => {
					// Try each protocol handler
					for (const handler of protocolHandlers) {
						const result = handler.parseFirstPacket(payload, yourUUID);
						if (result.状态 === 'ok') {
							const 首包 = result.结果;
							if (isSpeedTestSite(首包.hostname)) {
								log(`[XHTTP] 拒绝测速站: ${首包.hostname}`);
								closeSocketQuietly(xhttpBridge);
								return;
							}
							isUDP = 首包.isUDP;
							respHeader = 首包.respHeader;

							if (!handler.isUDPAllowed(首包)) {
								log(`[XHTTP] UDP 不允许: ${首包.hostname}:${首包.port}`);
								closeSocketQuietly(xhttpBridge);
								return;
							}

							log(`[XHTTP] ${首包.协议} ${首包.isUDP ? 'UDP' : 'TCP'} ${首包.hostname}:${首包.port}`);

							if (首包.isUDP) {
								if (首包.rawData?.byteLength) {
									if (首包.协议 === 'trojan') {
										await 转发木马UDP数据(首包.rawData, xhttpBridge as Parameters<typeof 转发木马UDP数据>[1], 木马UDP上下文, request);
									} else {
										await forwardataudp(首包.rawData, xhttpBridge as Parameters<typeof forwardataudp>[1], respHeader, request);
										respHeader = null;
									}
								}
							} else {
								await forwardataTCP(
									首包.hostname, 首包.port, 首包.rawData,
									xhttpBridge as Parameters<typeof forwardataTCP>[3],
									首包.respHeader, remoteConnWrapper, yourUUID, request,
								);
							}
							return;
						}
						if (result.状态 === 'invalid') continue; // Try next handler
						// 'need_more' - shouldn't happen for FIRST frame, but try next
					}
					// All handlers failed
					log(`[XHTTP] 首包解析失败`);
					closeSocketQuietly(xhttpBridge);
				};

				try {
					// 5. Read HTTP body, parse frames, decrypt, process
					for (;;) {
						const { done, value } = await reader.read();
						if (done) break;
						if (!value || value.byteLength === 0) continue;

						const frames = frameParser.feed(数据转Uint8Array(value));

						for (const frame of frames) {
							if (frame.streamId === 0) continue;

							// CLOSE frame
							if (frame.flags & 帧关闭标记) {
								try { remoteConnWrapper.socket?.close(); } catch { /* ignore */ }
								continue;
							}

							// Decrypt payload
							const plaintext = frame.payload.byteLength > 0
								? await cryptoHandler.decrypt(frame.payload)
								: frame.payload;

							// FIRST frame: parse protocol, establish remote
							if (frame.flags & 帧首帧标记) {
								if (!firstFrameProcessed) {
									firstFrameProcessed = true;
									await processFirstFrame(plaintext);
								}
								continue;
							}

							// DATA frame: forward to remote
							if (isUDP) {
								// For UDP, use the bridge directly
								const 首包协议 = protocolHandlers[0]; // Determine from firstFrame...
								// For simplicity, reuse the same UDP forwarding
								await forwardataudp(plaintext, xhttpBridge as Parameters<typeof forwardataudp>[1], respHeader, request);
								respHeader = null;
							} else {
								if (!(await 写入远端(plaintext))) {
									throw new Error('Remote socket is not ready');
								}
							}
						}
					}

					// 6. Flush upload queue and close remote
					if (!isUDP) {
						await 上行写入队列.等待空();
						const writer = 获取远端写入器();
						if (writer) {
							try { await writer.close(); } catch { /* ignore */ }
						}
					}
				} catch (err) {
					log(`[XHTTP转发] 处理失败: ${(err as { message?: string })?.message || err}`);
					closeSocketQuietly(xhttpBridge);
				} finally {
					上行写入队列.清空();
					释放远端写入器();
					try { reader.releaseLock(); } catch { /* ignore */ }
					// Ensure response stream is closed
					try { controller.close(); } catch { /* ignore */ }
				}
				void 有效数据长度;
				void TOKENS;
			},
			cancel() {
				XHTTP上行写入队列?.清空();
				try { remoteConnWrapper.socket?.close(); } catch { /* ignore */ }
				释放远端写入器();
				try { reader.releaseLock(); } catch { /* ignore */ }
			},
		}),
		{ status: 200, headers: responseHeaders },
	);
}
