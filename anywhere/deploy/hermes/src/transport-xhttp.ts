// XHTTP 单向传输：前端读 ReadableStream，后端写 controller.enqueue。

import { log } from './state';
import { TOKENS } from './tokens';
import { 数据转Uint8Array, 有效数据长度, isSpeedTestSite, sha224, closeSocketQuietly } from './utils';
import { UUID字节匹配, BLESS文本解码器 } from './protocol';
import { 创建上行写入队列, forwardataTCP, forwardataudp, 转发木马UDP数据 } from './forward';
import type { RemoteConnWrapper } from './forward';
import type { TCPSocket } from './types';

interface XhttpFirstPacket {
	协议: string;
	hostname: string;
	port: number;
	isUDP: boolean;
	rawData: Uint8Array;
	respHeader: Uint8Array | null;
}

type ParsePartial = { 状态: 'need_more' | 'invalid' } | { 状态: 'ok'; 结果: XhttpFirstPacket };

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

interface XhttpFirstPacketWithReader extends XhttpFirstPacket {
	reader: ReadableStreamDefaultReader<Uint8Array>;
}

async function 读取XHTTP首包(reader: ReadableStreamDefaultReader<Uint8Array>, token: string): Promise<XhttpFirstPacketWithReader | null> {
	let buffer = new Uint8Array(1024);
	let offset = 0;

	for (;;) {
		const { value, done } = await reader.read();
		if (done) {
			if (offset === 0) return null;
			break;
		}

		const chunk = value instanceof Uint8Array ? value : new Uint8Array(value);
		if (offset + chunk.byteLength > buffer.byteLength) {
			const newBuffer = new Uint8Array(Math.max(buffer.byteLength * 2, offset + chunk.byteLength));
			newBuffer.set(buffer.subarray(0, offset));
			buffer = newBuffer;
		}

		buffer.set(chunk, offset);
		offset += chunk.byteLength;

		const 当前数据 = buffer.subarray(0, offset);
		const 木马结果 = 尝试解析木马首包(当前数据, token);
		if (木马结果.状态 === 'ok') return { ...木马结果.结果, reader };

		const 魏烈思结果 = 尝试解析魏烈思首包(当前数据, token);
		if (魏烈思结果.状态 === 'ok') return { ...魏烈思结果.结果, reader };

		if (木马结果.状态 === 'invalid' && 魏烈思结果.状态 === 'invalid') return null;
	}

	const 最终数据 = buffer.subarray(0, offset);
	const 最终木马 = 尝试解析木马首包(最终数据, token);
	if (最终木马.状态 === 'ok') return { ...最终木马.结果, reader };
	const 最终魏烈思 = 尝试解析魏烈思首包(最终数据, token);
	if (最终魏烈思.状态 === 'ok') return { ...最终魏烈思.结果, reader };
	return null;
}

export async function 处理XHTTP请求(request: Request, yourUUID: string): Promise<Response> {
	if (!request.body) return new Response('Bad Request', { status: 400 });
	const reader = request.body.getReader();
	const 首包 = await 读取XHTTP首包(reader, yourUUID);
	if (!首包) {
		try { reader.releaseLock(); } catch { /* ignore */ }
		return new Response('Invalid request', { status: 400 });
	}
	if (isSpeedTestSite(首包.hostname)) {
		try { reader.releaseLock(); } catch { /* ignore */ }
		return new Response('Forbidden', { status: 403 });
	}
	if (首包.isUDP && 首包.协议 !== 'trojan' && 首包.port !== 53) {
		try { reader.releaseLock(); } catch { /* ignore */ }
		return new Response('UDP is not supported', { status: 400 });
	}

	const remoteConnWrapper: RemoteConnWrapper = { socket: null, connectingPromise: null, retryConnect: null, socketWritePromise: null };
	let 当前写入Socket: TCPSocket | null = null;
	let 远端写入器: WritableStreamDefaultWriter<Uint8Array> | null = null;
	const responseHeaders = new Headers({
		'Content-Type': 'application/octet-stream',
		'X-Accel-Buffering': 'no',
		'Cache-Control': 'no-store',
	});

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
	return new Response(
		new ReadableStream<Uint8Array>({
			async start(controller) {
				let 已关闭 = false;
				let udpRespHeader = 首包.respHeader;
				const 木马UDP上下文 = { 缓存: new Uint8Array(0) };
				const xhttpBridge: { readyState: number; send(data: Uint8Array | ArrayBuffer | ArrayBufferView): void; close(): void } = {
					readyState: WebSocket.OPEN,
					send(data) {
						if (已关闭) return;
						try {
							const chunk = 数据转Uint8Array(data);
							controller.enqueue(chunk);
						} catch {
							已关闭 = true;
							this.readyState = WebSocket.CLOSED;
						}
					},
					close() {
						if (已关闭) return;
						已关闭 = true;
						this.readyState = WebSocket.CLOSED;
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

				try {
					if (首包.isUDP) {
						if (首包.rawData?.byteLength) {
							if (首包.协议 === 'trojan') await 转发木马UDP数据(首包.rawData, xhttpBridge as Parameters<typeof 转发木马UDP数据>[1], 木马UDP上下文, request);
							else await forwardataudp(首包.rawData, xhttpBridge as Parameters<typeof forwardataudp>[1], udpRespHeader, request);
							udpRespHeader = null;
						}
					} else {
						await forwardataTCP(首包.hostname, 首包.port, 首包.rawData, xhttpBridge as Parameters<typeof forwardataTCP>[3], 首包.respHeader, remoteConnWrapper, yourUUID, request);
					}

					for (;;) {
						const { done, value } = await reader.read();
						if (done) break;
						if (!value || value.byteLength === 0) continue;
						if (首包.isUDP) {
							if (首包.协议 === 'trojan') await 转发木马UDP数据(value, xhttpBridge as Parameters<typeof 转发木马UDP数据>[1], 木马UDP上下文, request);
							else await forwardataudp(value, xhttpBridge as Parameters<typeof forwardataudp>[1], udpRespHeader, request);
							udpRespHeader = null;
						} else {
							if (!(await 写入远端(value))) throw new Error('Remote socket is not ready');
						}
					}

					if (!首包.isUDP) {
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
				}
				void 有效数据长度;
			},
			cancel() {
				XHTTP上行写入队列?.清空();
				try { remoteConnWrapper.socket?.close(); } catch { /* ignore */ }
				释放远端写入器();
				try { reader.releaseLock(); } catch { /* ignore */ }
			},
		}),
		{ status: 200, headers: responseHeaders }
	);
}
