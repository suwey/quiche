// XHTTP 传输（标准协议，对齐上游 2026-09-22）：
// VLESS/Trojan 首包 + XPadding 混淆（tokenish/queryInHeader），
// TCP: request.body → 上行合包流 → socket.writable 直通，socket.readable → IdentityTransformStream 下行直通；
// UDP: 独立分支（Trojan UDP + DNS 转发）。mless 帧协议只保留在 WebSocket 传输。

import { log, state } from './state';
import { TOKENS } from './tokens';
import { 数据转Uint8Array, 有效数据长度, isSpeedTestSite, sha224, closeSocketQuietly } from './utils';
import { UUID字节匹配, BLESS文本解码器 } from './protocol';
import { forwardataTCP, forwardataudp, 转发木马UDP数据 } from './forward';
import type { RemoteConnWrapper } from './forward';
import type { TCPSocket } from './types';
import { 创建上行Grain合包流 } from './grain';

// ---------------------------------------------------------------------------
// XPadding 混淆（对齐上游：per-UUID 头/键 + HPACK Huffman 长度校验）
// ---------------------------------------------------------------------------

const HPACKHuffman码长 = [
	13, 23, 28, 28, 28, 28, 28, 28, 28, 24, 30, 28, 28, 30, 28, 28,
	28, 28, 28, 28, 28, 28, 30, 28, 28, 28, 28, 28, 28, 28, 28, 28,
	6, 10, 10, 12, 13, 6, 8, 11, 10, 10, 8, 11, 8, 6, 6, 6,
	5, 5, 5, 6, 6, 6, 6, 6, 6, 6, 7, 8, 15, 6, 12, 10,
	13, 6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
	7, 7, 7, 7, 7, 7, 7, 7, 8, 7, 8, 13, 19, 13, 14, 6,
	15, 5, 6, 5, 6, 5, 6, 6, 6, 5, 7, 7, 6, 6, 6, 5,
	6, 7, 6, 5, 5, 6, 7, 7, 7, 7, 7, 15, 11, 14, 13, 28,
	20, 22, 20, 20, 22, 22, 22, 23, 22, 23, 23, 23, 23, 23, 24, 23,
	24, 24, 22, 23, 24, 23, 23, 23, 23, 21, 22, 23, 22, 23, 23, 24,
	22, 21, 20, 22, 22, 23, 23, 21, 23, 22, 22, 24, 21, 22, 23, 23,
	21, 21, 22, 21, 23, 22, 23, 23, 20, 22, 22, 22, 23, 22, 22, 23,
	26, 26, 20, 19, 22, 23, 22, 25, 26, 26, 26, 27, 27, 26, 24, 25,
	19, 21, 26, 27, 27, 26, 27, 24, 21, 21, 26, 26, 28, 27, 27, 27,
	20, 24, 20, 21, 22, 21, 21, 23, 22, 22, 25, 25, 24, 24, 26, 23,
	26, 27, 26, 26, 27, 27, 27, 27, 27, 28, 27, 27, 27, 27, 27, 26,
	30,
];

/** 由 UUID 派生本机 XPadding 请求头名与查询参数键。 */
export function 获取叉HTTPPadding标识(yourUUID: string): { 头: string; 键: string } {
	return { 头: yourUUID.slice(1, 7), 键: '_' + yourUUID.slice(25, 31) };
}

function 计算HPACKHuffman字节长度(字符串: string): number {
	const 字节 = new TextEncoder().encode(字符串);
	let 总位数 = 0;
	for (let i = 0; i < 字节.length; i++) {
		总位数 += HPACKHuffman码长[字节[i]];
	}
	return Math.ceil(总位数 / 8);
}

function 提取叉HTTPPadding值(request: Request, 本机Padding头: string, 本机Padding键: string): string {
	const 头值 = request.headers.get(本机Padding头);
	if (头值) {
		try {
			const 解析URL = new URL(头值, 'https://x.invalid');
			const 查询值 = 解析URL.searchParams.get(本机Padding键);
			if (查询值) return 查询值;
		} catch { /* 非法头值，按原值处理 */ }
		return 头值;
	}
	const 请求URL = new URL(request.url);
	return 请求URL.searchParams.get(本机Padding键) || '';
}

function 校验叉HTTPPadding(request: Request, 本机Padding头: string, 本机Padding键: string): boolean {
	const padding值 = 提取叉HTTPPadding值(request, 本机Padding头, 本机Padding键);
	if (!padding值) return true;
	const huffman长度 = 计算HPACKHuffman字节长度(padding值);
	return huffman长度 >= 98 && huffman长度 <= 1002;
}

const 叉HTTPBase62字符集 = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';

function 生成叉HTTPPadding串(长度: number): string {
	const 字符集长度 = 叉HTTPBase62字符集.length;
	let 结果 = '';
	for (let i = 0; i < 长度; i++) {
		结果 += 叉HTTPBase62字符集[Math.floor(Math.random() * 字符集长度)];
	}
	return 结果;
}

/** 本地直出的 204 响应（测速站免出网）。 */
function 构造本地204响应(respHeader: Uint8Array | null = null): Uint8Array {
	const 本地204响应 = new TextEncoder().encode(
		'HTTP/1.1 204 No Content\r\n' +
		'Content-Length: 0\r\n' +
		'Connection: close\r\n' +
		'\r\n',
	);
	if (有效数据长度(respHeader) === 0) return 本地204响应;
	const 协议响应头 = 数据转Uint8Array(respHeader);
	const response = new Uint8Array(协议响应头.byteLength + 本地204响应.byteLength);
	response.set(协议响应头, 0);
	response.set(本地204响应, 协议响应头.byteLength);
	log(`[TCP转发] 构造本地204响应: ${response.byteLength}B`);
	return response;
}

// ---------------------------------------------------------------------------
// 首包解析（VLESS / Trojan，带 need_more 增量读取）
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

async function 读取叉HTTP首包(reader: ReadableStreamDefaultReader<Uint8Array>, token: string): Promise<XhttpFirstPacket | null> {
	let buffer = new Uint8Array(1024);
	let offset = 0;

	const 解析当前缓冲 = (data: Uint8Array): XhttpFirstPacket | 'need_more' | null => {
		const 木马结果 = 尝试解析木马首包(data, token);
		if (木马结果.状态 === 'ok') return 木马结果.结果;
		const 魏烈思结果 = 尝试解析魏烈思首包(data, token);
		if (魏烈思结果.状态 === 'ok') return 魏烈思结果.结果;
		if (木马结果.状态 === 'invalid' && 魏烈思结果.状态 === 'invalid') return null;
		return 'need_more';
	};

	while (true) {
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

		const 解析结果 = 解析当前缓冲(buffer.subarray(0, offset));
		if (解析结果 === 'need_more') continue;
		return 解析结果;
	}

	const 最终结果 = 解析当前缓冲(buffer.subarray(0, offset));
	return 最终结果 === 'need_more' ? null : 最终结果;
}

// ---------------------------------------------------------------------------
// 主处理（TCP pipe 直通 / UDP 独立分支）
// ---------------------------------------------------------------------------

export async function 处理叉HTTP请求(request: Request, yourUUID: string): Promise<Response> {
	if (!request.body) return new Response('Bad Request', { status: 400 });
	const { 头: 本机Padding头, 键: 本机Padding键 } = 获取叉HTTPPadding标识(yourUUID);
	if (!校验叉HTTPPadding(request, 本机Padding头, 本机Padding键)) return new Response('Bad Request', { status: 400 });
	const reader = request.body.getReader();
	const 首包 = await 读取叉HTTP首包(reader, yourUUID);
	if (!首包) {
		try { reader.releaseLock(); } catch { /* ignore */ }
		return new Response('Invalid request', { status: 400 });
	}
	// 测速站本地直出：仅在未使用 SOCKS5/HTTP/HTTPS/TURN/SSTP 代理时（走代理时正常转发以测代理链路）。
	if (isSpeedTestSite(首包.hostname) && !state.启用SOCKS5反代) {
		try { reader.releaseLock(); } catch { /* ignore */ }
		return new Response(构造本地204响应(首包.respHeader), {
			status: 200,
			headers: {
				'Content-Type': 'application/octet-stream',
				'X-Accel-Buffering': 'no',
				'Cache-Control': 'no-store',
			},
		});
	}
	if (首包.isUDP && 首包.协议 !== 'trojan' && 首包.port !== 53) {
		try { reader.releaseLock(); } catch { /* ignore */ }
		return new Response('UDP is not supported', { status: 400 });
	}

	const responseHeaders = new Headers({
		'Content-Type': 'application/octet-stream',
		'X-Accel-Buffering': 'no',
		'Cache-Control': 'no-store',
	});

	try {
		const 响应URL = new URL('https://x.invalid/');
		响应URL.searchParams.set(本机Padding键, 生成叉HTTPPadding串(100 + Math.floor(Math.random() * 901)));
		responseHeaders.set(本机Padding头, 响应URL.toString());
	} catch { /* ignore */ }

	if (首包.isUDP) return 处理叉HTTPUDP请求(首包, reader, request, responseHeaders);

	try { reader.releaseLock(); } catch { /* ignore */ }

	const remoteConnWrapper: RemoteConnWrapper = { socket: null, connectingPromise: null, retryConnect: null, socketWritePromise: null };
	const abortController = new AbortController();
	let 已清理 = false;
	const 清理 = (reason?: unknown): void => {
		if (已清理) return;
		已清理 = true;
		try { abortController.abort(reason); } catch { /* ignore */ }
		try { remoteConnWrapper.socket?.close(); } catch { /* ignore */ }
	};

	const 占位WS = { readyState: WebSocket.OPEN, send: (): void => { }, close: (): void => { } };

	let socket: TCPSocket | null;
	try {
		socket = await forwardataTCP(首包.hostname, 首包.port, 首包.rawData, 占位WS, 首包.respHeader, remoteConnWrapper, yourUUID, request, null, true);
	} catch (err) {
		log(`[叉HTTP-Pipe] 连接失败: ${(err as { message?: string })?.message || err}`);
		清理(err);
		return new Response('bad gateway', { status: 502 });
	}
	if (!socket) {
		清理(new Error('socket is null'));
		return new Response('bad gateway', { status: 502 });
	}

	const 上行Promise = (async (): Promise<void> => {
		const 上行合包器 = 创建上行Grain合包流();
		const 搬运Promise = 上行合包器.readable.pipeTo(socket.writable, { signal: abortController.signal });
		void 搬运Promise.catch(清理);
		const 上行reader = request.body!.getReader();
		const 取消上行reader = (): void => {
			try { 上行reader.cancel((abortController.signal.reason as Error) ?? undefined).catch(() => { }); } catch { /* ignore */ }
		};
		abortController.signal.addEventListener('abort', 取消上行reader, { once: true });
		try {
			try {
				while (true) {
					const { done, value } = await 上行reader.read();
					if (done) break;
					if (value?.byteLength) await 上行合包器.写入(value);
				}
			} finally {
				abortController.signal.removeEventListener('abort', 取消上行reader);
				try { 上行reader.releaseLock(); } catch { /* ignore */ }
			}
		} finally {
			try { await 上行合包器.结束(); } catch { /* ignore */ }
		}
		await 搬运Promise;
	})();

	const 响应流 = typeof IdentityTransformStream !== 'undefined'
		? new IdentityTransformStream()
		: new TransformStream<Uint8Array, Uint8Array>();
	const 下行Promise = (async (): Promise<void> => {
		const writer = 响应流.writable.getWriter();
		try {
			if (首包.respHeader && 有效数据长度(首包.respHeader) > 0) await writer.write(首包.respHeader);
		} catch (error) {
			try { await writer.abort(error); } catch { /* ignore */ }
			throw error;
		} finally {
			try { writer.releaseLock(); } catch { /* ignore */ }
		}
		await socket.readable.pipeTo(响应流.writable, { signal: abortController.signal });
	})();

	void 上行Promise.catch(清理);
	void 下行Promise.then(() => 清理(), 清理);
	void Promise.allSettled([上行Promise, 下行Promise]);

	return new Response(响应流.readable, { status: 200, headers: responseHeaders });
}

function 处理叉HTTPUDP请求(首包: XhttpFirstPacket, reader: ReadableStreamDefaultReader<Uint8Array>, request: Request, responseHeaders: Headers): Response {
	const 木马UDP上下文 = { 缓存: new Uint8Array(0) };
	return new Response(new ReadableStream<Uint8Array>({
		async start(controller) {
			let 已关闭 = false;
			let udpRespHeader = 首包.respHeader;
			const 叉桥 = {
				readyState: WebSocket.OPEN,
				send(data: Uint8Array | ArrayBuffer | ArrayBufferView): void {
					if (已关闭) return;
					try {
						const chunk = 数据转Uint8Array(data);
						controller.enqueue(chunk);
					} catch {
						已关闭 = true;
						叉桥.readyState = WebSocket.CLOSED;
					}
				},
				close(): void {
					if (已关闭) return;
					已关闭 = true;
					叉桥.readyState = WebSocket.CLOSED;
					try { controller.close(); } catch { /* ignore */ }
				},
			};
			try {
				if (首包.协议 === 'trojan') {
					if (首包.rawData?.byteLength) await 转发木马UDP数据(首包.rawData, 叉桥, 木马UDP上下文, request);
				} else if (首包.rawData?.byteLength) {
					await forwardataudp(首包.rawData, 叉桥, udpRespHeader, request);
					udpRespHeader = null;
				}
				while (true) {
					const { done, value } = await reader.read();
					if (done) break;
					if (!value || value.byteLength === 0) continue;
					if (首包.协议 === 'trojan') await 转发木马UDP数据(value, 叉桥, 木马UDP上下文, request);
					else {
						await forwardataudp(value, 叉桥, udpRespHeader, request);
						udpRespHeader = null;
					}
				}
			} catch (err) {
				log(`[叉HTTP转发] 处理失败: ${(err as { message?: string })?.message || err}`);
				closeSocketQuietly(叉桥);
			} finally {
				closeSocketQuietly(叉桥);
				try { reader.releaseLock(); } catch { /* ignore */ }
			}
		},
		cancel() {
			try { reader.releaseLock(); } catch { /* ignore */ }
		},
	}), { status: 200, headers: responseHeaders });
}
