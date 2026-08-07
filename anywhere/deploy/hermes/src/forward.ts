// Copyright (c) 2024 anywhere contributors
// SPDX-License-Identifier: BSD-2-Clause
//
// TCP/UDP 转发层。
// connectStreams 负责把远端 socket 的下行字节通过 GrainSender 推到 WebSocket，
// 检测 TLS handshake_failure 触发 PROXYIP 拉黑+重试。
// forwardataTCP 选择直连/PROXYIP/SOCKS5，失败时通过 retryFunc 切换路径。

import { state, log, 下行Grain包字节 } from './state';
import {
	数据转Uint8Array, 拼接字节数据, 有效数据长度,
	isIPHostname, isIPv4, closeSocketQuietly, WebSocket发送并等待,
} from './utils';
import { DoH查询 } from './doh';
import { 解析地址端口 } from './resolver';
import { socks5Connect, httpConnect, httpsConnect } from './proxy-connect';
import { sstpConnect } from './sstp';
import { turnConnect } from './turn';
import { 创建下行Grain发送器 } from './grain';
import type { ParsedProxyAddress, TCPSocket, TCPConnector, TCPConnectOptions, TCPConnectInit } from './types';

export interface RemoteConnWrapper {
	socket: TCPSocket | null;
	connectingPromise: Promise<void> | null;
	retryConnect: (() => Promise<void>) | null;
	socketWritePromise: Promise<void> | null;
}

export function 创建请求TCP连接器(request?: Request): TCPConnector {
	const fetcher = (request as unknown as { fetcher?: { connect: (options: TCPConnectOptions, init?: TCPConnectInit) => TCPSocket } })?.fetcher;
	if (!fetcher || typeof fetcher.connect !== 'function') throw new Error('request.fetcher.connect unavailable');
	return (options: TCPConnectOptions, init?: TCPConnectInit): TCPSocket =>
		init === undefined ? fetcher.connect(options) : fetcher.connect(options, init);
}

interface ConnectStreamsWebSocket {
	readyState: number;
	send(data: ArrayBuffer | ArrayBufferView | Uint8Array): unknown;
	close(): void;
}

export async function connectStreams(
	remoteSocket: TCPSocket,
	webSocket: ConnectStreamsWebSocket,
	headerData: Uint8Array | null,
	retryFunc: (() => Promise<void>) | null,
	onProxyFailure: (() => void) | null = null,
): Promise<void> {
	const BYOB单次读取上限 = 64 * 1024;
	const 下行发送器 = 创建下行Grain发送器(webSocket, headerData);
	let useBYOB = false;
	let byobReader: ReadableStreamBYOBReader | null = null;
	let defaultReader: ReadableStreamDefaultReader<Uint8Array> | null = null;
	try {
		byobReader = remoteSocket.readable.getReader({ mode: 'byob' });
		useBYOB = true;
	} catch {
		defaultReader = remoteSocket.readable.getReader();
	}
	let hasData = false;
	let totalBytesRead = 0;
	let readCount = 0;
	let 首字节: Uint8Array | null = null;
	// 用 remoteSocket.closed 作为辅助终止信号：Cloudflare TCP socket 的 BYOB
	// reader 偶尔在读完第一段数据后误报 done，需要二次确认 socket 是否真的关闭。
	let 远端主动关闭 = false;
	const 连接关闭 = remoteSocket.closed
		.then(() => { 远端主动关闭 = true; return true; })
		.catch(() => { 远端主动关闭 = true; return true; });
	try {
		if (!useBYOB && defaultReader) {
			for (;;) {
				const { done, value } = await defaultReader.read();
				if (done) {
					// BYOB done 误报检测：若 socket 未关闭则继续读
					const 已关闭 = await Promise.race([
						连接关闭.then(() => true),
						new Promise<boolean>(resolve => setTimeout(() => resolve(false), 50)),
					]);
					if (已关闭) break;
					continue;
				}
				if (!value || value.byteLength === 0) continue;
				if (首字节 === null) 首字节 = value.slice(0, Math.min(value.byteLength, 8));
				hasData = true;
				readCount++;
				totalBytesRead += value.byteLength;

				if (value.byteLength <= 64) {
					const hex = Array.from(value).map(b => b.toString(16).padStart(2, '0')).join(' ');
					log(`[connectStreams] hex#${readCount} (${value.byteLength}B): ${hex}`);
				}
				await 下行发送器.发送(value);
			}
		} else if (byobReader) {
			let readBuffer = new ArrayBuffer(BYOB单次读取上限);
			for (;;) {
				const { done, value } = await byobReader.read(
					new Uint8Array(readBuffer, 0, BYOB单次读取上限),
				);
				if (done) {
					const 已关闭 = await Promise.race([
						连接关闭.then(() => true),
						new Promise<boolean>(resolve => setTimeout(() => resolve(false), 50)),
					]);
					if (已关闭) break;
					continue;
				}
				if (!value || value.byteLength === 0) continue;
				if (首字节 === null) 首字节 = value.slice(0, Math.min(value.byteLength, 8));
				hasData = true;
				readCount++;
				totalBytesRead += value.byteLength;

				if (value.byteLength <= 64) {
					const hex = Array.from(value).map(b => b.toString(16).padStart(2, '0')).join(' ');
					log(`[connectStreams] hex#${readCount} (${value.byteLength}B): ${hex}`);
				}
				if (value.byteLength >= 下行Grain包字节) {
					await 下行发送器.flush();
					await 下行发送器.直接发送(value);
					readBuffer = new ArrayBuffer(BYOB单次读取上限);
				} else {
					await 下行发送器.发送(value);
					readBuffer = value.buffer.byteLength >= BYOB单次读取上限
						? value.buffer
						: new ArrayBuffer(BYOB单次读取上限);
				}
			}
		}
		await 下行发送器.flush();
	} catch (err) {
		log(`[connectStreams] read error: ${(err as { message?: string })?.message ?? err}`);
	} finally {
		// 注意：远端主动关闭=true 仅表示 remoteSocket.closed resolve 了，
		// 不能区分是远端 FIN 还是本地 close()。如需精确判断，看 read error。
		log(`[connectStreams] 读取结束 hasData=${hasData} reads=${readCount} totalBytes=${totalBytesRead} socket已关闭=${远端主动关闭}`);
		try { await (byobReader ?? defaultReader)?.cancel(); } catch { /* ignore */ }
		try { byobReader?.releaseLock(); } catch { /* ignore */ }
		try { defaultReader?.releaseLock(); } catch { /* ignore */ }
	}
	// PROXYIP 失败检测：极短响应 (<=32B) + handshake_failure pattern (15 03 0x 00 02 02 28)。
	// 反代节点拒绝服务（被限流、SNI 被拦截等）时拉黑该节点。
	const 疑似反代失败 = totalBytesRead <= 32 && 首字节 !== null && 首字节.length >= 7 &&
		首字节[0] === 0x15 && 首字节[1] === 0x03 && 首字节[3] === 0x00 &&
		首字节[4] === 0x02 && 首字节[5] === 0x02 && 首字节[6] === 0x28;
	if (疑似反代失败 && onProxyFailure) {
		log(`[connectStreams] 检测到 PROXYIP 返回 TLS handshake_failure，拉黑该节点`);
		onProxyFailure();
	}
	if (retryFunc && (!hasData || 疑似反代失败)) await retryFunc();
}

export interface ForwardataTCPOptions {
	反代IP?: string;
	启用SOCKS5反代?: typeof state['启用SOCKS5反代'];
	启用SOCKS5全局反代?: boolean;
	SOCKS5白名单?: string[];
	parsedSocks5Address?: ParsedProxyAddress;
	TCP并发拨号数?: number;
	预加载竞速拨号?: boolean;
	启用反代兜底?: boolean;
}

export async function forwardataTCP(
	host: string,
	portNum: number,
	rawData: Uint8Array | null,
	ws: ConnectStreamsWebSocket,
	respHeader: Uint8Array | null,
	remoteConnWrapper: RemoteConnWrapper,
	yourUUID: string,
	request: Request | null = null,
	tcpConnector: TCPConnector | null = null,
): Promise<void> {
	const 反代IP = state.反代IP;
	const 启用SOCKS5反代 = state.启用SOCKS5反代;
	const 启用SOCKS5全局反代 = state.启用SOCKS5全局反代;
	const SOCKS5白名单 = state.SOCKS5白名单;
	const parsedSocks5Address = state.parsedSocks5Address as ParsedProxyAddress;
	const TCP并发拨号数 = state.TCP并发拨号数;
	const 预加载竞速拨号 = state.预加载竞速拨号;
	const 启用反代兜底 = state.启用反代兜底;

	log(`[TCP转发] 目标: ${host}:${portNum} | 反代IP: ${反代IP} | 反代兜底: ${启用反代兜底 ? '是' : '否'} | 反代类型: ${启用SOCKS5反代 || 'proxyip'} | 全局: ${启用SOCKS5全局反代 ? '是' : '否'}`);
	const 连接超时毫秒 = 1000;
	let 已通过代理发送首包 = false;
	const TCP连接 = tcpConnector ?? 创建请求TCP连接器(request ?? undefined);

	async function 等待连接建立(remoteSock: TCPSocket, timeoutMs: number = 连接超时毫秒): Promise<void> {
		await Promise.race([
			(remoteSock.opened as Promise<unknown> | undefined) ?? Promise.resolve(),
			new Promise<never>((_, reject) => setTimeout(() => reject(new Error('连接超时')), timeoutMs)),
		]);
	}

	async function 打开TCP连接(address: string, port: number): Promise<TCPSocket> {
		const remoteSock = TCP连接({ hostname: address, port });
		try {
			await 等待连接建立(remoteSock);
			return remoteSock;
		} catch (err) {
			try { remoteSock.close?.(); } catch { /* ignore */ }
			throw err;
		}
	}

	async function 写入首包(remoteSock: TCPSocket, data: Uint8Array | null): Promise<void> {
		if (有效数据长度(data) <= 0) return;
		const writer = remoteSock.writable.getWriter();
		try { await writer.write(数据转Uint8Array(data)); }
		finally { try { writer.releaseLock(); } catch { /* ignore */ } }
	}

	interface Candidate {
		hostname: string;
		port: number;
		attempt: number;
		resolvedFrom?: string;
		index?: number;
	}

	async function 并发打开候选连接(候选列表: Candidate[]): Promise<{ socket: TCPSocket; candidate: Candidate }> {
		if (候选列表.length === 1) {
			const 候选 = 候选列表[0];
			return { socket: await 打开TCP连接(候选.hostname, 候选.port), candidate: 候选 };
		}
		const attempts = 候选列表.map(候选 =>
			打开TCP连接(候选.hostname, 候选.port).then(socket => ({ socket, candidate: 候选 })),
		);
		let winner: { socket: TCPSocket; candidate: Candidate } | null = null;
		try {
			winner = await Promise.any(attempts);
			return winner;
		} finally {
			if (winner) {
				for (const attempt of attempts) {
					attempt.then(({ socket }) => {
						if (socket !== winner!.socket) {
							try { socket.close?.(); } catch { /* ignore */ }
						}
					}).catch(() => { /* ignore */ });
				}
			}
		}
	}

	async function 构建预加载竞速候选列表(address: string, port: number): Promise<Candidate[] | null> {
		if (!预加载竞速拨号 || isIPHostname(address)) return null;
		log(`[TCP直连] 预加载竞速拨号开启，开始并发查询 ${address} 的 A/AAAA 记录`);
		const [aRecords, aaaaRecords] = await Promise.all([
			DoH查询(address, 'A'),
			DoH查询(address, 'AAAA'),
		]);
		const ipv4List = [...new Set(aRecords.flatMap(r => {
			const data = r.data;
			return r.type === 1 && typeof data === 'string' && isIPv4(data) ? [data] : [];
		}))];
		const ipv6List = [...new Set(aaaaRecords.flatMap(r => {
			const data = r.data;
			return r.type === 28 && typeof data === 'string' && isIPHostname(data) ? [data] : [];
		}))];
		const 拨号上限 = Math.max(1, TCP并发拨号数 | 0);
		const ipList = ipv4List.length >= 拨号上限
			? ipv4List.slice(0, 拨号上限)
			: ipv4List.concat(ipv6List.slice(0, 拨号上限 - ipv4List.length));
		const 使用记录类型 = ipv4List.length > 0
			? (ipList.length > ipv4List.length ? 'A+AAAA' : 'A')
			: 'AAAA';
		if (ipList.length === 0) {
			log(`[TCP直连] ${address} 的 A/AAAA 未获得可用解析结果，预加载竞速不可用，回退到原始 hostname 直连。`);
			return null;
		}
		const 选中IP列表 = ipList;
		log(`[TCP直连] ${address} A记录:${ipv4List.length} AAAA记录:${ipv6List.length}，使用${使用记录类型}记录，竞速拨号 ${选中IP列表.length}/${拨号上限}: ${选中IP列表.join(', ')}`);
		return 选中IP列表.map((hostname, attempt) => ({ hostname, port, attempt, resolvedFrom: address }));
	}

	async function connectDirect(address: string, port: number, data: Uint8Array | null = null, 启用预加载 = false): Promise<TCPSocket> {
		const 预加载候选列表 = 启用预加载 ? await 构建预加载竞速候选列表(address, port) : null;
		const 候选列表: Candidate[] = 预加载候选列表
			|| Array.from({ length: TCP并发拨号数 }, (_, attempt) => ({ hostname: address, port, attempt }));
		log(预加载候选列表
			? `[TCP直连] 并发尝试 ${候选列表.length} 路: ${候选列表.map(候选 => `${候选.hostname}:${候选.port}`).join(', ')}`
			: `[TCP直连] 并发尝试 ${候选列表.length} 路: ${address}:${port}`);
		let socket: TCPSocket | null = null;
		try {
			const 连接结果 = await 并发打开候选连接(候选列表);
			socket = 连接结果.socket;
			if (预加载候选列表) {
				const winner = 连接结果.candidate;
				log(`[TCP直连] 预加载竞速结果: ${winner.hostname}:${winner.port} 胜出，源域名: ${winner.resolvedFrom || address}`);
			}
			await 写入首包(socket, data);
			return socket;
		} catch (err) {
			try { socket?.close?.(); } catch { /* ignore */ }
			if (预加载候选列表) log(`[TCP直连] 预加载竞速失败: ${(err as { message?: string })?.message ?? err}`);
			throw err;
		}
	}

	async function connectProxyIP(
		address: string,
		port: number,
		data: Uint8Array | null = null,
		所有反代数组: Array<[string, number]> | null = null,
		启用反代失败兜底 = true,
	): Promise<{ socket: TCPSocket; proxyKey: string | null }> {
		if (所有反代数组 && 所有反代数组.length > 0) {
			// 过滤掉近期失败黑名单中的 IP，未到失效时间则跳过。
			const 当前时间 = Date.now();
			const 候选索引列表: number[] = [];
			for (let k = 0; k < 所有反代数组.length; k++) {
				const 索引 = (state.缓存反代数组索引 + k) % 所有反代数组.length;
				const [反代地址, 反代端口] = 所有反代数组[索引];
				const 黑名单key = `${反代地址}:${反代端口}`;
				const 失效截止 = state.反代失败黑名单.get(黑名单key);
				if (失效截止 !== undefined && 当前时间 < 失效截止) {
					continue;
				}
				if (失效截止 !== undefined) state.反代失败黑名单.delete(黑名单key);
				候选索引列表.push(索引);
			}
			if (候选索引列表.length === 0) {
				log(`[反代连接] 所有 PROXYIP 都在黑名单中，清空黑名单重试`);
				state.反代失败黑名单.clear();
				for (let k = 0; k < 所有反代数组.length; k++) {
					候选索引列表.push((state.缓存反代数组索引 + k) % 所有反代数组.length);
				}
			}
			// 按 反代并发拨号数 分批并发拨号：每批取最快节点，轮询推进。
			// 保留黑名单过滤（拉黑的节点跳过）；默认 1 路即退化为原单路轮询。
			const 实际并发数 = Math.max(1, Math.floor(Number(state.反代并发拨号数) || 1));
			for (let i = 0; i < 候选索引列表.length; i += 实际并发数) {
				const 候选列表: Candidate[] = [];
				for (let j = 0; j < 实际并发数 && i + j < 候选索引列表.length; j++) {
					const 反代数组索引 = 候选索引列表[i + j];
					const [反代地址, 反代端口] = 所有反代数组[反代数组索引];
					候选列表.push({ hostname: 反代地址, port: 反代端口, attempt: 0, index: 反代数组索引 });
				}
				let socket: TCPSocket | null = null;
				try {
					log(`[反代连接] 并发尝试 ${候选列表.length} 路: ${候选列表.map(候选 => `${候选.hostname}:${候选.port}`).join(', ')}`);
					const 连接结果 = await 并发打开候选连接(候选列表);
					socket = 连接结果.socket;
					const 胜出候选 = 连接结果.candidate;
					await 写入首包(socket, data);
					log(`[反代连接] 成功连接到: ${胜出候选.hostname}:${胜出候选.port} (索引: ${胜出候选.index})`);
					// 索引前进到 winner+1，下次从下一个 PROXYIP 开始（轮询）。
					state.缓存反代数组索引 = ((胜出候选.index ?? 0) + 1) % 所有反代数组.length;
					return { socket, proxyKey: `${胜出候选.hostname}:${胜出候选.port}` };
				} catch (err) {
					try { socket?.close?.(); } catch { /* ignore */ }
					log(`[反代连接] 本批连接失败: ${(err as { message?: string })?.message ?? err}`);
				}
			}
		}

		if (启用反代失败兜底) return { socket: await connectDirect(address, port, data, false), proxyKey: null };
		else {
			closeSocketQuietly(ws as unknown as { readyState?: number; close?: () => void });
			throw new Error('[反代连接] 所有反代连接失败，且未启用反代兜底，连接终止。');
		}
	}

	async function connecttoPry(允许发送首包 = true): Promise<void> {
		if (remoteConnWrapper.connectingPromise) {
			await remoteConnWrapper.connectingPromise;
			return;
		}

		const 走PROXYIP = !启用SOCKS5反代;
		const PROXYIP最大重试 = 5;

		const 单次尝试 = async (): Promise<{ 需要重试: boolean }> => {
			const 本次发送首包 = 允许发送首包 && !已通过代理发送首包 && 有效数据长度(rawData) > 0;
			const 本次首包数据: Uint8Array | null = 本次发送首包 ? rawData : null;
			log(`[connecttoPry] 首包大小: ${本次首包数据 ? 本次首包数据.byteLength : 0}B, 允许发送: ${允许发送首包}, 已发送: ${已通过代理发送首包}`);

			let newSocket: TCPSocket;
			let proxyKey: string | null = null;
			if (启用SOCKS5反代 === 'socks5') {
				log(`[SOCKS5代理] 代理到: ${host}:${portNum}`);
				newSocket = await socks5Connect(host, portNum, 本次首包数据, TCP连接);
			} else if (启用SOCKS5反代 === 'http') {
				log(`[HTTP代理] 代理到: ${host}:${portNum}`);
				newSocket = await httpConnect(host, portNum, 本次首包数据, false, TCP连接);
			} else if (启用SOCKS5反代 === 'https') {
				log(`[HTTPS代理] 代理到: ${host}:${portNum}`);
				newSocket = isIPHostname(parsedSocks5Address.hostname)
					? await httpsConnect(host, portNum, 本次首包数据, TCP连接)
					: await httpConnect(host, portNum, 本次首包数据, true, TCP连接);
			} else if (启用SOCKS5反代 === 'turn') {
				log(`[TURN代理] 代理到: ${host}:${portNum}`);
				newSocket = await turnConnect(parsedSocks5Address, host, portNum, TCP连接);
				if (有效数据长度(本次首包数据) > 0) {
					const writer = newSocket.writable.getWriter();
					try { await writer.write(数据转Uint8Array(本次首包数据)); }
					finally { try { writer.releaseLock(); } catch { /* ignore */ } }
				}
			} else if (启用SOCKS5反代 === 'sstp') {
				log(`[SSTP代理] 代理到: ${host}:${portNum}`);
				newSocket = await sstpConnect(parsedSocks5Address, host, portNum, TCP连接);
				if (有效数据长度(本次首包数据) > 0) {
					const writer = newSocket.writable.getWriter();
					try { await writer.write(数据转Uint8Array(本次首包数据)); }
					finally { try { writer.releaseLock(); } catch { /* ignore */ } }
				}
			} else {
				log(`[反代连接] 代理到: ${host}:${portNum}`);
				const 所有反代数组 = await 解析地址端口(反代IP, host, yourUUID);
				const 反代结果 = await connectProxyIP(atob('UFJPWFlJUC50cDEuMDkwMjI3Lnh5eg=='), 1, 本次首包数据, 所有反代数组, 启用反代兜底);
				newSocket = 反代结果.socket;
				proxyKey = 反代结果.proxyKey;
			}
			if (本次发送首包) 已通过代理发送首包 = true;
			remoteConnWrapper.socket = newSocket;

			let proxy被拒绝 = false;
			let onProxyFailure: (() => void) | null = null;
			if (proxyKey !== null && 走PROXYIP) {
				const 拉黑key = proxyKey;
				onProxyFailure = (): void => {
					const 拉黑毫秒 = 30_000;
					state.反代失败黑名单.set(拉黑key, Date.now() + 拉黑毫秒);
					log(`[反代连接] 拉黑 ${拉黑key} 共 ${拉黑毫秒 / 1000}s`);
					// PROXYIP 拒绝时 ClientHello 没真正送达目标，必须重发首包。
					已通过代理发送首包 = false;
					proxy被拒绝 = true;
				};
			}
			// 走 PROXYIP 时 retryFunc 传 null，由本函数循环重试；否则保留原 retry。
			await connectStreams(newSocket, ws, respHeader, null, onProxyFailure);
			return { 需要重试: proxy被拒绝 };
		};

		const 当前连接任务 = (async (): Promise<void> => {
			for (let i = 0; i < PROXYIP最大重试; i++) {
				const { 需要重试 } = await 单次尝试();
				if (!需要重试) return;
				log(`[connecttoPry] PROXYIP 被拒绝，重试 ${i + 1}/${PROXYIP最大重试}`);
			}
			log(`[connecttoPry] PROXYIP 重试用尽 (${PROXYIP最大重试} 次)`);
		})();

		remoteConnWrapper.connectingPromise = 当前连接任务;
		try {
			await 当前连接任务;
		} finally {
			if (remoteConnWrapper.connectingPromise === 当前连接任务) {
				remoteConnWrapper.connectingPromise = null;
			}
		}
	}
	remoteConnWrapper.retryConnect = async () => connecttoPry(!已通过代理发送首包);

	const 有PROXYIP = !!反代IP;

	if (启用SOCKS5反代 && (启用SOCKS5全局反代 || SOCKS5白名单.some(p => new RegExp(`^${p.replace(/\*/g, '.*')}$`, 'i').test(host)))) {
		log(`[TCP转发] 启用 SOCKS5/HTTP/HTTPS/TURN/SSTP 全局代理`);
		try {
			await connecttoPry();
		} catch (err) {
			log(`[TCP转发] SOCKS5/HTTP/HTTPS/TURN/SSTP 代理连接失败: ${(err as { message?: string })?.message ?? err}`);
			throw err;
		}
	} else {
		// 与上游 openclaw 一致：先直连，直连失败/中途断开才回退 PROXYIP。
		// 不再对 googlevideo/youtube 强制走 PROXYIP（CF Worker 直连现在可行，且更快）。
		try {
			log(`[TCP转发] 尝试直连到: ${host}:${portNum}`);
			const initialSocket = await connectDirect(host, portNum, rawData, true);
			remoteConnWrapper.socket = initialSocket;
			await connectStreams(initialSocket, ws, respHeader, async () => {
				if (remoteConnWrapper.socket !== initialSocket) return;
				if (有PROXYIP) await connecttoPry();
			});
		} catch (err) {
			log(`[TCP转发] 直连 ${host}:${portNum} 失败: ${(err as { message?: string })?.message ?? err}`);
			if (err instanceof Error && err.name === '预加载解析为空') {
				closeSocketQuietly(ws as unknown as { readyState?: number; close?: () => void });
				throw err;
			}
			if (有PROXYIP) await connecttoPry();
		}
	}
}

export { 创建上行写入队列 } from './uplink-queue';

export type UdpResponseEnvelop = (chunk: Uint8Array) => Uint8Array | Uint8Array[] | Promise<Uint8Array | Uint8Array[]>;
export async function forwardataudp(
	udpChunk: Uint8Array | ArrayBuffer | ArrayBufferView,
	webSocket: ConnectStreamsWebSocket,
	respHeader: Uint8Array | null,
	request: Request | null,
	响应封装器: UdpResponseEnvelop | null = null,
	tcpConnector: TCPConnector | null = null,
): Promise<void> {
	const 请求数据 = 数据转Uint8Array(udpChunk);
	const 请求字节数 = 请求数据.byteLength;
	log(`[UDP转发] 收到 DNS 请求: ${请求字节数}B -> 8.8.4.4:53`);
	try {
		const TCP连接 = tcpConnector ?? 创建请求TCP连接器(request ?? undefined);
		const tcpSocket = TCP连接({ hostname: '8.8.4.4', port: 53 });
		let 魏烈思Header: Uint8Array | null = respHeader;
		const writer = tcpSocket.writable.getWriter();
		await writer.write(请求数据);
		log(`[UDP转发] DNS 请求已写入上游: ${请求字节数}B`);
		writer.releaseLock();
		await tcpSocket.readable.pipeTo(new WritableStream({
			async write(chunk: ArrayBuffer | Uint8Array) {
				const 原始响应 = 数据转Uint8Array(chunk);
				log(`[UDP转发] 收到 DNS 响应: ${原始响应.byteLength}B`);
				const 封装结果 = 响应封装器 ? await 响应封装器(原始响应) : 原始响应;
				const 发送片段列表: Uint8Array[] = Array.isArray(封装结果) ? 封装结果 : [封装结果];
				if (!发送片段列表.length) return;
				if (webSocket.readyState !== WebSocket.OPEN) return;
				for (const fragment of 发送片段列表) {
					const 转发响应 = 数据转Uint8Array(fragment);
					if (!转发响应.byteLength) continue;
					if (魏烈思Header) {
						const response = new Uint8Array(魏烈思Header.length + 转发响应.byteLength);
						response.set(魏烈思Header, 0);
						response.set(转发响应, 魏烈思Header.length);
						await WebSocket发送并等待(webSocket, response.buffer);
						魏烈思Header = null;
					} else {
						await WebSocket发送并等待(webSocket, 转发响应);
					}
				}
			},
		}));
	} catch (error) {
		log(`[UDP转发] DNS 转发失败: ${(error as { message?: string })?.message ?? error}`);
	}
}
export async function 转发木马UDP数据(
	chunk: Uint8Array | ArrayBuffer | ArrayBufferView,
	webSocket: ConnectStreamsWebSocket,
	上下文: { 缓存: Uint8Array } | null,
	request: Request | null,
): Promise<void> {
	const 当前块 = 数据转Uint8Array(chunk);
	const 缓存块 = 上下文?.缓存 instanceof Uint8Array ? 上下文.缓存 : new Uint8Array(0);
	const input = 缓存块.byteLength ? 拼接字节数据(缓存块, 当前块) : 当前块;
	let cursor = 0;

	while (cursor < input.byteLength) {
		const packetStart = cursor;
		const atype = input[cursor];
		let addrCursor = cursor + 1;
		let addrLen = 0;
		if (atype === 1) addrLen = 4;
		else if (atype === 4) addrLen = 16;
		else if (atype === 3) {
			if (input.byteLength < addrCursor + 1) break;
			addrLen = 1 + input[addrCursor];
		} else throw new Error(`invalid bbjan udp addressType: ${atype}`);

		const portCursor = addrCursor + addrLen;
		if (input.byteLength < portCursor + 6) break;

		const port = (input[portCursor] << 8) | input[portCursor + 1];
		const payloadLength = (input[portCursor + 2] << 8) | input[portCursor + 3];
		if (input[portCursor + 4] !== 0x0d || input[portCursor + 5] !== 0x0a) throw new Error('invalid bbjan udp delimiter');

		const payloadStart = portCursor + 6;
		const payloadEnd = payloadStart + payloadLength;
		if (input.byteLength < payloadEnd) break;

		const 地址端口头 = input.slice(packetStart, portCursor + 2);
		const payload = input.slice(payloadStart, payloadEnd);
		cursor = payloadEnd;

		if (port !== 53) throw new Error('UDP is not supported');
		if (!payload.byteLength) continue;

		let tcpDNS查询: Uint8Array = payload;
		if (payload.byteLength < 2 || ((payload[0] << 8) | payload[1]) !== payload.byteLength - 2) {
			tcpDNS查询 = new Uint8Array(payload.byteLength + 2);
			tcpDNS查询[0] = (payload.byteLength >>> 8) & 0xff;
			tcpDNS查询[1] = payload.byteLength & 0xff;
			tcpDNS查询.set(payload, 2);
		}

		const dns响应上下文 = { 缓存: new Uint8Array(0) };
		await forwardataudp(tcpDNS查询, webSocket, null, request, (dnsRespChunk: Uint8Array) => {
			const 当前响应块 = 数据转Uint8Array(dnsRespChunk);
			const 响应输入 = dns响应上下文.缓存.byteLength ? 拼接字节数据(dns响应上下文.缓存, 当前响应块) : 当前响应块;
			const 响应帧列表: Uint8Array[] = [];
			let responseCursor = 0;
			while (responseCursor + 2 <= 响应输入.byteLength) {
				const dnsLen = (响应输入[responseCursor] << 8) | 响应输入[responseCursor + 1];
				const dnsStart = responseCursor + 2;
				const dnsEnd = dnsStart + dnsLen;
				if (dnsEnd > 响应输入.byteLength) break;
				const dnsPayload = 响应输入.slice(dnsStart, dnsEnd);
				const frame = new Uint8Array(地址端口头.byteLength + 4 + dnsPayload.byteLength);
				frame.set(地址端口头, 0);
				frame[地址端口头.byteLength] = (dnsPayload.byteLength >>> 8) & 0xff;
				frame[地址端口头.byteLength + 1] = dnsPayload.byteLength & 0xff;
				frame[地址端口头.byteLength + 2] = 0x0d;
				frame[地址端口头.byteLength + 3] = 0x0a;
				frame.set(dnsPayload, 地址端口头.byteLength + 4);
				响应帧列表.push(frame);
				responseCursor = dnsEnd;
			}
			dns响应上下文.缓存 = 响应输入.slice(responseCursor);
			return 响应帧列表.length ? 响应帧列表 : new Uint8Array(0);
		});
	}

	if (上下文) 上下文.缓存 = input.slice(cursor);
}
