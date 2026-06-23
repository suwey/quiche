// gRPC over HTTP/2: 双向流，前后端用 5 字节长度前缀帧 + protobuf 单字段。

import { log } from './state';
import { 下行Grain包字节, 下行Grain静默毫秒 } from './state';
import { 数据转Uint8Array, 有效数据长度, isSpeedTestSite } from './utils';
import { 解析木马请求, 解析魏烈思请求 } from './protocol';
import { 创建上行写入队列, forwardataTCP, forwardataudp, 转发木马UDP数据 } from './forward';
import type { RemoteConnWrapper } from './forward';
import type { TCPSocket } from './types';

export async function 处理gRPC请求(request: Request, yourUUID: string): Promise<Response> {
	if (!request.body) return new Response('Bad Request', { status: 400 });
	const reader = request.body.getReader();
	const remoteConnWrapper: RemoteConnWrapper = { socket: null, connectingPromise: null, retryConnect: null, socketWritePromise: null };
	let isDnsQuery = false;
	const 木马UDP上下文 = { 缓存: new Uint8Array(0) };
	let 判断是否是木马: boolean | null = null;
	let 当前写入Socket: TCPSocket | null = null;
	let 远端写入器: WritableStreamDefaultWriter<Uint8Array> | null = null;
	let GRPC上行写入队列: ReturnType<typeof 创建上行写入队列> | null = null;

	const grpcHeaders = new Headers({
		'Content-Type': 'application/grpc',
		'grpc-status': '0',
		'X-Accel-Buffering': 'no',
		'Cache-Control': 'no-store',
	});

	const 下行缓存上限 = 下行Grain包字节;
	const 下行刷新间隔 = Math.max(下行Grain静默毫秒, 1);

	return new Response(
		new ReadableStream<Uint8Array>({
			async start(controller) {
				let 已关闭 = false;
				let 发送队列: Uint8Array[] = [];
				let 队列字节数 = 0;
				let 刷新定时器: ReturnType<typeof setTimeout> | null = null;
				let 刷新Microtask已排队 = false;

				interface GrpcBridge { readyState: number; send(data: Uint8Array | ArrayBuffer | ArrayBufferView): void; close(): void }

				const 刷新发送队列 = (force = false): void => {
					刷新Microtask已排队 = false;
					clearTimeout(刷新定时器 ?? null);
					刷新定时器 = null;
					if ((!force && 已关闭) || 队列字节数 === 0) return;
					const out = new Uint8Array(队列字节数);
					let offset = 0;
					for (const item of 发送队列) {
						out.set(item, offset);
						offset += item.byteLength;
					}
					发送队列 = [];
					队列字节数 = 0;
					try {
						controller.enqueue(out);
					} catch {
						已关闭 = true;
						grpcBridge.readyState = WebSocket.CLOSED;
					}
				};

				const 安排刷新发送队列 = (): void => {
					if (队列字节数 >= 下行缓存上限) {
						刷新发送队列();
						return;
					}
					if (刷新Microtask已排队 || 刷新定时器) return;
					刷新Microtask已排队 = true;
					queueMicrotask(() => {
						刷新Microtask已排队 = false;
						if (已关闭 || 队列字节数 === 0 || 刷新定时器) return;
						刷新定时器 = setTimeout(() => 刷新发送队列(), 下行刷新间隔);
					});
				};

				const grpcBridge: GrpcBridge = {
					readyState: WebSocket.OPEN,
					send(data) {
						if (已关闭) return;
						const chunk = 数据转Uint8Array(data);
						const lenBytes数组: number[] = [];
						let remaining = chunk.byteLength >>> 0;
						while (remaining > 127) {
							lenBytes数组.push((remaining & 0x7f) | 0x80);
							remaining >>>= 7;
						}
						lenBytes数组.push(remaining);
						const lenBytes = new Uint8Array(lenBytes数组);
						const protobufLen = 1 + lenBytes.length + chunk.byteLength;
						const frame = new Uint8Array(5 + protobufLen);
						frame[0] = 0;
						frame[1] = (protobufLen >>> 24) & 0xff;
						frame[2] = (protobufLen >>> 16) & 0xff;
						frame[3] = (protobufLen >>> 8) & 0xff;
						frame[4] = protobufLen & 0xff;
						frame[5] = 0x0a;
						frame.set(lenBytes, 6);
						frame.set(chunk, 6 + lenBytes.length);
						发送队列.push(frame);
						队列字节数 += frame.byteLength;
						安排刷新发送队列();
					},
					close() {
						if (this.readyState === WebSocket.CLOSED) return;
						刷新发送队列(true);
						已关闭 = true;
						this.readyState = WebSocket.CLOSED;
						try { controller.close(); } catch { /* ignore */ }
					},
				};

				const 关闭连接 = (): void => {
					if (已关闭) return;
					GRPC上行写入队列?.清空();
					刷新发送队列(true);
					已关闭 = true;
					grpcBridge.readyState = WebSocket.CLOSED;
					clearTimeout(刷新定时器 ?? null);
					if (远端写入器) {
						try { 远端写入器.releaseLock(); } catch { /* ignore */ }
						远端写入器 = null;
					}
					当前写入Socket = null;
					try { reader.releaseLock(); } catch { /* ignore */ }
					try { remoteConnWrapper.socket?.close(); } catch { /* ignore */ }
					try { controller.close(); } catch { /* ignore */ }
				};

				const 释放远端写入器 = (): void => {
					if (远端写入器) {
						try { 远端写入器.releaseLock(); } catch { /* ignore */ }
						远端写入器 = null;
					}
					当前写入Socket = null;
				};

				const 上行写入队列 = (GRPC上行写入队列 = 创建上行写入队列({
					获取写入器: () => {
						const socket = remoteConnWrapper.socket;
						if (!socket) return null;
						if (socket !== 当前写入Socket) {
							释放远端写入器();
							当前写入Socket = socket;
							远端写入器 = socket.writable.getWriter();
						}
						return 远端写入器;
					},
					释放写入器: 释放远端写入器,
					重试连接: async () => {
						if (typeof remoteConnWrapper.retryConnect !== 'function') throw new Error('retry unavailable');
						await remoteConnWrapper.retryConnect();
					},
					关闭连接,
					名称: 'gRPC上行',
				}));

				const 写入远端 = async (payload: Uint8Array, allowRetry = true): Promise<boolean> => {
					const r = 上行写入队列.写入并等待(payload, allowRetry);
					return r === true ? true : await r;
				};

				try {
					let pending = new Uint8Array(0);
					for (;;) {
						const { done, value } = await reader.read();
						if (done) break;
						if (!value || value.byteLength === 0) continue;
						const 当前块 = 数据转Uint8Array(value);
						const merged = new Uint8Array(pending.length + 当前块.length);
						merged.set(pending, 0);
						merged.set(当前块, pending.length);
						pending = merged;
						while (pending.byteLength >= 5) {
							const grpcLen = ((pending[1] << 24) >>> 0) | (pending[2] << 16) | (pending[3] << 8) | pending[4];
							const frameSize = 5 + grpcLen;
							if (pending.byteLength < frameSize) break;
							const grpcPayload = pending.subarray(5, frameSize);
							pending = pending.slice(frameSize);
							if (!grpcPayload.byteLength) continue;
							let payload = grpcPayload;
							if (payload.byteLength >= 2 && payload[0] === 0x0a) {
								let shift = 0;
								let offset = 1;
								let varint有效 = false;
								while (offset < payload.length) {
									const current = payload[offset++];
									if ((current & 0x80) === 0) {
										varint有效 = true;
										break;
									}
									shift += 7;
									if (shift > 35) break;
								}
								if (varint有效) payload = payload.subarray(offset);
							}
							if (!payload.byteLength) continue;
							if (isDnsQuery) {
								if (判断是否是木马) await 转发木马UDP数据(payload, grpcBridge as Parameters<typeof 转发木马UDP数据>[1], 木马UDP上下文, request);
								else await forwardataudp(payload, grpcBridge as Parameters<typeof forwardataudp>[1], null, request);
								continue;
							}
							if (remoteConnWrapper.socket) {
								if (!(await 写入远端(payload))) throw new Error('Remote socket is not ready');
							} else {
								const 首包bytes = 数据转Uint8Array(payload);
								if (判断是否是木马 === null) 判断是否是木马 = 首包bytes.byteLength >= 58 && 首包bytes[56] === 0x0d && 首包bytes[57] === 0x0a;
								if (判断是否是木马) {
									const 解析结果 = 解析木马请求(首包bytes, yourUUID);
									if (解析结果.hasError) throw new Error(解析结果.message || 'Invalid bbjan request');
									const { port, hostname, rawClientData, isUDP } = 解析结果;
									log(`[gRPC] 木马首包: ${hostname}:${port} | UDP: ${isUDP ? '是' : '否'}`);
									if (isSpeedTestSite(hostname)) throw new Error('Speedtest site is blocked');
									if (isUDP) {
										isDnsQuery = true;
										if (有效数据长度(rawClientData) > 0) await 转发木马UDP数据(rawClientData, grpcBridge as Parameters<typeof 转发木马UDP数据>[1], 木马UDP上下文, request);
									} else {
										await forwardataTCP(hostname, port, rawClientData, grpcBridge as Parameters<typeof forwardataTCP>[3], null, remoteConnWrapper, yourUUID, request);
									}
								} else {
									判断是否是木马 = false;
									const 解析结果 = 解析魏烈思请求(首包bytes, yourUUID);
									if (解析结果.hasError) throw new Error(解析结果.message || 'Invalid 魏烈思 request');
									const { port, hostname, version, isUDP, rawClientData } = 解析结果;
									log(`[gRPC] 魏烈思首包: ${hostname}:${port} | UDP: ${isUDP ? '是' : '否'}`);
									if (isSpeedTestSite(hostname)) throw new Error('Speedtest site is blocked');
									if (isUDP) {
										if (port !== 53) throw new Error('UDP is not supported');
										isDnsQuery = true;
									}
									const respHeader = new Uint8Array([version ?? 0, 0]);
									grpcBridge.send(respHeader);
									const rawData = rawClientData;
									if (isDnsQuery) {
										if (判断是否是木马) await 转发木马UDP数据(rawData, grpcBridge as Parameters<typeof 转发木马UDP数据>[1], 木马UDP上下文, request);
										else await forwardataudp(rawData, grpcBridge as Parameters<typeof forwardataudp>[1], null, request);
									} else {
										await forwardataTCP(hostname, port, rawData, grpcBridge as Parameters<typeof forwardataTCP>[3], null, remoteConnWrapper, yourUUID, request);
									}
								}
							}
						}
						刷新发送队列();
					}
					await 上行写入队列.等待空();
				} catch (err) {
					log(`[gRPC转发] 处理失败: ${(err as { message?: string })?.message || err}`);
				} finally {
					上行写入队列.清空();
					释放远端写入器();
					关闭连接();
				}
			},
			cancel() {
				GRPC上行写入队列?.清空();
				try { remoteConnWrapper.socket?.close(); } catch { /* ignore */ }
				try { reader.releaseLock(); } catch { /* ignore */ }
			},
		}),
		{ status: 200, headers: grpcHeaders }
	);
}
