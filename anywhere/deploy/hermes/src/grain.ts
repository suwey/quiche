// 下行 Grain 发送器 + 上行 Grain 合包流：批量合包 + microtask/timer flush。

import { 下行Grain包字节, 下行Grain尾部阈值, 下行Grain静默毫秒, 上行合包目标字节 } from './state';
import { 数据转Uint8Array, WebSocket发送并等待, closeSocketQuietly } from './utils';

interface SocketLikeSend {
	readyState: number;
	send(data: ArrayBuffer | ArrayBufferView): unknown;
	close?(): void;
}

export interface GrainSender {
	直接发送(data: Uint8Array | ArrayBuffer | ArrayBufferView): Promise<void>;
	发送(data: Uint8Array | ArrayBuffer | ArrayBufferView): Promise<void>;
	flush(): Promise<void>;
}

export function 创建下行Grain发送器(webSocket: SocketLikeSend, headerData: Uint8Array | null = null): GrainSender {
	const packetCap = 下行Grain包字节;
	const tailBytes = 下行Grain尾部阈值;
	const lowWaterBytes = Math.max(4096, tailBytes * 12);
	let header = headerData;
	let pendingBuffer = new Uint8Array(packetCap);
	let pendingBytes = 0;
	let flushTimer: ReturnType<typeof setTimeout> | null = null;
	let microtaskQueued = false;
	let generation = 0;
	let scheduledGeneration = 0;
	let waitRounds = 0;
	let flushPromise: Promise<void> | null = null;

	const 发送原始块 = async (chunk: Uint8Array): Promise<void> => {
		if (webSocket.readyState !== WebSocket.OPEN) throw new Error('ws.readyState is not open');
		await WebSocket发送并等待(webSocket, chunk);
	};

	const 附加响应头 = (chunk: Uint8Array): Uint8Array => {
		if (!header) return chunk;
		const merged = new Uint8Array(header.length + chunk.byteLength);
		merged.set(header, 0);
		merged.set(chunk, header.length);
		header = null;
		return merged;
	};

	const flush = async (): Promise<void> => {
		while (flushPromise) await flushPromise;
		clearTimeout(flushTimer ?? null);
		flushTimer = null;
		microtaskQueued = false;
		if (!pendingBytes) return;
		const output = pendingBuffer.subarray(0, pendingBytes).slice();
		pendingBuffer = new Uint8Array(packetCap);
		pendingBytes = 0;
		waitRounds = 0;
		flushPromise = 发送原始块(output).finally(() => {
			flushPromise = null;
		});
		return flushPromise;
	};

	const scheduleFlush = (): void => {
		if (flushTimer || microtaskQueued) return;
		microtaskQueued = true;
		scheduledGeneration = generation;
		queueMicrotask(() => {
			microtaskQueued = false;
			if (!pendingBytes || flushTimer) return;
			if (packetCap - pendingBytes < tailBytes) {
				flush().catch(() => closeSocketQuietly(webSocket));
				return;
			}
			flushTimer = setTimeout(() => {
				flushTimer = null;
				if (!pendingBytes) return;
				if (packetCap - pendingBytes < tailBytes) {
					flush().catch(() => closeSocketQuietly(webSocket));
					return;
				}
				if (waitRounds < 4 && (generation !== scheduledGeneration || pendingBytes < lowWaterBytes)) {
					waitRounds++;
					scheduledGeneration = generation;
					scheduleFlush();
					return;
				}
				flush().catch(() => closeSocketQuietly(webSocket));
			}, Math.max(下行Grain静默毫秒, 1));
		});
	};

	return {
		async 直接发送(data) {
			let chunk = 数据转Uint8Array(data);
			if (!chunk.byteLength) return;
			chunk = 附加响应头(chunk);
			await 发送原始块(chunk);
		},
		async 发送(data) {
			const chunk = 附加响应头(数据转Uint8Array(data));
			if (!chunk.byteLength) return;
			let offset = 0;
			const totalBytes = chunk.byteLength;
			while (offset < totalBytes) {
				if (!pendingBytes && totalBytes - offset >= packetCap) {
					const sendBytes = Math.min(packetCap, totalBytes - offset);
					const view = offset || sendBytes !== totalBytes ? chunk.subarray(offset, offset + sendBytes) : chunk;
					await 发送原始块(view);
					offset += sendBytes;
					continue;
				}
				const copyBytes = Math.min(packetCap - pendingBytes, totalBytes - offset);
				pendingBuffer.set(chunk.subarray(offset, offset + copyBytes), pendingBytes);
				pendingBytes += copyBytes;
				offset += copyBytes;
				generation++;
				if (pendingBytes === packetCap || packetCap - pendingBytes < tailBytes) await flush();
				else scheduleFlush();
			}
		},
		flush,
	};
}

/** 上行合包流（对齐上游 2026-08-11）：小块合并到目标字节再写，pipeTo 直通 socket.writable。 */
export interface 上行Grain合包流 {
	readable: ReadableStream<Uint8Array>;
	写入(chunk: Uint8Array | ArrayBuffer | ArrayBufferView): Promise<void>;
	结束(): Promise<void>;
}

export function 创建上行Grain合包流(目标字节: number = 上行合包目标字节): 上行Grain合包流 {
	const identity = typeof IdentityTransformStream !== 'undefined'
		? new IdentityTransformStream()
		: new TransformStream<Uint8Array, Uint8Array>();
	const writer = identity.writable.getWriter();
	const 缓冲 = new Uint8Array(目标字节);
	let 缓冲长度 = 0;
	let 定时器: ReturnType<typeof setTimeout> | null = null;
	let 在途写: Promise<void> | null = null;
	let 冲刷链: Promise<void> = Promise.resolve();

	const 清理定时器 = (): void => {
		if (定时器) {
			clearTimeout(定时器);
			定时器 = null;
		}
	};

	const 串行写 = async (chunk: Uint8Array): Promise<void> => {
		if (在途写) await 在途写;
		在途写 = writer.write(chunk);
		try { await 在途写; } finally { 在途写 = null; }
	};

	const 冲刷 = async (): Promise<void> => {
		if (缓冲长度) {
			const chunk = 缓冲.slice(0, 缓冲长度);
			缓冲长度 = 0;
			await 串行写(chunk);
		}
	};

	const 排队冲刷 = (): void => {
		冲刷链 = 冲刷链.then(() => 冲刷()).catch(() => { /* ignore */ });
	};

	const 启动定时器 = (): void => {
		if (定时器) return;
		定时器 = setTimeout(() => {
			定时器 = null;
			排队冲刷();
		}, 1);
	};

	return {
		readable: identity.readable,
		async 写入(chunk) {
			const data = 数据转Uint8Array(chunk);
			if (!data.byteLength) return;
			if (data.byteLength >= 目标字节) {
				清理定时器();
				if (缓冲长度) await 冲刷();
				await 串行写(data);
				return;
			}
			if (缓冲长度 + data.byteLength >= 目标字节) {
				const output = new Uint8Array(缓冲长度 + data.byteLength);
				output.set(缓冲.subarray(0, 缓冲长度), 0);
				output.set(data, 缓冲长度);
				缓冲长度 = 0;
				清理定时器();
				await 串行写(output);
			} else {
				缓冲.set(data, 缓冲长度);
				缓冲长度 += data.byteLength;
				启动定时器();
			}
		},
		async 结束() {
			清理定时器();
			try {
				await 冲刷链;
				await 冲刷();
				await writer.close();
			} finally {
				try { writer.releaseLock(); } catch { /* ignore */ }
			}
		},
	};
}
