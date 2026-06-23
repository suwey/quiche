// 上行写包合并队列。原文件里 XHTTP/gRPC/WS 都各自创建一个。

import { 上行合包目标字节, 上行队列最大字节, 上行队列最大条目, log } from './state';
import { 数据转Uint8Array } from './utils';

interface QueueCompletion {
	resolve: () => void;
	reject: (err: unknown) => void;
}

interface QueueItem {
	chunk: Uint8Array;
	allowRetry: boolean;
	completions: QueueCompletion[] | null;
}

interface RemoteWriter {
	write(chunk: Uint8Array): Promise<void>;
	releaseLock?(): void;
}

export interface 上行队列选项 {
	获取写入器: () => RemoteWriter | null | undefined;
	释放写入器?: () => void;
	重试连接?: () => Promise<void>;
	关闭连接?: (err?: unknown) => void;
	名称?: string;
}

export interface 上行队列控制 {
	写入(data: Uint8Array | ArrayBuffer | ArrayBufferView, allowRetry?: boolean): boolean;
	写入并等待(data: Uint8Array | ArrayBuffer | ArrayBufferView, allowRetry?: boolean): boolean | Promise<boolean>;
	等待空(): Promise<void>;
	清空(): void;
}

export function 创建上行写入队列(选项: 上行队列选项): 上行队列控制 {
	const { 获取写入器, 释放写入器, 重试连接, 关闭连接, 名称 = '上行队列' } = 选项;
	let chunks: Array<QueueItem | undefined> = [];
	let head = 0;
	let queuedBytes = 0;
	let draining = false;
	let closed = false;
	let bundleBuffer: Uint8Array | null = null;
	let idleResolvers: Array<() => void> = [];
	let activeCompletions: QueueCompletion[] | null = null;

	const settleCompletions = (completions: QueueCompletion[] | null, err: unknown = null): void => {
		if (!completions) return;
		for (const completion of completions) {
			if (err) completion.reject(err);
			else completion.resolve();
		}
	};

	const rejectQueued = (err: unknown): void => {
		for (let i = head; i < chunks.length; i++) {
			const item = chunks[i];
			if (item?.completions) settleCompletions(item.completions, err);
		}
	};

	const compact = (): void => {
		if (head > 32 && head * 2 >= chunks.length) {
			chunks = chunks.slice(head);
			head = 0;
		}
	};

	const resolveIdle = (): void => {
		if (queuedBytes || draining || !idleResolvers.length) return;
		const resolvers = idleResolvers;
		idleResolvers = [];
		for (const resolve of resolvers) resolve();
	};

	const clear = (err: unknown = null): void => {
		const closeErr = err || (closed ? new Error(`${名称}: queue closed`) : null);
		if (closeErr) {
			rejectQueued(closeErr);
			settleCompletions(activeCompletions, closeErr);
			activeCompletions = null;
		}
		chunks = [];
		head = 0;
		queuedBytes = 0;
		resolveIdle();
	};

	const shift = (): QueueItem | null => {
		if (head >= chunks.length) return null;
		const item = chunks[head];
		chunks[head++] = undefined;
		if (!item) return null;
		queuedBytes -= item.chunk.byteLength;
		compact();
		return item;
	};

	const bundle = (): QueueItem | null => {
		const first = shift();
		if (!first) return null;
		if (head >= chunks.length || first.chunk.byteLength >= 上行合包目标字节) return first;

		let byteLength = first.chunk.byteLength;
		let end = head;
		let allowRetry = first.allowRetry;
		let completions = first.completions || null;
		while (end < chunks.length) {
			const next = chunks[end];
			if (!next) break;
			const nextLength = byteLength + next.chunk.byteLength;
			if (nextLength > 上行合包目标字节) break;
			byteLength = nextLength;
			allowRetry = allowRetry && next.allowRetry;
			if (next.completions) completions = completions ? completions.concat(next.completions) : next.completions;
			end++;
		}
		if (end === head) return first;

		bundleBuffer ||= new Uint8Array(上行合包目标字节);
		bundleBuffer.set(first.chunk);
		let offset = first.chunk.byteLength;
		while (head < end) {
			const next = chunks[head];
			chunks[head++] = undefined;
			if (!next) continue;
			queuedBytes -= next.chunk.byteLength;
			bundleBuffer.set(next.chunk, offset);
			offset += next.chunk.byteLength;
		}
		compact();
		return { chunk: bundleBuffer.subarray(0, byteLength), allowRetry, completions };
	};

	const drain = async (): Promise<void> => {
		if (draining || closed) return;
		draining = true;
		try {
			for (;;) {
				if (closed) break;
				const item = bundle();
				if (!item) break;
				let writer = 获取写入器();
				if (!writer) throw new Error(`${名称}: remote writer unavailable`);
				const completions = item.completions || null;
				activeCompletions = completions;
				try {
					try {
						await writer.write(item.chunk);
					} catch (err) {
						释放写入器?.();
						if (!item.allowRetry || typeof 重试连接 !== 'function') throw err;
						await 重试连接();
						writer = 获取写入器();
						if (!writer) throw err;
						await writer.write(item.chunk);
					}
					settleCompletions(completions);
				} catch (err) {
					settleCompletions(completions, err);
					throw err;
				} finally {
					if (activeCompletions === completions) activeCompletions = null;
				}
			}
		} catch (err) {
			closed = true;
			clear(err);
			log(`[${名称}] 写入失败: ${(err as { message?: string })?.message || err}`);
			try { 关闭连接?.(err); } catch { /* ignore */ }
		} finally {
			draining = false;
			if (!closed && head < chunks.length) queueMicrotask(drain);
			else resolveIdle();
		}
	};

	const enqueue = (data: Uint8Array | ArrayBuffer | ArrayBufferView, allowRetry = true, waitForFlush = false): boolean | Promise<boolean> => {
		if (closed) return false;
		if (!获取写入器()) return false;
		const chunk = 数据转Uint8Array(data);
		if (!chunk.byteLength) return true;
		const nextBytes = queuedBytes + chunk.byteLength;
		const nextItems = chunks.length - head + 1;
		if (nextBytes > 上行队列最大字节 || nextItems > 上行队列最大条目) {
			closed = true;
			const err = Object.assign(new Error(`${名称}: upload queue overflow (${nextBytes}B/${nextItems})`), { isQueueOverflow: true });
			clear(err);
			log(`[${名称}] 队列超限，关闭连接`);
			try { 关闭连接?.(err); } catch { /* ignore */ }
			throw err;
		}
		let completionPromise: Promise<unknown> | null = null;
		let completions: QueueCompletion[] | null = null;
		if (waitForFlush) {
			completions = [];
			const list = completions;
			completionPromise = new Promise<void>((resolve, reject) => {
				list.push({ resolve, reject });
			});
		}
		chunks.push({ chunk, allowRetry, completions });
		queuedBytes = nextBytes;
		if (!draining) queueMicrotask(drain);
		if (waitForFlush && completionPromise) {
			return completionPromise.then(() => true);
		}
		return true;
	};

	return {
		写入(data, allowRetry = true) {
			const result = enqueue(data, allowRetry, false);
			return result === true;
		},
		写入并等待(data, allowRetry = true) {
			return enqueue(data, allowRetry, true);
		},
		async 等待空() {
			if (!queuedBytes && !draining) return;
			await new Promise<void>((resolve) => idleResolvers.push(resolve));
		},
		清空() {
			closed = true;
			clear();
		},
	};
}
