// HermesAgentDispatcher Durable Object：包揽所有请求处理。
// 用 ctx.storage.sql 模拟原 Pages 项目里的 env.KV 接口。
// 使用 DO hibernation 模式处理 WebSocket 连接。

import { DurableObject } from 'cloudflare:workers';

import { 处理请求 } from './router';
import type { WSHandoff, WebSocketSession } from './transport-ws';
import type { Env, KVAdapter, RuntimeEnv } from './types';

/** 把 ctx.storage.sql 包成兼容 `env.KV.get/put` 的简单 KV。 */
function 创建SQL_KV(state: DurableObjectState): KVAdapter {
	const sql = state.storage.sql;
	sql.exec('CREATE TABLE IF NOT EXISTS kv (k TEXT PRIMARY KEY, v TEXT NOT NULL)');
	return {
		async get(key: string): Promise<string | null> {
			const cursor = sql.exec<{ v: string }>('SELECT v FROM kv WHERE k = ? LIMIT 1', key);
			const row = cursor.toArray()[0];
			return row ? row.v : null;
		},
		async put(key: string, value: string): Promise<void> {
			sql.exec('INSERT INTO kv (k, v) VALUES (?, ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v', key, value);
		},
	};
}

function 错误响应(err: unknown, label: string, env: Env, request: Request): Response {
	console.error(`[${label}] ${request.method} ${new URL(request.url).pathname} crashed:`, err);
	console.error(`[${label}] stack:`, (err as { stack?: string })?.stack);
	if (env.DEBUG) {
		const stack = (err as { stack?: string })?.stack || String(err);
		return new Response(`[${label} crash] ${(err as { message?: string })?.message || err}\n\n${stack}`, {
			status: 500,
			headers: { 'Content-Type': 'text/plain; charset=utf-8' },
		});
	}
	throw err;
}

export class HermesAgentDispatcher extends DurableObject<Env> {
	private readonly kv: KVAdapter;
	private sessions = new Map<WebSocket, WebSocketSession>();

	constructor(ctx: DurableObjectState, env: Env) {
		super(ctx, env);
		this.kv = 创建SQL_KV(ctx);
	}

	override async fetch(request: Request): Promise<Response> {
		const runtimeEnv: RuntimeEnv = Object.assign({}, this.env, { KV: this.kv });
		const exec: ExecutionContext = {
			waitUntil: (p: Promise<unknown>) => this.ctx.waitUntil(p),
			passThroughOnException: () => { /* DO 不支持 */ },
			props: {} as ExecutionContext['props'],
		} as ExecutionContext;
		try {
			const result = await 处理请求(request, runtimeEnv, exec);
			if (isWSHandoff(result)) {
				this.ctx.acceptWebSocket(result.serverSock);
				this.sessions.set(result.serverSock, result.session);
				return result.response;
			}
			return result;
		} catch (err) {
			return 错误响应(err, 'DO', this.env, request);
		}
	}

	override async webSocketMessage(
		ws: WebSocket, message: string | ArrayBuffer,
	): Promise<void> {
		const session = this.sessions.get(ws);
		if (session) {
			session.handleMessage(message);
		}
	}

	override async webSocketClose(
		ws: WebSocket, code: number, reason: string, wasClean: boolean,
	): Promise<void> {
		const session = this.sessions.get(ws);
		console.log(`[DO] webSocketClose code=${code} reason=${JSON.stringify(reason)} wasClean=${wasClean} hasSession=${!!session}`);
		if (session) {
			session.handleClose();
			this.sessions.delete(ws);
		}
	}

	override async webSocketError(ws: WebSocket, error: unknown): Promise<void> {
		const session = this.sessions.get(ws);
		console.log(`[DO] webSocketError error=${JSON.stringify((error as { message?: string })?.message ?? String(error))} hasSession=${!!session}`);
		if (session) {
			session.handleError();
			this.sessions.delete(ws);
		}
	}
}

function isWSHandoff(result: Response | WSHandoff): result is WSHandoff {
	return (
		result !== null &&
		typeof result === 'object' &&
		'response' in result &&
		'serverSock' in result &&
		'session' in result
	);
}

// 隧道分片：把 mless 连接池的各条隧道分散到多个 DO 实例上。
//
// 单实例（getByName('hermes')）下全部隧道挤在一个单线程 DO 里：
// - CPU 限额被所有流共享，双站高吞吐直接打满 → 全局卡顿；
// - DO 被 CF 强杀/逐出时一死全死（现场：5 条隧道 30 秒内 1005/1006 全灭）。
//
// 客户端（anywhere mless WS 池）在隧道路径上带 `_hslot=<slot>` 标记；
// 带 `_hslot` 的隧道请求按值取模分片，其余请求（admin/订阅/配置页）
// 一律落 shard 0 —— KV（config.json 等）只在 shard 0 上有完整状态，
// 隧道数据面不读 KV，因此各分片 DO 独立持有自己的 WS session 是安全的。
const DO_SHARD_COUNT = 8;

function 解析隧道分片(request: Request, url: URL): number | null {
	const upgradeHeader = (request.headers.get('Upgrade') || '').toLowerCase();
	if (upgradeHeader !== 'websocket' && request.method !== 'POST') {
		return null;
	}
	const raw = url.searchParams.get('_hslot');
	if (raw === null) return null;
	const slot = Number(raw);
	if (!Number.isInteger(slot) || slot < 0) return null;
	return slot % DO_SHARD_COUNT;
}

export default {
	async fetch(request: Request, env: Env): Promise<Response> {
		try {
			// url 已在 router 归一化过 %3f 等转义，这里用原始 URL 解析一次即可；
			// `_hslot` 是纯数字参数，不受那些转义影响。
			const url = new URL(request.url);
			const shard = 解析隧道分片(request, url) ?? 0;
			const stub = env.HERMES_AGENT_DISPATCHER.getByName(
				shard === 0 ? 'hermes' : `hermes:${shard}`,
			);
			return await stub.fetch(request);
		} catch (err) {
			return 错误响应(err, 'Worker', env, request);
		}
	},
} satisfies ExportedHandler<Env>;
