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

export default {
	async fetch(request: Request, env: Env): Promise<Response> {
		try {
			const stub = env.HERMES_AGENT_DISPATCHER.getByName('hermes');
			return await stub.fetch(request);
		} catch (err) {
			return 错误响应(err, 'Worker', env, request);
		}
	},
} satisfies ExportedHandler<Env>;
