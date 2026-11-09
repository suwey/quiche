// Hermes 部署入口：Worker + Durable Object 分层架构。
//
// 数据面（WS upgrade、隧道 POST → transport-ws/xhttp/grpc）完全不碰 KV，
// 由 Worker 侧直接调用 `处理请求`，不经过 DO —— 省掉每请求 1 次 DO 计费。
// 仅 KV 路径（sub / admin）转发给 Durable Object `HermesAgentDispatcher`，
// DO 内用 ctx.storage.sql 模拟原 Pages 项目里的 env.KV 接口。
// WebSocket 由 Worker 原生 WebSocket + 事件监听驱动，不再进 DO hibernation。

import { DurableObject } from 'cloudflare:workers';

import { 处理请求 } from './router';
import type { WSHandoff } from './transport-ws';
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

/** Worker 侧占位 KV：非 KV 路径意外触到 KV 时显式报错，不静默。 */
const 不可用KV适配器: KVAdapter = {
	async get(): Promise<string | null> {
		throw new Error('KV 仅在 DO 上下文可用（sub/admin 路径）');
	},
	async put(): Promise<void> {
		throw new Error('KV 仅在 DO 上下文可用（sub/admin 路径）');
	},
};

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
				// WS 数据面已由 Worker 直接处理，不应路由到 DO；防御性兜底。
				throw new Error('WS 请求不应路由到 DO（sub/admin 路径不含 WS upgrade）');
			}
			return result;
		} catch (err) {
			return 错误响应(err, 'DO', this.env, request);
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
	async fetch(
		request: Request,
		env: Env,
		ctx: ExecutionContext,
	): Promise<Response> {
		try {
			// 与 router.ts 开头相同的 URL 归一化（%5C / 反斜杠剔除、%3f 还原），
			// 只用于解析访问路径做分流；原始 request 原样传下去，
			// `处理请求` 内部会自己再归一化一次，行为与现状保持一致。
			let 请求URL文本 = request.url.replace(/%5[Cc]/g, '').replace(/\\/g, '');
			const 请求URL锚点索引 = 请求URL文本.indexOf('#');
			const 请求URL主体部分 = 请求URL锚点索引 === -1 ? 请求URL文本 : 请求URL文本.slice(0, 请求URL锚点索引);
			if (!请求URL主体部分.includes('?') && /%3f/i.test(请求URL主体部分)) {
				const 请求URL锚点部分 = 请求URL锚点索引 === -1 ? '' : 请求URL文本.slice(请求URL锚点索引);
				请求URL文本 = 请求URL主体部分.replace(/%3f/i, '?') + 请求URL锚点部分;
			}
			const url = new URL(请求URL文本);

			// KV 只在 sub / admin 路径用到；这些请求转发给 DO，
			// 其余（隧道数据面等）留在 Worker 直接处理，节省 DO 计费。
			const 访问路径 = url.pathname.slice(1).toLowerCase();
			const 需要KV = 访问路径 === 'sub' || 访问路径 === 'admin' || 访问路径.startsWith('admin/');
			if (需要KV) {
				const stub = env.HERMES_AGENT_DISPATCHER.getByName('hermes');
				return await stub.fetch(request);
			}

			const runtimeEnv: RuntimeEnv = Object.assign({}, env, { KV: 不可用KV适配器 });
			const result = await 处理请求(request, runtimeEnv, ctx);
			if (isWSHandoff(result)) {
				// Worker 原生 WebSocket：事件监听驱动会话，不进 DO hibernation。
				result.serverSock.accept();
				result.serverSock.addEventListener('message', (e) => result.session.handleMessage(e.data));
				result.serverSock.addEventListener('close', () => {
					result.session.handleClose();
				});
				result.serverSock.addEventListener('error', () => {
					result.session.handleError();
				});
				return result.response;
			}
			return result;
		} catch (err) {
			return 错误响应(err, 'Worker', env, request);
		}
	},
} satisfies ExportedHandler<Env>;
