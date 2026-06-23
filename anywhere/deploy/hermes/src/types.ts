// 共享类型定义。

import type { HermesAgentDispatcher } from './index';

export interface Env {
	HERMES_AGENT_DISPATCHER: DurableObjectNamespace<HermesAgentDispatcher>;
	ADMIN?: string;
	admin?: string;
	PASSWORD?: string;
	password?: string;
	pswd?: string;
	TOKEN?: string;
	KEY?: string;
	UUID?: string;
	uuid?: string;
	HOST?: string;
	PATH?: string;
	URL?: string;
	PROXYIP?: string;
	GO2SOCKS5?: string;
	DEBUG?: string;
	PRELOAD_RACE_DIAL?: string;
	BEST_SUB?: string;
	OFF_LOG?: string;
}

/** 兼容原 Pages 项目里 `env.KV.get/put` 调用形态的存储抽象。 */
export interface KVAdapter {
	get(key: string): Promise<string | null>;
	put(key: string, value: string): Promise<void>;
}

/** Pages 的 env 对象，透传所有原始环境变量并把 SQL-backed KV 注入为 `KV` 字段。 */
export type RuntimeEnv = Env & { KV: KVAdapter };

/** TCP 连接选项与初始化参数（Cloudflare Sockets API 形态）。 */
export interface TCPConnectOptions {
	hostname: string;
	port: number;
}

export interface TCPConnectInit {
	secureTransport?: 'on' | 'off' | 'starttls';
	allowHalfOpen?: boolean;
}

export interface TCPSocket {
	readable: ReadableStream<Uint8Array>;
	writable: WritableStream<Uint8Array>;
	closed: Promise<void>;
	opened?: Promise<unknown>;
	close(): void | Promise<void>;
}

export type TCPConnector = (options: TCPConnectOptions, init?: TCPConnectInit) => TCPSocket;

/** 解析后的代理凭据。 */
export interface ParsedProxyAddress {
	username?: string;
	password?: string;
	hostname: string;
	port: number;
}

/** 魏烈思 / 木马 协议解析的统一返回。 */
export interface ParsedRequestOK {
	hasError: false;
	addressType?: number;
	port: number;
	hostname: string;
	isUDP: boolean;
	rawClientData: Uint8Array;
	version?: number;
}

export interface ParsedRequestError {
	hasError: true;
	message: string;
}

export type ParsedRequest = ParsedRequestOK | ParsedRequestError;

/** 兼容前端写入的最简 WebSocket 形态（XHTTP / gRPC 桥接对象会冒充它）。 */
export interface SocketLike {
	readyState: number;
	send(data: ArrayBuffer | ArrayBufferView | Uint8Array): unknown;
	close(): void;
}
