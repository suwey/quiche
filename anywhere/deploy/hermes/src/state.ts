// 全局可变状态（原 _worker.js 顶部 let 变量）。
// 模块单例：每个 isolate 内共享一份，跟 Pages 项目语义保持一致。

import type { ParsedProxyAddress } from './types';

export interface ConfigJSON {
	[key: string]: unknown;
}

export const state = {
	config_JSON: null as ConfigJSON | null,
	反代IP: '' as string,
	启用SOCKS5反代: null as null | 'socks5' | 'http' | 'https' | 'turn' | 'sstp',
	启用SOCKS5全局反代: false as boolean,
	我的SOCKS5账号: '' as string,
	parsedSocks5Address: {} as ParsedProxyAddress | Record<string, never>,
	缓存SOCKS5白名单: null as string[] | null,
	缓存反代IP: undefined as string | undefined,
	缓存反代解析数组: undefined as Array<[string, number]> | undefined,
	缓存反代数组索引: 0 as number,
	// PROXYIP 失败黑名单：{ "ip:port": 失效截止时间戳 }。
	// 由 connectStreams 检测 TLS handshake_failure / 极短响应触发拉黑。
	反代失败黑名单: new Map<string, number>(),
	启用反代兜底: true as boolean,
	调试日志打印: false as boolean,
	SOCKS5白名单: [
		'*tapecontent.net',
		'*cloudatacdn.com',
		'*loadshare.org',
		'*cdn-centaurus.com',
		'scholar.google.com',
	] as string[],
	TCP并发拨号数: 2 as number,
	反代并发拨号数: 1 as number,
	预加载竞速拨号: false as boolean,
};

export const Version = '2026-07-29 23:57:34';

export const 帧首帧标记 = 0x80;
export const 帧关闭标记 = 0x40;
export const 帧数据标记 = 0x00;

export const Pages静态页面 = 'https://edt-pages.github.io';
// 默认反代 IP 域名特征码（与上游 openclaw 一致，避免字面量直出）。
export const 特征码字典 = [
	(Proxy.name + 'IP').toUpperCase(),
	'cmliu',
	'090227',
];

export const WS早期数据最大字节 = 8 * 1024;
export const WS早期数据最大头长度 = Math.ceil((WS早期数据最大字节 * 4) / 3) + 4;

export const 上行合包目标字节 = 20 * 1024;
export const 上行队列最大字节 = 16 * 1024 * 1024;
export const 上行队列最大条目 = 4096;

export const 下行Grain包字节 = 32 * 1024;
export const 下行Grain尾部阈值 = 512;
export const 下行Grain静默毫秒 = 0;

export function log(...args: unknown[]): void {
	if (state.调试日志打印) console.log(...args);
}
