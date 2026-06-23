import { TOKENS } from './tokens';
// 读取/初始化 config.json / cf.json / tg.json，所有持久化都走 KV 适配器。
// 原 _worker.js 的 env.KV.get/put 在 DO 里指向 SQL 后端。

import { state } from './state';
import { 整理成数组, MD5MD5, 掩码敏感信息 } from './utils';
import { 获取传输协议配置, 获取传输路径参数值 } from './sub-helpers';
import type { ConfigJSON } from './state';
import type { RuntimeEnv } from './types';

const _p = atob('UFJPWFlJUA==');

interface PathTemplateLeaf { 全局: string; 标准: string }
interface PathTemplate {
	SOCKS5?: PathTemplateLeaf;
	HTTP?: PathTemplateLeaf;
	HTTPS?: PathTemplateLeaf;
	TURN?: PathTemplateLeaf;
	SSTP?: PathTemplateLeaf;
	[index: string]: string | PathTemplateLeaf | undefined;
}

interface 反代SubObj {
	SOCKS5?: { 启用?: string | null; 全局?: boolean; 账号?: string; 白名单?: string[] };
	路径模板?: PathTemplate;
	[index: string]: string | boolean | undefined | { 启用?: string | null; 全局?: boolean; 账号?: string; 白名单?: string[] } | PathTemplate;
}

interface FullConfig extends ConfigJSON {
	TIME?: string;
	HOST?: string;
	HOSTS?: string[];
	UUID?: string;
	PATH?: string;
	协议类型?: string;
	传输协议?: string;
	gRPC模式?: string;
	gRPCUserAgent?: string;
	跳过证书验证?: boolean;
	启用0RTT?: boolean;
	TLS分片?: string | null;
	随机路径?: boolean;
	ECH?: boolean;
	ECHConfig?: { DNS?: string; SNI?: string };
	SS?: { 加密方式?: string; TLS?: boolean };
	Fingerprint?: string;
	完整节点路径?: string;
	LINK?: string;
	加载时间?: string;
	init?: string;
	优选订阅生成?: {
		local?: boolean;
		本地IP库?: { 随机IP?: boolean; 随机数量?: number; 指定端口?: number };
		SUB?: string | null;
		SUBNAME?: string;
		SUBUpdateTime?: number;
		TOKEN?: string;
	};
	订阅转换配置?: { SUBAPI?: string; SUBCONFIG?: string; SUBEMOJI?: boolean };
	反代?: 反代SubObj;
	TG?: { 启用?: boolean; BotToken?: unknown; ChatID?: unknown };
	CF?: {
		Email?: string | null;
		GlobalAPIKey?: unknown;
		AccountID?: unknown;
		APIToken?: unknown;
		UsageAPI?: string | null;
		Usage?: { success: boolean; pages: number; workers: number; total: number; max: number };
	};
}

export interface CloudflareUsage {
	success: boolean;
	pages: number;
	workers: number;
	total: number;
	max: number;
}

export async function getCloudflareUsage(Email: string | null, GlobalAPIKey: string | null, AccountID: string | null, APIToken: string | null): Promise<CloudflareUsage> {
	const API = 'https://api.cloudflare.com/client/v4';
	const sum = (a: Array<{ sum?: { requests?: number } } | undefined> | null | undefined): number =>
		a?.reduce((t, i) => t + (i?.sum?.requests || 0), 0) || 0;
	const cfg = { 'Content-Type': 'application/json' };

	try {
		if (!AccountID && (!Email || !GlobalAPIKey)) return { success: false, pages: 0, workers: 0, total: 0, max: 100000 };

		let resolvedAccountID: string | null = AccountID;
		if (!resolvedAccountID) {
			const r = await fetch(`${API}/accounts`, {
				method: 'GET',
				headers: { ...cfg, 'X-AUTH-EMAIL': Email!, 'X-AUTH-KEY': GlobalAPIKey! },
			});
			if (!r.ok) throw new Error(`账户获取失败: ${r.status}`);
			const d = (await r.json()) as { result?: Array<{ id?: string; name?: string }> };
			if (!d?.result?.length) throw new Error('未找到账户');
			const idx = d.result.findIndex((acc) => acc.name?.toLowerCase().startsWith((Email || '').toLowerCase()));
			resolvedAccountID = d.result[idx >= 0 ? idx : 0]?.id ?? null;
		}

		const now = new Date();
		now.setUTCHours(0, 0, 0, 0);
		const hdr = APIToken ? { ...cfg, Authorization: `Bearer ${APIToken}` } : { ...cfg, 'X-AUTH-EMAIL': Email!, 'X-AUTH-KEY': GlobalAPIKey! };

		const res = await fetch(`${API}/graphql`, {
			method: 'POST',
			headers: hdr,
			body: JSON.stringify({
				query: `query getBillingMetrics($AccountID: String!, $filter: AccountWorkersInvocationsAdaptiveFilter_InputObject) {
					viewer { accounts(filter: {accountTag: $AccountID}) {
						pagesFunctionsInvocationsAdaptiveGroups(limit: 1000, filter: $filter) { sum { requests } }
						workersInvocationsAdaptive(limit: 10000, filter: $filter) { sum { requests } }
					} }
				}`,
				variables: { AccountID: resolvedAccountID, filter: { datetime_geq: now.toISOString(), datetime_leq: new Date().toISOString() } },
			}),
		});

		if (!res.ok) throw new Error(`查询失败: ${res.status}`);
		const result = (await res.json()) as {
			errors?: Array<{ message: string }>;
			data?: {
				viewer?: {
					accounts?: Array<{
						pagesFunctionsInvocationsAdaptiveGroups?: Array<{ sum?: { requests?: number } }>;
						workersInvocationsAdaptive?: Array<{ sum?: { requests?: number } }>;
					}>;
				};
			};
		};
		if (result.errors?.length) throw new Error(result.errors[0].message);

		const acc = result?.data?.viewer?.accounts?.[0];
		if (!acc) throw new Error('未找到账户数据');

		const pages = sum(acc.pagesFunctionsInvocationsAdaptiveGroups);
		const workers = sum(acc.workersInvocationsAdaptive);
		const total = pages + workers;
		return { success: true, pages, workers, total, max: 100000 };
	} catch (error) {
		console.error('获取使用量错误:', (error as { message?: string })?.message || error);
		return { success: false, pages: 0, workers: 0, total: 0, max: 100000 };
	}
}

export async function 读取config_JSON(env: RuntimeEnv, hostname: string, userID: string, UA = 'Mozilla/5.0', 重置配置 = false): Promise<FullConfig> {
	const host = hostname;
	const Ali_DoH = 'https://dns.alidns.com/dns-query';
	const ECH_SNI = 'cloudflare-ech.com';
	const 占位符 = '{{IP:PORT}}';
	const 初始化开始时间 = performance.now();
	const 默认配置JSON: FullConfig = {
		TIME: new Date().toISOString(),
		HOST: host,
		HOSTS: [hostname],
		UUID: userID,
		PATH: '/',
		协议类型: 'vless',
		传输协议: 'ws',
		gRPC模式: 'gun',
		gRPCUserAgent: UA,
		跳过证书验证: false,
		启用0RTT: false,
		TLS分片: null,
		随机路径: false,
		ECH: false,
		ECHConfig: { DNS: Ali_DoH, SNI: ECH_SNI },
		SS: { 加密方式: 'aes-128-gcm', TLS: true },
		Fingerprint: 'chrome',
		优选订阅生成: {
			local: true,
			本地IP库: { 随机IP: true, 随机数量: 16, 指定端口: -1 },
			SUB: null,
			SUBNAME: 'edgetunnel',
			SUBUpdateTime: 3,
			TOKEN: await MD5MD5(hostname + userID),
		},
		订阅转换配置: {
			SUBAPI: 'https://SUBAPI.cmliussss.net',
			SUBCONFIG: 'https://raw.githubusercontent.com/cmliu/ACL4SSR/refs/heads/main/Clash/config/ACL4SSR_Online_Mini_MultiMode_CF.ini',
			SUBEMOJI: false,
		},
		反代: {
			[_p]: 'auto',
			SOCKS5: {
				启用: state.启用SOCKS5反代,
				全局: state.启用SOCKS5全局反代,
				账号: state.我的SOCKS5账号,
				白名单: state.SOCKS5白名单,
			},
			路径模板: {
				[_p]: 'proxyip=' + 占位符,
				SOCKS5: { 全局: 'socks5://' + 占位符, 标准: 'socks5=' + 占位符 },
				HTTP: { 全局: 'http://' + 占位符, 标准: 'http=' + 占位符 },
				HTTPS: { 全局: 'https://' + 占位符, 标准: 'https=' + 占位符 },
				TURN: { 全局: 'turn://' + 占位符, 标准: 'turn=' + 占位符 },
				SSTP: { 全局: 'sstp://' + 占位符, 标准: 'sstp=' + 占位符 },
			},
		},
		TG: { 启用: false, BotToken: null, ChatID: null },
		CF: {
			Email: null,
			GlobalAPIKey: null,
			AccountID: null,
			APIToken: null,
			UsageAPI: null,
			Usage: { success: false, pages: 0, workers: 0, total: 0, max: 100000 },
		},
	};

	let cfg: FullConfig = 默认配置JSON;
	try {
		const configJSON = await env.KV.get('config.json');
		if (!configJSON || 重置配置 === true) {
			await env.KV.put('config.json', JSON.stringify(默认配置JSON, null, 2));
			cfg = 默认配置JSON;
		} else {
			cfg = JSON.parse(configJSON) as FullConfig;
		}
	} catch (error) {
		console.error(`读取config_JSON出错: ${(error as { message?: string })?.message || error}`);
		cfg = 默认配置JSON;
	}
	state.config_JSON = cfg as ConfigJSON;

	if (!cfg.gRPCUserAgent) cfg.gRPCUserAgent = UA;
	cfg.HOST = host;
	if (!cfg.HOSTS) cfg.HOSTS = [hostname];
	if (env.HOST) cfg.HOSTS = (await 整理成数组(env.HOST)).map((h) => h.toLowerCase().replace(/^https?:\/\//, '').split('/')[0].split(':')[0]);
	cfg.UUID = userID;
	if (!cfg.随机路径) cfg.随机路径 = false;
	if (!cfg.启用0RTT) cfg.启用0RTT = false;

	if (env.PATH) cfg.PATH = env.PATH.startsWith('/') ? env.PATH : '/' + env.PATH;
	else if (!cfg.PATH) cfg.PATH = '/';

	if (!cfg.gRPC模式) cfg.gRPC模式 = 'gun';
	if (!cfg.SS) cfg.SS = { 加密方式: 'aes-128-gcm', TLS: false };

	const 反代 = (cfg.反代 ||= {});
	const 路径模板 = (反代.路径模板 ||= {});
	if (!路径模板[_p]) {
		反代.路径模板 = {
			[_p]: 'proxyip=' + 占位符,
			SOCKS5: { 全局: 'socks5://' + 占位符, 标准: 'socks5=' + 占位符 },
			HTTP: { 全局: 'http://' + 占位符, 标准: 'http=' + 占位符 },
			HTTPS: { 全局: 'https://' + 占位符, 标准: 'https=' + 占位符 },
			TURN: { 全局: 'turn://' + 占位符, 标准: 'turn=' + 占位符 },
			SSTP: { 全局: 'sstp://' + 占位符, 标准: 'sstp=' + 占位符 },
		};
	}
	const 模板 = 反代.路径模板!;
	if (!模板.HTTPS) 模板.HTTPS = { 全局: 'https://' + 占位符, 标准: 'https=' + 占位符 };
	if (!模板.TURN) 模板.TURN = { 全局: 'turn://' + 占位符, 标准: 'turn=' + 占位符 };
	if (!模板.SSTP) 模板.SSTP = { 全局: 'sstp://' + 占位符, 标准: 'sstp=' + 占位符 };

	const socks5启用大写 = 反代.SOCKS5?.启用?.toUpperCase();
	type 模板键 = keyof PathTemplate;
	const 代理配置 = socks5启用大写 ? 模板[socks5启用大写 as 模板键] as PathTemplateLeaf | undefined : undefined;

	let 路径反代参数 = '';
	if (代理配置 && 反代.SOCKS5?.账号) {
		路径反代参数 = (反代.SOCKS5.全局 ? 代理配置.全局 : 代理配置.标准).replace(占位符, 反代.SOCKS5.账号);
	} else {
		const 当前反代值 = 反代[_p];
		if (typeof 当前反代值 === 'string' && 当前反代值 !== 'auto' && 当前反代值) {
			const 模板模式 = (模板 as Record<string, string | undefined>)[_p] || '';
			路径反代参数 = 模板模式.replace(占位符, 当前反代值);
		}
	}

	let 反代查询参数 = '';
	if (路径反代参数.includes('?')) {
		const [反代路径部分, 反代查询部分] = 路径反代参数.split('?');
		路径反代参数 = 反代路径部分;
		反代查询参数 = 反代查询部分;
	}

	cfg.PATH = (cfg.PATH || '/').replace(路径反代参数, '').replace('//', '/');
	const normalizedPath = cfg.PATH === '/' ? '' : cfg.PATH.replace(/\/+(?=\?|$)/, '').replace(/\/+$/, '');
	const [路径部分, ...查询数组] = normalizedPath.split('?');
	const 查询部分 = 查询数组.length ? '?' + 查询数组.join('?') : '';
	const 最终查询部分 = 反代查询参数 ? (查询部分 ? 查询部分 + '&' + 反代查询参数 : '?' + 反代查询参数) : 查询部分;
	cfg.完整节点路径 = (路径部分 || '/') + (路径部分 && 路径反代参数 ? '/' : '') + 路径反代参数 + 最终查询部分 + (cfg.启用0RTT ? (最终查询部分 ? '&' : '?') + 'ed=2560' : '');

	if (!cfg.TLS分片 && cfg.TLS分片 !== null) cfg.TLS分片 = null;
	const TLS分片参数 = cfg.TLS分片 === 'Shadowrocket'
		? `&fragment=${encodeURIComponent('1,40-60,30-50,tlshello')}`
		: cfg.TLS分片 === 'Happ'
			? `&fragment=${encodeURIComponent('3,1,tlshello')}`
			: '';
	if (!cfg.Fingerprint) cfg.Fingerprint = 'chrome';
	if (!cfg.ECH) cfg.ECH = false;
	if (!cfg.ECHConfig) cfg.ECHConfig = { DNS: Ali_DoH, SNI: ECH_SNI };
	const ECHLINK参数 = cfg.ECH ? `&ech=${encodeURIComponent((cfg.ECHConfig.SNI ? cfg.ECHConfig.SNI + '+' : '') + cfg.ECHConfig.DNS)}` : '';
	const { type: 传输协议, 路径字段名, 域名字段名 } = 获取传输协议配置(cfg);
	const 传输路径参数值 = 获取传输路径参数值(cfg, cfg.完整节点路径);
	cfg.LINK = cfg.协议类型 === 'ss'
		? `${cfg.协议类型}://${btoa((cfg.SS?.加密方式 || 'aes-128-gcm') + ':' + userID)}@${host}:${cfg.SS?.TLS ? '443' : '80'}?plugin=v2${encodeURIComponent(`ray-plugin;mode=websocket;host=${host};path=${(cfg.完整节点路径.includes('?') ? cfg.完整节点路径.replace('?', '?enc=' + cfg.SS?.加密方式 + '&') : cfg.完整节点路径 + '?enc=' + cfg.SS?.加密方式) + (cfg.SS?.TLS ? ';tls' : '')};mux=0`) + ECHLINK参数}#${encodeURIComponent(cfg.优选订阅生成?.SUBNAME || 'edgetunnel')}`
		: `${cfg.协议类型}://${userID}@${host}:443?security=tls&type=${传输协议 + ECHLINK参数}&${域名字段名}=${host}&fp=${cfg.Fingerprint}&sni=${host}&${路径字段名}=${encodeURIComponent(传输路径参数值) + TLS分片参数}&encryption=none#${encodeURIComponent(cfg.优选订阅生成?.SUBNAME || 'edgetunnel')}`;
	if (cfg.优选订阅生成) cfg.优选订阅生成.TOKEN = await MD5MD5(hostname + userID);

	const 初始化TG_JSON = { BotToken: null, ChatID: null };
	cfg.TG = { 启用: cfg.TG?.启用 ?? false, ...初始化TG_JSON };
	try {
		const TG_TXT = await env.KV.get('tg.json');
		if (!TG_TXT) {
			await env.KV.put('tg.json', JSON.stringify(初始化TG_JSON, null, 2));
		} else {
			const TG_JSON = JSON.parse(TG_TXT) as { BotToken?: string; ChatID?: string };
			cfg.TG.ChatID = TG_JSON.ChatID || null;
			cfg.TG.BotToken = TG_JSON.BotToken ? 掩码敏感信息(TG_JSON.BotToken) : null;
		}
	} catch (error) {
		console.error(`读取tg.json出错: ${(error as { message?: string })?.message || error}`);
	}

	const 初始化CF_JSON = { Email: null, GlobalAPIKey: null, AccountID: null, APIToken: null, UsageAPI: null };
	cfg.CF = { ...初始化CF_JSON, Usage: { success: false, pages: 0, workers: 0, total: 0, max: 100000 } };
	try {
		const CF_TXT = await env.KV.get('cf.json');
		if (!CF_TXT) {
			await env.KV.put('cf.json', JSON.stringify(初始化CF_JSON, null, 2));
		} else {
			const CF_JSON = JSON.parse(CF_TXT) as { Email?: string; GlobalAPIKey?: string; AccountID?: string; APIToken?: string; UsageAPI?: string };
			if (CF_JSON.UsageAPI) {
				try {
					const response = await fetch(CF_JSON.UsageAPI);
					const Usage = (await response.json()) as CloudflareUsage;
					cfg.CF.Usage = Usage;
				} catch (err) {
					console.error(`请求 CF_JSON.UsageAPI 失败: ${(err as { message?: string })?.message || err}`);
				}
			} else {
				cfg.CF.Email = CF_JSON.Email ?? null;
				cfg.CF.GlobalAPIKey = CF_JSON.GlobalAPIKey ? 掩码敏感信息(CF_JSON.GlobalAPIKey) : null;
				cfg.CF.AccountID = CF_JSON.AccountID ? 掩码敏感信息(CF_JSON.AccountID) : null;
				cfg.CF.APIToken = CF_JSON.APIToken ? 掩码敏感信息(CF_JSON.APIToken) : null;
				cfg.CF.UsageAPI = null;
				const Usage = await getCloudflareUsage(CF_JSON.Email ?? null, CF_JSON.GlobalAPIKey ?? null, CF_JSON.AccountID ?? null, CF_JSON.APIToken ?? null);
				cfg.CF.Usage = Usage;
			}
		}
	} catch (error) {
		console.error(`读取cf.json出错: ${(error as { message?: string })?.message || error}`);
	}

	cfg.加载时间 = (performance.now() - 初始化开始时间).toFixed(2) + 'ms';
	state.config_JSON = cfg as ConfigJSON;
	return cfg;
}

const ASN运营商映射: Record<string, string> = {
	'4134': 'ct', '4809': 'ct', '4811': 'ct', '4812': 'ct', '4815': 'ct',
	'4837': 'cu', '4814': 'cu', '9929': 'cu', '17623': 'cu', '17816': 'cu',
	'9808': 'cmcc', '24400': 'cmcc', '56040': 'cmcc', '56041': 'cmcc', '56044': 'cmcc',
};

const 运营商关键词映射: ReadonlyArray<{ code: string; pattern: RegExp }> = [
	{ code: 'ct', pattern: /chinanet|chinatelecom|china telecom|cn2|shtel/ },
	{ code: 'cmcc', pattern: /cmi|cmnet|chinamobile|china mobile|cmcc|mobile communications/ },
	{ code: 'cu', pattern: /china169|china unicom|chinaunicom|cucc|cncgroup|cuii|netcom/ },
];

export function 识别运营商(request: Request): string {
	const cf = (request as Request & { cf?: { country?: string; asOrganization?: string; asn?: number | string } }).cf;
	if (String(cf?.country || '').toLowerCase() !== 'cn') return 'cf';
	const 组织名称 = String(cf?.asOrganization || '').toLowerCase();
	const 命中运营商 = 运营商关键词映射.find(({ pattern }) => pattern.test(组织名称))?.code;
	return 命中运营商 || ASN运营商映射[String(cf?.asn || '')] || 'cf';
}

export async function 生成随机IP(request: Request, count = 16, 指定端口 = -1): Promise<[string[], string]> {
	const url = new URL(request.url);
	const 查询参数运营商 = String(url.searchParams.get('asOrg') || '').toLowerCase();
	const 运营商文件标识 = ['ct', 'cu', 'cmcc', 'cf'].includes(查询参数运营商) ? 查询参数运营商 : 识别运营商(request);
	const 运营商名称映射: Record<string, string> = {
		cmcc: 'CF移动优选',
		cu: 'CF联通优选',
		ct: 'CF电信优选',
		cf: 'CF官方优选',
	};
	const cidr_url = 运营商文件标识 === 'cf'
		? 'https://raw.githubusercontent.com/cmliu/cmliu/main/CF-CIDR.txt'
		: `https://raw.githubusercontent.com/cmliu/cmliu/main/CF-CIDR/${运营商文件标识}.txt`;
	const cfname = 运营商名称映射[运营商文件标识] || 'CF官方优选';
	const cfport = [443, 2053, 2083, 2087, 2096, 8443];
	let cidrList: string[] = [];
	try {
		const res = await fetch(cidr_url);
		cidrList = res.ok ? await 整理成数组(await res.text()) : ['104.16.0.0/13'];
	} catch {
		cidrList = ['104.16.0.0/13'];
	}

	const generateRandomIPFromCIDR = (cidr: string): string => {
		const [baseIP, prefixLength] = cidr.split('/');
		const prefix = parseInt(prefixLength, 10);
		const hostBits = 32 - prefix;
		const ipInt = baseIP.split('.').reduce((a, p, i) => a | (parseInt(p, 10) << (24 - i * 8)), 0);
		const randomOffset = Math.floor(Math.random() * Math.pow(2, hostBits));
		const mask = (0xffffffff << hostBits) >>> 0;
		const randomIP = (((ipInt & mask) >>> 0) + randomOffset) >>> 0;
		return [(randomIP >>> 24) & 0xff, (randomIP >>> 16) & 0xff, (randomIP >>> 8) & 0xff, randomIP & 0xff].join('.');
	};
	const randomIPs = Array.from({ length: count }, (_, index) => {
		const ip = generateRandomIPFromCIDR(cidrList[Math.floor(Math.random() * cidrList.length)]);
		const 目标端口 = 指定端口 === -1 ? cfport[Math.floor(Math.random() * cfport.length)] : 指定端口;

		return `${ip}:${目标端口}#${cfname}${index + 1}`;
	});
	return [randomIPs, randomIPs.join('\n')];
}

export async function 请求日志记录(env: RuntimeEnv, request: Request, 访问IP: string, 请求类型 = 'Get_SUB', config_JSON: ConfigJSON, 是否写入KV日志 = true): Promise<void> {
	try {
		const cfg = config_JSON as FullConfig;
		const cf = (request as Request & { cf?: { asn?: number | string; asOrganization?: string; country?: string; city?: string } }).cf;
		const 当前时间 = new Date();
		const 日志内容 = {
			TYPE: 请求类型,
			IP: 访问IP,
			ASN: `AS${cf?.asn || '0'} ${cf?.asOrganization || 'Unknown'}`,
			CC: `${cf?.country || 'N/A'} ${cf?.city || 'N/A'}`,
			URL: request.url,
			UA: request.headers.get('User-Agent') || 'Unknown',
			TIME: 当前时间.getTime(),
		};
		if (cfg.TG?.启用) {
			try {
				const TG_TXT = await env.KV.get('tg.json');
				const TG_JSON = TG_TXT ? (JSON.parse(TG_TXT) as { BotToken?: string; ChatID?: string }) : null;
				if (TG_JSON?.BotToken && TG_JSON?.ChatID) {
					const 请求时间 = new Date(日志内容.TIME).toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai' });
					const 请求URL = new URL(日志内容.URL);
					const usage = cfg.CF?.Usage;
					const usageLine = usage?.success ? `📊 <b>请求用量：</b>${usage.total}/${usage.max} <b>${((usage.total / usage.max) * 100).toFixed(2)}%</b>\n` : '';
					const msg = `<b>#${cfg.优选订阅生成?.SUBNAME || ''} 日志通知</b>\n\n`
						+ `📌 <b>类型：</b>#${日志内容.TYPE}\n`
						+ `🌐 <b>IP：</b><code>${日志内容.IP}</code>\n`
						+ `📍 <b>位置：</b>${日志内容.CC}\n`
						+ `🏢 <b>ASN：</b>${日志内容.ASN}\n`
						+ `🔗 <b>域名：</b><code>${请求URL.host}</code>\n`
						+ `🔍 <b>路径：</b><code>${请求URL.pathname + 请求URL.search}</code>\n`
						+ `🤖 <b>UA：</b><code>${日志内容.UA}</code>\n`
						+ `📅 <b>时间：</b>${请求时间}\n`
						+ usageLine;
					await fetch(`https://api.telegram.org/bot${TG_JSON.BotToken}/sendMessage?chat_id=${TG_JSON.ChatID}&parse_mode=HTML&text=${encodeURIComponent(msg)}`, {
						method: 'GET',
						headers: {
							Accept: 'text/html,application/xhtml+xml,application/xml;',
							'Accept-Encoding': 'gzip, deflate, br',
							'User-Agent': 日志内容.UA || 'Unknown',
						},
					});
				}
			} catch (error) {
				console.error(`读取tg.json出错: ${(error as { message?: string })?.message || error}`);
			}
		}
		const 关闭日志 = ['1', 'true'].includes(env.OFF_LOG ?? '');
		if (关闭日志) 是否写入KV日志 = false;
		if (!是否写入KV日志) return;
		let 日志数组: typeof 日志内容[] = [];
		const 现有日志 = await env.KV.get('log.json');
		const KV容量限制 = 4; // MB
		if (现有日志) {
			try {
				const parsed = JSON.parse(现有日志) as unknown;
				if (!Array.isArray(parsed)) {
					日志数组 = [日志内容];
				} else {
					日志数组 = parsed as typeof 日志内容[];
					if (请求类型 !== 'Get_SUB') {
						const 三十分钟前 = 当前时间.getTime() - 30 * 60 * 1000;
						if (日志数组.some((logEntry) =>
							logEntry.TYPE !== 'Get_SUB'
							&& logEntry.IP === 访问IP
							&& logEntry.URL === request.url
							&& logEntry.UA === (request.headers.get('User-Agent') || 'Unknown')
							&& logEntry.TIME >= 三十分钟前
						)) return;
						日志数组.push(日志内容);
					} else {
						日志数组.push(日志内容);
					}
					while (JSON.stringify(日志数组, null, 2).length > KV容量限制 * 1024 * 1024 && 日志数组.length > 0) 日志数组.shift();
				}
			} catch {
				日志数组 = [日志内容];
			}
		} else {
			日志数组 = [日志内容];
		}
		await env.KV.put('log.json', JSON.stringify(日志数组, null, 2));
	} catch (error) {
		console.error(`日志记录失败: ${(error as { message?: string })?.message || error}`);
	}
}
