// 主请求路由：移植自 _worker.js 的 export default { fetch }。
// 行为完全保留，env.KV 由 DO 注入的 SQL 适配器提供。

import { state, log, Version, Pages静态页面 } from './state';
import { TOKENS } from './tokens';
import { 整理成数组, MD5MD5, 替换星号为随机字符, 数据转Uint8Array, 拼接字节数据, base64SecretEncode, isIPHostname } from './utils';
import { 反代参数获取 } from './proxy-params';
import { 处理WS请求 } from './transport-ws';
import type { WSHandoff } from './transport-ws';
import { 处理XHTTP请求 } from './transport-xhttp';
import { 处理gRPC请求 } from './transport-grpc';
import { 读取config_JSON, 请求日志记录, 识别运营商, 生成随机IP, getCloudflareUsage } from './config-store';
import { 请求优选API, 获取优选订阅生成器数据 } from './best-ip';
import { Clash订阅配置文件热补丁, Singbox订阅配置文件热补丁, Surge订阅配置文件热补丁 } from './subscription';
import { 获取传输协议配置, 获取传输路径参数值 } from './sub-helpers';
import { 获取SOCKS5账号, 获取代理默认端口 } from './resolver';
import { socks5Connect, httpConnect, httpsConnect } from './proxy-connect';
import { turnConnect } from './turn';
import { sstpConnect } from './sstp';
import { TlsClient } from './tls-client';
import { 创建请求TCP连接器 } from './forward';
import { nginx, html1101 } from './disguise';
import { 随机路径 } from './utils';
import type { RuntimeEnv, ParsedProxyAddress } from './types';
import type { ConfigJSON } from './state';

interface CFCtx {
	asn?: number | string;
	colo?: string;
	country?: string;
	asOrganization?: string;
	city?: string;
}
function getCf(request: Request): CFCtx {
	return ((request as Request & { cf?: CFCtx }).cf) ?? {};
}

interface ConfigShape extends ConfigJSON {
	UUID?: string;
	HOST?: string;
	HOSTS?: string[];
	协议类型?: string;
	传输协议?: string;
	完整节点路径?: string;
	跳过证书验证?: boolean;
	启用0RTT?: boolean;
	TLS分片?: string | null;
	随机路径?: boolean;
	ECH?: boolean;
	ECHConfig?: { DNS?: string; SNI?: string };
	SS?: { 加密方式?: string; TLS?: boolean };
	Fingerprint?: string;
	优选订阅生成?: { local?: boolean; SUB?: string | null; SUBNAME?: string; SUBUpdateTime?: number; 本地IP库?: { 随机IP?: boolean; 随机数量?: number; 指定端口?: number } };
	订阅转换配置?: { SUBAPI?: string; SUBCONFIG?: string; SUBEMOJI?: boolean };
	CF?: { Usage?: { success?: boolean; pages?: number; workers?: number; max?: number; total?: number } };
	PATH?: string;
	init?: string;
	gRPCUserAgent?: string;
	加载时间?: string;
	gRPC模式?: string;
}

const uuidRegex = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$/;

export async function 处理请求(request: Request, env: RuntimeEnv, ctx: ExecutionContext): Promise<Response | WSHandoff> {
	let 请求URL文本 = request.url.replace(/%5[Cc]/g, '').replace(/\\/g, '');
	const 请求URL锚点索引 = 请求URL文本.indexOf('#');
	const 请求URL主体部分 = 请求URL锚点索引 === -1 ? 请求URL文本 : 请求URL文本.slice(0, 请求URL锚点索引);
	if (!请求URL主体部分.includes('?') && /%3f/i.test(请求URL主体部分)) {
		const 请求URL锚点部分 = 请求URL锚点索引 === -1 ? '' : 请求URL文本.slice(请求URL锚点索引);
		请求URL文本 = 请求URL主体部分.replace(/%3f/i, '?') + 请求URL锚点部分;
	}
	const url = new URL(请求URL文本);
	const UA = request.headers.get('User-Agent') || 'null';
	const upgradeHeader = (request.headers.get('Upgrade') || '').toLowerCase();
	const contentType = (request.headers.get('content-type') || '').toLowerCase();
	const 管理员密码 = env.ADMIN || env.admin || env.PASSWORD || env.password || env.pswd || env.TOKEN || env.KEY || env.UUID || env.uuid;
	const 加密秘钥 = env.KEY || '勿动此默认密钥，有需求请自行通过添加变量KEY进行修改';
	const userIDMD5 = await MD5MD5((管理员密码 || '') + 加密秘钥);
	const envUUID = env.UUID || env.uuid;
	const userID = envUUID && uuidRegex.test(envUUID)
		? envUUID.toLowerCase()
		: [userIDMD5.slice(0, 8), userIDMD5.slice(8, 12), '4' + userIDMD5.slice(13, 16), '8' + userIDMD5.slice(17, 20), userIDMD5.slice(20)].join('-');
	const hosts = env.HOST
		? (await 整理成数组(env.HOST)).map((h) => h.toLowerCase().replace(/^https?:\/\//, '').split('/')[0].split(':')[0])
		: [url.hostname];
	const host = hosts[0];
	const 访问路径 = url.pathname.slice(1).toLowerCase();
	state.调试日志打印 = ['1', 'true'].includes(env.DEBUG ?? '') || state.调试日志打印;
	state.预加载竞速拨号 = ['1', 'true'].includes(env.PRELOAD_RACE_DIAL ?? '') || state.预加载竞速拨号;
	if (state.TCP并发拨号数 !== 1 && 识别运营商(request) === 'cmcc') state.TCP并发拨号数 = 1;
	const cf = getCf(request);
	if (env.PROXYIP) {
		const proxyIPs = await 整理成数组(env.PROXYIP);
		state.反代IP = proxyIPs[Math.floor(Math.random() * proxyIPs.length)];
		state.启用反代兜底 = false;
	} else {
		state.反代IP = (`${cf.colo || ''}.PrOxYIp.CmLiUsSsS.nEt`).toLowerCase();
	}
	const 访问IP = request.headers.get('CF-Connecting-IP')
		|| request.headers.get('True-Client-IP')
		|| request.headers.get('X-Real-IP')
		|| request.headers.get('X-Forwarded-For')
		|| request.headers.get('Fly-Client-IP')
		|| request.headers.get('X-Appengine-Remote-Addr')
		|| request.headers.get('X-Cluster-Client-IP')
		|| '未知IP';
	if (state.缓存SOCKS5白名单 === null) {
		if (env.GO2SOCKS5) state.SOCKS5白名单 = [...new Set(state.SOCKS5白名单.concat(await 整理成数组(env.GO2SOCKS5)))];
		state.缓存SOCKS5白名单 = state.SOCKS5白名单;
	} else {
		state.SOCKS5白名单 = state.缓存SOCKS5白名单;
	}

	if (访问路径 === 'version' && url.searchParams.get('uuid') === userID) {
		return new Response(JSON.stringify({ Version: Number(String(Version).replace(/\D+/g, '')) }), {
			status: 200,
			headers: { 'Content-Type': 'application/json;charset=utf-8' },
		});
	}

	if (管理员密码 && upgradeHeader === 'websocket') {
		await 反代参数获取(url, userID);
		log(`[WebSocket] 命中请求: ${url.pathname}${url.search}`);
		return await 处理WS请求(request, userID, url);
	}

	if (管理员密码 && !访问路径.startsWith('admin/') && 访问路径 !== 'login' && request.method === 'POST') {
		await 反代参数获取(url, userID);
		const referer = request.headers.get('Referer') || '';
		const 命中XHTTP特征 = referer.includes('x_padding', 14) || referer.includes('x_padding=');
		if (!命中XHTTP特征 && contentType.startsWith('application/grpc')) {
			log(`[gRPC] 命中请求: ${url.pathname}${url.search}`);
			return await 处理gRPC请求(request, userID);
		}
		log(`[XHTTP] 命中请求: ${url.pathname}${url.search}`);
		return await 处理XHTTP请求(request, userID);
	}

	if (url.protocol === 'http:') {
		return Response.redirect(url.href.replace(`http://${url.hostname}`, `https://${url.hostname}`), 301);
	}

	if (!管理员密码) {
		return fetch(Pages静态页面 + '/noADMIN').then((r) => {
			const headers = new Headers(r.headers);
			headers.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
			headers.set('Pragma', 'no-cache');
			headers.set('Expires', '0');
			return new Response(r.body, { status: 404, statusText: r.statusText, headers });
		});
	}

	const 区分大小写访问路径 = url.pathname.slice(1);

	if (区分大小写访问路径 === 加密秘钥 && 加密秘钥 !== '勿动此默认密钥，有需求请自行通过添加变量KEY进行修改') {
		const params = new URLSearchParams(url.search);
		params.set('token', await MD5MD5(host + userID));
		return new Response('重定向中...', { status: 302, headers: { Location: `/sub?${params.toString()}` } });
	}

	if (访问路径 === 'login') {
		const cookies = request.headers.get('Cookie') || '';
		const authCookie = cookies.split(';').find((c) => c.trim().startsWith('auth='))?.split('=')[1];
		if (authCookie === (await MD5MD5(UA + 加密秘钥 + 管理员密码))) {
			return new Response('重定向中...', { status: 302, headers: { Location: '/admin' } });
		}
		if (request.method === 'POST') {
			const formData = await request.text();
			const params = new URLSearchParams(formData);
			const 输入密码 = params.get('password');
			const expected = typeof 管理员密码 === 'string' ? 管理员密码.replace(/[\r\n]/g, '') : 管理员密码;
			if (输入密码 === expected) {
				const 响应 = new Response(JSON.stringify({ success: true }), { status: 200, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
				响应.headers.set('Set-Cookie', `auth=${await MD5MD5(UA + 加密秘钥 + 管理员密码)}; Path=/; Max-Age=86400; HttpOnly; Secure; SameSite=Strict`);
				return 响应;
			}
		}
		return fetch(Pages静态页面 + '/login');
	}

	if (访问路径 === 'admin' || 访问路径.startsWith('admin/')) {
		const cookies = request.headers.get('Cookie') || '';
		const authCookie = cookies.split(';').find((c) => c.trim().startsWith('auth='))?.split('=')[1];
		if (!authCookie || authCookie !== (await MD5MD5(UA + 加密秘钥 + 管理员密码))) {
			return new Response('重定向中...', { status: 302, headers: { Location: '/login' } });
		}
		const 管理结果 = await 处理管理路径(request, env, ctx, url, host, 访问路径, 区分大小写访问路径, userID, UA, 访问IP);
		if (管理结果) return 管理结果;
	}

	if (访问路径 === 'logout' || uuidRegex.test(访问路径)) {
		const 响应 = new Response('重定向中...', { status: 302, headers: { Location: '/login' } });
		响应.headers.set('Set-Cookie', 'auth=; Path=/; Max-Age=0; HttpOnly');
		return 响应;
	}

	if (访问路径 === 'sub') {
		return await 处理订阅请求(request, env, ctx, url, host, userID, UA, 访问IP);
	}

	if (访问路径 === 'locations') {
		const cookies = request.headers.get('Cookie') || '';
		const authCookie = cookies.split(';').find((c) => c.trim().startsWith('auth='))?.split('=')[1];
		if (authCookie && authCookie === (await MD5MD5(UA + 加密秘钥 + 管理员密码))) {
			return fetch(new Request('https://speed.cloudflare.com/locations', { headers: { Referer: 'https://speed.cloudflare.com/' } }));
		}
	}

	if (访问路径 === 'robots.txt') {
		return new Response('User-agent: *\nDisallow: /', { status: 200, headers: { 'Content-Type': 'text/plain; charset=UTF-8' } });
	}

	let 伪装页URL = env.URL || 'nginx';
	if (伪装页URL && 伪装页URL !== 'nginx' && 伪装页URL !== '1101') {
		伪装页URL = 伪装页URL.trim().replace(/\/$/, '');
		if (!伪装页URL.match(/^https?:\/\//i)) 伪装页URL = 'https://' + 伪装页URL;
		if (伪装页URL.toLowerCase().startsWith('http://')) 伪装页URL = 'https://' + 伪装页URL.substring(7);
		try {
			const u = new URL(伪装页URL);
			伪装页URL = u.protocol + '//' + u.host;
		} catch {
			伪装页URL = 'nginx';
		}
	}
	if (伪装页URL === '1101') {
		return new Response(await html1101(url.host, 访问IP), { status: 200, headers: { 'Content-Type': 'text/html; charset=UTF-8' } });
	}
	try {
		const 反代URL = new URL(伪装页URL);
		const 新请求头 = new Headers(request.headers);
		新请求头.set('Host', 反代URL.host);
		新请求头.set('Referer', 反代URL.origin);
		新请求头.set('Origin', 反代URL.origin);
		if (!新请求头.has('User-Agent') && UA && UA !== 'null') 新请求头.set('User-Agent', UA);
		const 反代响应 = await fetch(反代URL.origin + url.pathname + url.search, { method: request.method, headers: 新请求头, body: request.body, cf: cf as RequestInitCfProperties });
		const 内容类型 = 反代响应.headers.get('content-type') || '';
		if (/text|javascript|json|xml/.test(内容类型)) {
			const 响应内容 = (await 反代响应.text()).replaceAll(反代URL.host, url.host);
			return new Response(响应内容, { status: 反代响应.status, headers: { ...Object.fromEntries(反代响应.headers), 'Cache-Control': 'no-store' } });
		}
		return 反代响应;
	} catch { /* fall back to nginx */ }
	return new Response(await nginx(), { status: 200, headers: { 'Content-Type': 'text/html; charset=UTF-8' } });
}

async function 处理管理路径(request: Request, env: RuntimeEnv, ctx: ExecutionContext, url: URL, host: string, 访问路径: string, 区分大小写访问路径: string, userID: string, UA: string, 访问IP: string): Promise<Response | null> {
	if (访问路径 === 'admin/log.json') {
		const 读取日志内容 = (await env.KV.get('log.json')) || '[]';
		return new Response(读取日志内容, { status: 200, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
	}

	if (区分大小写访问路径 === 'admin/getCloudflareUsage') {
		try {
			const Usage_JSON = await getCloudflareUsage(url.searchParams.get('Email'), url.searchParams.get('GlobalAPIKey'), url.searchParams.get('AccountID'), url.searchParams.get('APIToken'));
			return new Response(JSON.stringify(Usage_JSON, null, 2), { status: 200, headers: { 'Content-Type': 'application/json' } });
		} catch (err) {
			const message = (err as { message?: string })?.message || String(err);
			return new Response(JSON.stringify({ msg: '查询请求量失败，失败原因：' + message, error: message }, null, 2), { status: 500, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
		}
	}

	if (区分大小写访问路径 === 'admin/getADDAPI') {
		const urlParam = url.searchParams.get('url');
		if (urlParam) {
			try {
				new URL(urlParam);
				const 请求优选API内容 = await 请求优选API([urlParam], url.searchParams.get('port') || '443');
				let 优选API的IP = 请求优选API内容[0].length > 0 ? 请求优选API内容[0] : 请求优选API内容[1];
				优选API的IP = 优选API的IP.map((item) => item.replace(/#(.+)$/, (_match, remark) => '#' + decodeURIComponent(remark)));
				return new Response(JSON.stringify({ success: true, data: 优选API的IP }, null, 2), { status: 200, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
			} catch (err) {
				const message = (err as { message?: string })?.message || String(err);
				return new Response(JSON.stringify({ msg: '验证优选API失败，失败原因：' + message, error: message }, null, 2), { status: 500, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
			}
		}
		return new Response(JSON.stringify({ success: false, data: [] }, null, 2), { status: 403, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
	}

	if (访问路径 === 'admin/check') {
		return await 处理代理检查(request);
	}

	state.config_JSON = (await 读取config_JSON(env, host, userID, UA)) as ConfigJSON;
	const cfg = state.config_JSON as ConfigShape;

	if (访问路径 === 'admin/init') {
		try {
			state.config_JSON = (await 读取config_JSON(env, host, userID, UA, true)) as ConfigJSON;
			ctx.waitUntil(请求日志记录(env, request, 访问IP, 'Init_Config', state.config_JSON));
			(state.config_JSON as ConfigShape).init = '配置已重置为默认值';
			return new Response(JSON.stringify(state.config_JSON, null, 2), { status: 200, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
		} catch (err) {
			const message = (err as { message?: string })?.message || String(err);
			return new Response(JSON.stringify({ msg: '配置重置失败，失败原因：' + message, error: message }, null, 2), { status: 500, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
		}
	}

	if (request.method === 'POST') {
		const POST响应 = await 处理ADMIN_POST(request, env, ctx, url, 访问路径, 区分大小写访问路径, 访问IP, cfg);
		if (POST响应) return POST响应;
	}

	if (访问路径 === 'admin/config.json') {
		return new Response(JSON.stringify(cfg, null, 2), { status: 200, headers: { 'Content-Type': 'application/json' } });
	}

	if (区分大小写访问路径 === 'admin/ADD.txt') {
		let 本地优选IP = (await env.KV.get('ADD.txt')) || 'null';
		if (本地优选IP === 'null') {
			const local = await 生成随机IP(request, cfg.优选订阅生成?.本地IP库?.随机数量 ?? 16, cfg.优选订阅生成?.本地IP库?.指定端口 ?? -1);
			本地优选IP = local[1];
		}
		return new Response(本地优选IP, { status: 200, headers: { 'Content-Type': 'text/plain;charset=utf-8', asn: String(getCf(request).asn ?? '') } });
	}

	if (访问路径 === 'admin/cf.json') {
		return new Response(JSON.stringify(getCf(request), null, 2), { status: 200, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
	}

	ctx.waitUntil(请求日志记录(env, request, 访问IP, 'Admin_Login', cfg));
	return fetch(Pages静态页面 + '/admin' + url.search);
}

async function 处理ADMIN_POST(request: Request, env: RuntimeEnv, ctx: ExecutionContext, url: URL, 访问路径: string, 区分大小写访问路径: string, 访问IP: string, cfg: ConfigShape): Promise<Response | null> {
	if (访问路径 === 'admin/config.json') {
		try {
			const newConfig = (await request.json()) as { UUID?: string; HOST?: string };
			if (!newConfig.UUID || !newConfig.HOST) {
				return new Response(JSON.stringify({ error: '配置不完整' }), { status: 400, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
			}
			await env.KV.put('config.json', JSON.stringify(newConfig, null, 2));
			ctx.waitUntil(请求日志记录(env, request, 访问IP, 'Save_Config', cfg));
			return new Response(JSON.stringify({ success: true, message: '配置已保存' }), { status: 200, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
		} catch (error) {
			const message = (error as { message?: string })?.message || String(error);
			console.error('保存配置失败:', error);
			return new Response(JSON.stringify({ error: '保存配置失败: ' + message }), { status: 500, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
		}
	}

	if (访问路径 === 'admin/cf.json') {
		try {
			const newConfig = (await request.json()) as { init?: boolean; Email?: string; GlobalAPIKey?: string; AccountID?: string; APIToken?: string; UsageAPI?: string };
			const CF_JSON: { Email: string | null; GlobalAPIKey: string | null; AccountID: string | null; APIToken: string | null; UsageAPI: string | null } = {
				Email: null, GlobalAPIKey: null, AccountID: null, APIToken: null, UsageAPI: null,
			};
			if (!newConfig.init || newConfig.init !== true) {
				if (newConfig.Email && newConfig.GlobalAPIKey) {
					CF_JSON.Email = newConfig.Email;
					CF_JSON.GlobalAPIKey = newConfig.GlobalAPIKey;
				} else if (newConfig.AccountID && newConfig.APIToken) {
					CF_JSON.AccountID = newConfig.AccountID;
					CF_JSON.APIToken = newConfig.APIToken;
				} else if (newConfig.UsageAPI) {
					CF_JSON.UsageAPI = newConfig.UsageAPI;
				} else {
					return new Response(JSON.stringify({ error: '配置不完整' }), { status: 400, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
				}
			}
			await env.KV.put('cf.json', JSON.stringify(CF_JSON, null, 2));
			ctx.waitUntil(请求日志记录(env, request, 访问IP, 'Save_Config', cfg));
			return new Response(JSON.stringify({ success: true, message: '配置已保存' }), { status: 200, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
		} catch (error) {
			const message = (error as { message?: string })?.message || String(error);
			console.error('保存配置失败:', error);
			return new Response(JSON.stringify({ error: '保存配置失败: ' + message }), { status: 500, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
		}
	}

	if (访问路径 === 'admin/tg.json') {
		try {
			const newConfig = (await request.json()) as { init?: boolean; BotToken?: string; ChatID?: string };
			if (newConfig.init === true) {
				await env.KV.put('tg.json', JSON.stringify({ BotToken: null, ChatID: null }, null, 2));
			} else {
				if (!newConfig.BotToken || !newConfig.ChatID) {
					return new Response(JSON.stringify({ error: '配置不完整' }), { status: 400, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
				}
				await env.KV.put('tg.json', JSON.stringify(newConfig, null, 2));
			}
			ctx.waitUntil(请求日志记录(env, request, 访问IP, 'Save_Config', cfg));
			return new Response(JSON.stringify({ success: true, message: '配置已保存' }), { status: 200, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
		} catch (error) {
			const message = (error as { message?: string })?.message || String(error);
			console.error('保存配置失败:', error);
			return new Response(JSON.stringify({ error: '保存配置失败: ' + message }), { status: 500, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
		}
	}

	if (区分大小写访问路径 === 'admin/ADD.txt') {
		try {
			const customIPs = await request.text();
			await env.KV.put('ADD.txt', customIPs);
			ctx.waitUntil(请求日志记录(env, request, 访问IP, 'Save_Custom_IPs', cfg));
			return new Response(JSON.stringify({ success: true, message: '自定义IP已保存' }), { status: 200, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
		} catch (error) {
			const message = (error as { message?: string })?.message || String(error);
			console.error('保存自定义IP失败:', error);
			return new Response(JSON.stringify({ error: '保存自定义IP失败: ' + message }), { status: 500, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
		}
	}

	void url;
	return new Response(JSON.stringify({ error: '不支持的POST请求路径' }), { status: 404, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
}

async function 处理代理检查(request: Request): Promise<Response> {
	const url = new URL(request.url);
	const 代理协议 = (['socks5', 'http', 'https', 'turn', 'sstp'] as const).find((类型) => url.searchParams.has(类型)) || null;
	if (!代理协议) return new Response(JSON.stringify({ error: '缺少代理参数' }), { status: 400, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
	const 代理参数 = url.searchParams.get(代理协议)!;
	const startTime = Date.now();
	let 检测代理响应: { success: boolean; proxy?: string; ip?: string; loc?: string; responseTime: number; error?: string } = { success: false, responseTime: 0 };
	try {
		const proxy = 获取SOCKS5账号(代理参数, 获取代理默认端口(代理协议));
		state.parsedSocks5Address = proxy as ParsedProxyAddress;
		const { username, password, hostname, port } = proxy;
		const 完整代理参数 = username && password ? `${username}:${password}@${hostname}:${port}` : `${hostname}:${port}`;
		try {
			const 检测主机 = 'cloudflare.com';
			const 检测端口 = 443;
			const encoder = new TextEncoder();
			const decoder = new TextDecoder();
			const TCP连接 = 创建请求TCP连接器(request);
			let tcpSocket: Awaited<ReturnType<typeof socks5Connect>> | null = null;
			let tlsSocket: TlsClient | null = null;
			try {
				tcpSocket = 代理协议 === 'socks5'
					? await socks5Connect(检测主机, 检测端口, new Uint8Array(0), TCP连接)
					: 代理协议 === 'turn'
						? await turnConnect(proxy, 检测主机, 检测端口, TCP连接)
						: 代理协议 === 'sstp'
							? await sstpConnect(proxy, 检测主机, 检测端口, TCP连接)
							: 代理协议 === 'https' && isIPHostname(hostname)
								? await httpsConnect(检测主机, 检测端口, new Uint8Array(0), TCP连接)
								: await httpConnect(检测主机, 检测端口, new Uint8Array(0), 代理协议 === 'https', TCP连接);
				if (!tcpSocket) throw new Error('无法连接到代理服务器');
				tlsSocket = new TlsClient(tcpSocket, { serverName: 检测主机, insecure: true });
				await tlsSocket.handshake();
				await tlsSocket.write(encoder.encode(`GET /cdn-cgi/trace HTTP/1.1\r\nHost: ${检测主机}\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n`));
				let responseBuffer = new Uint8Array(0);
				let headerEndIndex = -1;
				let contentLength: number | null = null;
				let chunked = false;
				const 最大响应字节 = 64 * 1024;
				while (responseBuffer.length < 最大响应字节) {
					const value = await tlsSocket.read();
					if (!value) break;
					if (value.byteLength === 0) continue;
					responseBuffer = 拼接字节数据(responseBuffer, value);
					if (headerEndIndex === -1) {
						const crlfcrlf = responseBuffer.findIndex((_, i) => i < responseBuffer.length - 3 && responseBuffer[i] === 0x0d && responseBuffer[i + 1] === 0x0a && responseBuffer[i + 2] === 0x0d && responseBuffer[i + 3] === 0x0a);
						if (crlfcrlf !== -1) {
							headerEndIndex = crlfcrlf + 4;
							const headers = decoder.decode(responseBuffer.slice(0, headerEndIndex));
							const statusLine = headers.split('\r\n')[0] || '';
							const statusMatch = statusLine.match(/HTTP\/\d\.\d\s+(\d+)/);
							const statusCode = statusMatch ? parseInt(statusMatch[1], 10) : NaN;
							if (!Number.isFinite(statusCode) || statusCode < 200 || statusCode >= 300) throw new Error(`代理检测请求失败: ${statusLine || '无效响应'}`);
							const lengthMatch = headers.match(/\r\nContent-Length:\s*(\d+)/i);
							if (lengthMatch) contentLength = parseInt(lengthMatch[1], 10);
							chunked = /\r\nTransfer-Encoding:\s*chunked/i.test(headers);
						}
					}
					if (headerEndIndex !== -1 && contentLength !== null && responseBuffer.length >= headerEndIndex + contentLength) break;
					if (headerEndIndex !== -1 && chunked && decoder.decode(responseBuffer).includes('\r\n0\r\n\r\n')) break;
				}
				if (headerEndIndex === -1) throw new Error('代理检测响应头过长或无效');
				const response = decoder.decode(responseBuffer);
				const ip = response.match(/(?:^|\n)ip=(.*)/)?.[1];
				const loc = response.match(/(?:^|\n)loc=(.*)/)?.[1];
				if (!ip || !loc) throw new Error('代理检测响应无效');
				检测代理响应 = { success: true, proxy: 代理协议 + '://' + 完整代理参数, ip, loc, responseTime: Date.now() - startTime };
			} finally {
				try {
					if (tlsSocket) tlsSocket.close();
					else await tcpSocket?.close();
				} catch { /* ignore */ }
			}
		} catch (error) {
			const message = (error as { message?: string })?.message || String(error);
			检测代理响应 = { success: false, error: message, proxy: 代理协议 + '://' + 完整代理参数, responseTime: Date.now() - startTime };
		}
	} catch (err) {
		const message = (err as { message?: string })?.message || String(err);
		检测代理响应 = { success: false, error: message, proxy: 代理协议 + '://' + 代理参数, responseTime: Date.now() - startTime };
	}
	return new Response(JSON.stringify(检测代理响应, null, 2), { status: 200, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
}

async function 处理订阅请求(request: Request, env: RuntimeEnv, ctx: ExecutionContext, url: URL, host: string, userID: string, UA: string, 访问IP: string): Promise<Response> {
	const 订阅TOKEN = await MD5MD5(host + userID);
	const 作为优选订阅生成器 = ['1', 'true'].includes(env.BEST_SUB ?? '')
		&& url.searchParams.get('host') === 'example.com'
		&& url.searchParams.get('uuid') === '00000000-0000-4000-8000-000000000000'
		&& UA.toLowerCase().includes('tunnel (https://github.com/' + 'cmliu/edge');
	const 请求TOKEN = url.searchParams.get('token');
	const 用户客户端请求订阅 = 请求TOKEN === 订阅TOKEN;
	const 当前日序号 = Math.floor(Date.now() / 86400000);
	const 订阅转换后端TOKEN种子 = base64SecretEncode(订阅TOKEN, userID);
	const [今日订阅转换后端专属TOKEN, 昨日订阅转换后端专属TOKEN] = await Promise.all([
		MD5MD5(订阅转换后端TOKEN种子 + 当前日序号),
		MD5MD5(订阅转换后端TOKEN种子 + (当前日序号 - 1)),
	]);
	const 订阅转换后端请求订阅 = 请求TOKEN === 今日订阅转换后端专属TOKEN || 请求TOKEN === 昨日订阅转换后端专属TOKEN;
	if (!用户客户端请求订阅 && !订阅转换后端请求订阅 && !作为优选订阅生成器) {
		return new Response(await nginx(), { status: 200, headers: { 'Content-Type': 'text/html; charset=UTF-8' } });
	}

	const cfg = (await 读取config_JSON(env, host, userID, UA)) as ConfigShape;
	state.config_JSON = cfg as ConfigJSON;
	if (作为优选订阅生成器) ctx.waitUntil(请求日志记录(env, request, 访问IP, 'Get_Best_SUB', cfg, false));
	else ctx.waitUntil(请求日志记录(env, request, 访问IP, 'Get_SUB', cfg));
	const ua = UA.toLowerCase();
	const responseHeaders: Record<string, string> = {
		'content-type': 'text/plain; charset=utf-8',
		'Profile-Update-Interval': String(cfg.优选订阅生成?.SUBUpdateTime ?? 3),
		'Profile-web-page-url': url.protocol + '//' + url.host + '/admin',
		'Cache-Control': 'no-store',
	};
	if (cfg.CF?.Usage?.success) {
		const pagesSum = cfg.CF.Usage.pages ?? 0;
		const workersSum = cfg.CF.Usage.workers ?? 0;
		const total = Number.isFinite(cfg.CF.Usage.max) ? ((cfg.CF.Usage.max ?? 100000) / 1000) * 1024 : 1024 * 100;
		responseHeaders['Subscription-Userinfo'] = `upload=${pagesSum}; download=${workersSum}; total=${total}; expire=4102329600`;
	}
	const isSubConverterRequest = url.searchParams.has('b64')
		|| url.searchParams.has('base64')
		|| Boolean(request.headers.get('subconverter-request'))
		|| Boolean(request.headers.get('subconverter-version'))
		|| ua.includes('subconverter')
		|| ua.includes(('CF-Workers-SUB').toLowerCase())
		|| 作为优选订阅生成器;
	const 订阅类型 = isSubConverterRequest
		? 'mixed'
		: url.searchParams.has('target')
			? url.searchParams.get('target')!
			: url.searchParams.has('clash') || ua.includes('clash') || ua.includes('meta') || ua.includes('mihomo')
				? 'clash'
				: url.searchParams.has('sb') || url.searchParams.has('singbox') || ua.includes('singbox') || ua.includes('sing-box')
					? 'singbox'
					: url.searchParams.has('surge') || ua.includes('surge')
						? 'surge&ver=4'
						: url.searchParams.has('quanx') || ua.includes('quantumult')
							? 'quanx'
							: url.searchParams.has('loon') || ua.includes('loon')
								? 'loon'
								: 'mixed';

	if (!ua.includes('mozilla')) {
		responseHeaders['Content-Disposition'] = `attachment; filename*=utf-8''${encodeURIComponent(cfg.优选订阅生成?.SUBNAME || '')}`;
	}
	const 协议类型 = (url.searchParams.has('surge') || ua.includes('surge')) && cfg.协议类型 !== 'ss' ? 'trojan' : (cfg.协议类型 || 'vless');
	let 订阅内容 = '';
	if (订阅类型 === 'mixed') {
		订阅内容 = await 生成混合订阅(request, env, url, host, userID, ua, cfg, 协议类型, isSubConverterRequest, 作为优选订阅生成器);
	} else {
		const 订阅转换URL = `${cfg.订阅转换配置?.SUBAPI}/sub?target=${订阅类型}&url=${encodeURIComponent(url.protocol + '//' + url.host + '/sub?target=mixed&token=' + 今日订阅转换后端专属TOKEN + '&asOrg=' + 识别运营商(request) + (url.searchParams.has('sub') && url.searchParams.get('sub') !== '' ? `&sub=${url.searchParams.get('sub')}` : ''))}&config=${encodeURIComponent(cfg.订阅转换配置?.SUBCONFIG || '')}&emoji=${cfg.订阅转换配置?.SUBEMOJI}&scv=${cfg.跳过证书验证}`;
		try {
			const response = await fetch(订阅转换URL, { headers: { 'User-Agent': 'Subconverter for ${订阅类型} ' + 'edgetunnel' + ' (https://github.com/cmliu/' + 'edgetunnel' + ')' } });
			if (response.ok) {
				订阅内容 = await response.text();
				if (url.searchParams.has('surge') || ua.includes('surge')) {
					订阅内容 = Surge订阅配置文件热补丁(订阅内容, url.protocol + '//' + url.host + '/sub?token=' + 订阅TOKEN + '&surge', cfg as ConfigJSON);
				}
			} else {
				return new Response('订阅转换后端异常：' + response.statusText, { status: response.status });
			}
		} catch (error) {
			return new Response('订阅转换后端异常：' + ((error as { message?: string })?.message || error), { status: 403 });
		}
	}

	if (!ua.includes('subconverter') && 用户客户端请求订阅) {
		const 打乱后HOSTS = [...(cfg.HOSTS || [])].sort(() => Math.random() - 0.5);
		let 替换域名计数 = 0;
		let 当前随机HOST: string | null = null;
		订阅内容 = 订阅内容
			.replace(/00000000-0000-4000-8000-000000000000/g, cfg.UUID || '')
			.replace(/MDAwMDAwMDAtMDAwMC00MDAwLTgwMDAtMDAwMDAwMDAwMDAw/g, btoa(cfg.UUID || ''))
			.replace(/example\.com/g, () => {
				if (替换域名计数 % 2 === 0) {
					const 原始host = 打乱后HOSTS[Math.floor(替换域名计数 / 2) % 打乱后HOSTS.length];
					当前随机HOST = 替换星号为随机字符(原始host);
				}
				替换域名计数++;
				return 当前随机HOST || '';
			});
	}

	if (订阅类型 === 'mixed' && (!ua.includes('mozilla') || url.searchParams.has('b64') || url.searchParams.has('base64'))) {
		订阅内容 = btoa(订阅内容);
	}

	if (订阅类型 === 'singbox') {
		订阅内容 = await Singbox订阅配置文件热补丁(订阅内容, cfg as ConfigJSON);
		responseHeaders['content-type'] = 'application/json; charset=utf-8';
	} else if (订阅类型 === 'clash') {
		订阅内容 = Clash订阅配置文件热补丁(订阅内容, cfg as ConfigJSON);
		responseHeaders['content-type'] = 'application/x-yaml; charset=utf-8';
	}
	return new Response(订阅内容, { status: 200, headers: responseHeaders });
}

async function 生成混合订阅(request: Request, env: RuntimeEnv, url: URL, host: string, userID: string, ua: string, cfg: ConfigShape, 协议类型: string, isSubConverterRequest: boolean, 作为优选订阅生成器: boolean): Promise<string> {
	void host;
	const TLS分片参数 = cfg.TLS分片 === 'Shadowrocket'
		? `&fragment=${encodeURIComponent('1,40-60,30-50,tlshello')}`
		: cfg.TLS分片 === 'Happ'
			? `&fragment=${encodeURIComponent('3,1,tlshello')}`
			: '';
	let 完整优选IP: string[] = [];
	let 其他节点LINK = '';
	let 反代IP池: string[] = [];

	if (!url.searchParams.has('sub') && cfg.优选订阅生成?.local) {
		const 完整优选列表 = cfg.优选订阅生成.本地IP库?.随机IP
			? (await 生成随机IP(request, cfg.优选订阅生成.本地IP库.随机数量 ?? 16, cfg.优选订阅生成.本地IP库.指定端口 ?? -1))[0]
			: (await env.KV.get('ADD.txt'))
				? await 整理成数组((await env.KV.get('ADD.txt')) || '')
				: (await 生成随机IP(request, cfg.优选订阅生成.本地IP库?.随机数量 ?? 16, cfg.优选订阅生成.本地IP库?.指定端口 ?? -1))[0];
		const 优选API: string[] = [];
		const 优选IP: string[] = [];
		const 其他节点: string[] = [];
		for (const 元素 of 完整优选列表) {
			if (元素.toLowerCase().startsWith('sub://')) {
				优选API.push(元素);
				continue;
			}
			const 备注位置 = 元素.indexOf('#');
			const 地址部分 = 备注位置 > -1 ? 元素.slice(0, 备注位置) : 元素;
			const 备注部分 = 备注位置 > -1 ? 元素.slice(备注位置) : '';
			const subMatch = 元素.match(/sub\s*=\s*([^\s&#]+)/i);
			if (subMatch && subMatch[1].trim().includes('.')) {
				const 优选IP作为反代IP = 元素.toLowerCase().includes('proxyip=true');
				const remarkSuffix = 元素.includes('#') ? '#' + 元素.split('#')[1] : '';
				if (优选IP作为反代IP) 优选API.push('sub://' + subMatch[1].trim() + '?proxyip=true' + remarkSuffix);
				else 优选API.push('sub://' + subMatch[1].trim() + remarkSuffix);
			} else if (地址部分.toLowerCase().startsWith('https://')) {
				优选API.push(元素);
			} else if (地址部分.toLowerCase().includes('://')) {
				if (元素.includes('#')) {
					const 地址备注分离 = 元素.split('#');
					其他节点.push(地址备注分离[0] + '#' + encodeURIComponent(decodeURIComponent(地址备注分离[1])));
				} else {
					其他节点.push(元素);
				}
			} else if (地址部分.includes('*')) {
				优选IP.push(替换星号为随机字符(地址部分) + 备注部分);
			} else {
				优选IP.push(元素);
			}
		}
		const 请求优选API内容 = await 请求优选API(优选API, '443');
		const 合并其他节点数组 = [...new Set(其他节点.concat(请求优选API内容[1]))];
		其他节点LINK = 合并其他节点数组.length > 0 ? 合并其他节点数组.join('\n') + '\n' : '';
		const 优选API的IP = 请求优选API内容[0];
		反代IP池 = 请求优选API内容[3] || [];
		完整优选IP = [...new Set(优选IP.concat(优选API的IP))];
	} else {
		const 优选订阅生成器HOST = url.searchParams.get('sub') || cfg.优选订阅生成?.SUB || '';
		if (优选订阅生成器HOST) {
			const [优选生成器IP数组, 优选生成器其他节点] = await 获取优选订阅生成器数据(优选订阅生成器HOST);
			完整优选IP = 完整优选IP.concat(优选生成器IP数组);
			其他节点LINK += 优选生成器其他节点;
		}
	}
	const ECHLINK参数 = cfg.ECH ? `&ech=${encodeURIComponent((cfg.ECHConfig?.SNI ? cfg.ECHConfig.SNI + '+' : '') + cfg.ECHConfig?.DNS)}` : '';
	const isLoonOrSurge = ua.includes('loon') || ua.includes('surge');
	const { type: 传输协议, 路径字段名, 域名字段名 } = 获取传输协议配置(cfg);
	const 节点行集合 = 完整优选IP.map((原始地址) => {
		const regex = /^(\[[\da-fA-F:]+\]|[\d.]+|[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?)*)(?::(\d+))?(?:#(.+))?$/;
		const match = 原始地址.match(regex);
		if (!match) {
			console.warn(`[订阅内容] 不规范的IP格式已忽略: ${原始地址}`);
			return null;
		}

		const 节点地址 = match[1];
		let 节点端口 = match[2] ? match[2] : '443';
		let 节点备注 = match[3] || 节点地址;
		let 完整节点路径 = cfg.完整节点路径 || '/';

		const 链式代理匹配 = 节点备注.match(/\$(socks5|http|https|turn|sstp):\/\/([^#\s]+)/i);
		if (链式代理匹配) {
			try {
				const 代理协议 = 链式代理匹配[1].toLowerCase();
				const 代理参数 = 链式代理匹配[2];
				const acct = 获取SOCKS5账号(代理参数, 获取代理默认端口(代理协议));
				const 链式代理数据 = { type: 代理协议, ...acct };
				完整节点路径 = `/video/${base64SecretEncode(JSON.stringify(链式代理数据), userID) + (cfg.启用0RTT ? '?ed=2560' : '')}`;
				节点备注 = 节点备注.replace(链式代理匹配[0], '').trim() || 节点地址;
			} catch (error) {
				console.warn(`[订阅内容] 链式代理解析失败，已忽略该指令: ${链式代理匹配[0]} (${(error as { message?: string })?.message || error})`);
			}
		} else if (反代IP池.length > 0) {
			const 匹配到的反代IP = 反代IP池.find((p) => p.includes(节点地址));
			if (匹配到的反代IP) 完整节点路径 = `${cfg.PATH}/proxyip=${匹配到的反代IP}`.replace(/\/\//g, '/') + (cfg.启用0RTT ? '?ed=2560' : '');
		}
		if (isLoonOrSurge) 完整节点路径 = 完整节点路径.replace(/,/g, '%2C');

		if (协议类型 === 'ss' && !作为优选订阅生成器) {
			if (!cfg.SS?.TLS) {
				const TLS端口 = [443, 2053, 2083, 2087, 2096, 8443];
				const NOTLS端口 = [80, 2052, 2082, 2086, 2095, 8080];
				const idx = TLS端口.indexOf(Number(节点端口));
				节点端口 = String(NOTLS端口[idx] ?? 节点端口);
			}
			完整节点路径 = (完整节点路径.includes('?') ? 完整节点路径.replace('?', '?enc=' + cfg.SS?.加密方式 + '&') : 完整节点路径 + '?enc=' + cfg.SS?.加密方式).replace(/([=,])/g, '\\$1');
			if (!isSubConverterRequest) 完整节点路径 = 完整节点路径 + ';mux=0';
			return `${协议类型}://${btoa((cfg.SS?.加密方式 || 'aes-128-gcm') + ':00000000-0000-4000-8000-000000000000')}@${节点地址}:${节点端口}?plugin=v2${encodeURIComponent('ray-plugin;mode=websocket;host=example.com;path=' + (cfg.随机路径 ? 随机路径(完整节点路径) : 完整节点路径) + (cfg.SS?.TLS ? ';tls' : '')) + ECHLINK参数 + TLS分片参数}#${encodeURIComponent(节点备注)}`;
		}
		const 传输路径参数值 = 获取传输路径参数值(cfg, 完整节点路径, 作为优选订阅生成器);
		return `${协议类型}://00000000-0000-4000-8000-000000000000@${节点地址}:${节点端口}?security=tls&type=${传输协议 + ECHLINK参数}&${域名字段名}=example.com&fp=${cfg.Fingerprint}&sni=example.com&${路径字段名}=${encodeURIComponent(传输路径参数值) + TLS分片参数}&encryption=none#${encodeURIComponent(节点备注)}`;
	});
	const filtered: string[] = 节点行集合.filter((item): item is string => item !== null);
	const 拼接结果 = filtered.join('\n');
	void 数据转Uint8Array;
	return 其他节点LINK + 拼接结果;
}
