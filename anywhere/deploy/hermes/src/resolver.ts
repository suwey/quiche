// 反代地址解析（TXT/A/AAAA），SOCKS5 账号格式化。

import { DoH查询 } from './doh';
import { state, log } from './state';
import { 整理成数组 } from './utils';
import type { ParsedProxyAddress } from './types';

export const 反代协议默认端口: Record<string, number> = { socks5: 1080, http: 80, https: 443, turn: 3478, sstp: 443 };

export function 获取代理默认端口(类型: string | null | undefined): number {
	return 反代协议默认端口[String(类型 || '').toLowerCase()] || 80;
}

const SOCKS5账号Base64正则 = /^(?:[A-Z0-9+/]{4})*(?:[A-Z0-9+/]{2}==|[A-Z0-9+/]{3}=)?$/i;
const IPv6方括号正则 = /^\[.*\]$/;

export function 获取SOCKS5账号(address: string, 默认端口 = 80): ParsedProxyAddress {
	let addr = String(address || '').trim().replace(/^(socks5|http|https|turn|sstp):\/\//i, '').split('#')[0].trim();
	const firstAt = addr.lastIndexOf('@');
	if (firstAt !== -1) {
		let auth = addr.slice(0, firstAt).replaceAll('%3D', '=');
		if (!auth.includes(':') && SOCKS5账号Base64正则.test(auth)) auth = atob(auth);
		addr = `${auth}@${addr.slice(firstAt + 1)}`;
	}

	const atIndex = addr.lastIndexOf('@');
	const hostPart = (atIndex === -1 ? addr : addr.slice(atIndex + 1)).split('/')[0];
	const authPart = atIndex === -1 ? '' : addr.slice(0, atIndex);
	const [username, password] = authPart ? authPart.split(':') : [];
	if (authPart && !password) throw new Error('无效的 SOCKS 地址格式：认证部分必须是 "username:password" 的形式');

	let hostname = hostPart;
	let port: number = 默认端口;
	if (hostPart.includes(']:')) {
		const [ipv6Host, ipv6Port = ''] = hostPart.split(']:');
		hostname = ipv6Host + ']';
		port = Number(ipv6Port.replace(/[^\d]/g, ''));
	} else if (!hostPart.startsWith('[')) {
		const parts = hostPart.split(':');
		if (parts.length === 2) {
			hostname = parts[0];
			port = Number(parts[1].replace(/[^\d]/g, ''));
		}
	}

	if (isNaN(port)) throw new Error('无效的 SOCKS 地址格式：端口号必须是数字');
	if (hostname.includes(':') && !IPv6方括号正则.test(hostname)) throw new Error('无效的 SOCKS 地址格式：IPv6 地址必须用方括号括起来，如 [2001:db8::1]');
	return { username, password, hostname, port };
}

function 解析地址端口字符串(str: string): [string, number] {
	let 地址 = str;
	let 端口 = 443;
	if (str.includes(']:')) {
		const parts = str.split(']:');
		地址 = parts[0] + ']';
		端口 = parseInt(parts[1], 10) || 端口;
	} else if ((str.match(/:/g) || []).length === 1 && !str.startsWith('[')) {
		const colonIndex = str.lastIndexOf(':');
		地址 = str.slice(0, colonIndex);
		端口 = parseInt(str.slice(colonIndex + 1), 10) || 端口;
	}
	return [地址, 端口];
}

function 解析TXT反代记录(txtData: string[]): Array<[string, number]> {
	return txtData
		.flatMap((data) => {
			let normalized = data;
			if (normalized.startsWith('"') && normalized.endsWith('"')) normalized = normalized.slice(1, -1);
			return normalized.replace(/\\010/g, ',').replace(/\n/g, ',').split(',').map((s) => s.trim()).filter(Boolean);
		})
		.map((prefix) => 解析地址端口字符串(prefix));
}

export async function 解析地址端口(proxyIP: string, 目标域名 = 'dash.cloudflare.com', UUID = '00000000-0000-4000-8000-000000000000'): Promise<Array<[string, number]>> {
	if (!state.缓存反代IP || !state.缓存反代解析数组 || state.缓存反代IP !== proxyIP) {
		const lower = proxyIP.toLowerCase();
		const 反代IP数组 = await 整理成数组(lower);
		const 所有反代数组: Array<[string, number]> = [];
		const ipv4Regex = /^(25[0-5]|2[0-4]\d|[01]?\d\d?)\.(25[0-5]|2[0-4]\d|[01]?\d\d?)\.(25[0-5]|2[0-4]\d|[01]?\d\d?)\.(25[0-5]|2[0-4]\d|[01]?\d\d?)$/;
		const ipv6Regex = /^\[?(?:[a-fA-F0-9]{0,4}:){1,7}[a-fA-F0-9]{0,4}\]?$/;

		for (const singleProxyIP of 反代IP数组) {
			const [地址, 默认端口] = 解析地址端口字符串(singleProxyIP);
			let 端口 = 默认端口;

			if (singleProxyIP.includes('.tp')) {
				const tpMatch = singleProxyIP.match(/\.tp(\d+)/);
				if (tpMatch) 端口 = parseInt(tpMatch[1], 10);
			}

			if (ipv4Regex.test(地址) || ipv6Regex.test(地址)) {
				log(`[反代解析] ${地址} 为IP地址，直接使用`);
				所有反代数组.push([地址, 端口]);
				continue;
			}

			const [txtRecords, aRecords] = await Promise.all([DoH查询(地址, 'TXT'), DoH查询(地址, 'A')]);

			const txtData = txtRecords.filter((r) => r.type === 16).map((r) => r.data);
			const txtAddresses = 解析TXT反代记录(txtData);
			if (txtAddresses.length > 0) {
				log(`[反代解析] ${地址} 使用TXT记录，共${txtAddresses.length}个结果`);
				所有反代数组.push(...txtAddresses);
				continue;
			}

			const ipv4List = aRecords.filter((r) => r.type === 1).map((r) => r.data);
			if (ipv4List.length > 0) {
				log(`[反代解析] ${地址} 未获取到TXT记录，使用A记录，共${ipv4List.length}个结果`);
				所有反代数组.push(...ipv4List.map((ip) => [ip, 端口] as [string, number]));
				continue;
			}

			const aaaaRecords = await DoH查询(地址, 'AAAA');
			const ipv6List = aaaaRecords.filter((r) => r.type === 28).map((r) => `[${r.data}]`);
			if (ipv6List.length > 0) {
				log(`[反代解析] ${地址} 未获取到TXT和A记录，使用AAAA记录，共${ipv6List.length}个结果`);
				所有反代数组.push(...ipv6List.map((ip) => [ip, 端口] as [string, number]));
			} else {
				log(`[反代解析] ${地址} 未获取到TXT、A和AAAA记录，保留原域名`);
				所有反代数组.push([地址, 端口]);
			}
		}
		const 排序后数组 = 所有反代数组.sort((a, b) => a[0].localeCompare(b[0]));
		const 目标根域名 = 目标域名.includes('.') ? 目标域名.split('.').slice(-2).join('.') : 目标域名;
		let 随机种子 = [...(目标根域名 + UUID)].reduce((a, c) => a + c.charCodeAt(0), 0);
		log(`[反代解析] 随机种子: ${随机种子}\n目标站点: ${目标根域名}`);
		const 洗牌后 = [...排序后数组].sort(() => {
			随机种子 = (随机种子 * 1103515245 + 12345) & 0x7fffffff;
			return 随机种子 / 0x7fffffff - 0.5;
		});
		state.缓存反代解析数组 = 洗牌后.slice(0, 8);
		log(`[反代解析] 解析完成 总数: ${state.缓存反代解析数组.length}个\n${state.缓存反代解析数组.map(([ip, port], index) => `${index + 1}. ${ip}:${port}`).join('\n')}`);
		state.缓存反代IP = lower;
	} else {
		log(`[反代解析] 读取缓存 总数: ${state.缓存反代解析数组.length}个\n${state.缓存反代解析数组.map(([ip, port], index) => `${index + 1}. ${ip}:${port}`).join('\n')}`);
	}
	return state.缓存反代解析数组;
}
