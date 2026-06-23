// 解析路径/参数里的代理设置，写入全局 state。

import { state } from './state';
import { base64SecretDecode } from './utils';
import { 反代协议默认端口, 获取代理默认端口, 获取SOCKS5账号 } from './resolver';

export async function 反代参数获取(url: URL, uuid: string): Promise<void> {
	const { searchParams } = url;
	const pathname = decodeURIComponent(url.pathname);
	const pathLower = pathname.toLowerCase();

	const 链式代理路径匹配 = pathname.match(/\/video\/(.+)$/i);
	if (链式代理路径匹配) {
		try {
			const 链式代理明文 = base64SecretDecode(链式代理路径匹配[1], uuid);
			const parsed = JSON.parse(链式代理明文) as { type?: string; username?: string; password?: string; hostname?: string; port?: number | string };
			const { type, username, password, hostname, port } = parsed;
			if (!type || !反代协议默认端口[String(type).toLowerCase()]) throw new Error('链式代理类型无效');
			if (!hostname || !port) throw new Error('链式代理地址缺少 hostname 或 port');
			state.我的SOCKS5账号 = '';
			state.反代IP = '链式代理';
			state.启用反代兜底 = false;
			state.启用SOCKS5全局反代 = true;
			state.启用SOCKS5反代 = String(type).toLowerCase() as typeof state.启用SOCKS5反代;
			const portNum = Number(port);
			if (isNaN(portNum)) throw new Error('链式代理端口无效');
			state.parsedSocks5Address = { username, password, hostname, port: portNum };
			return;
		} catch (err) {
			console.error('解析链式代理参数失败:', (err as { message?: string })?.message || err);
		}
	}

	state.我的SOCKS5账号 = searchParams.get('socks5') || searchParams.get('http') || searchParams.get('https') || searchParams.get('turn') || searchParams.get('sstp') || '';
	state.启用SOCKS5全局反代 = searchParams.has('globalproxy');
	if (searchParams.get('socks5')) state.启用SOCKS5反代 = 'socks5';
	else if (searchParams.get('http')) state.启用SOCKS5反代 = 'http';
	else if (searchParams.get('https')) state.启用SOCKS5反代 = 'https';
	else if (searchParams.get('turn')) state.启用SOCKS5反代 = 'turn';
	else if (searchParams.get('sstp')) state.启用SOCKS5反代 = 'sstp';

	const 解析代理URL = (值: string, 强制全局 = true): boolean => {
		const 匹配 = /^(socks5|http|https|turn|sstp):\/\/(.+)$/i.exec(值 || '');
		if (!匹配) return false;
		state.启用SOCKS5反代 = 匹配[1].toLowerCase() as typeof state.启用SOCKS5反代;
		state.我的SOCKS5账号 = 匹配[2].split('/')[0];
		if (强制全局) state.启用SOCKS5全局反代 = true;
		return true;
	};

	const 设置反代IP = (值: string): void => {
		state.反代IP = 值;
		state.启用SOCKS5反代 = null;
		state.启用反代兜底 = false;
	};

	const 提取路径值 = (值: string): string => {
		if (!值.includes('://')) {
			const 斜杠索引 = 值.indexOf('/');
			return 斜杠索引 > 0 ? 值.slice(0, 斜杠索引) : 值;
		}
		const 协议拆分 = 值.split('://');
		if (协议拆分.length !== 2) return 值;
		const 斜杠索引 = 协议拆分[1].indexOf('/');
		return 斜杠索引 > 0 ? `${协议拆分[0]}://${协议拆分[1].slice(0, 斜杠索引)}` : 值;
	};

	const 查询反代IP = searchParams.get('proxyip');
	if (查询反代IP !== null) {
		if (!解析代理URL(查询反代IP)) {
			设置反代IP(查询反代IP);
			return;
		}
	} else {
		let 匹配 = /\/(socks5?|http|https|turn|sstp):\/?\/?([^/?#\s]+)/i.exec(pathname);
		if (匹配) {
			const 类型 = 匹配[1].toLowerCase();
			state.启用SOCKS5反代 = (类型 === 'sock' || 类型 === 'socks' ? 'socks5' : 类型) as typeof state.启用SOCKS5反代;
			state.我的SOCKS5账号 = 匹配[2].split('/')[0];
			state.启用SOCKS5全局反代 = true;
		} else if ((匹配 = /\/(g?s5|socks5|g?http|g?https|g?turn|g?sstp)=([^/?#\s]+)/i.exec(pathname))) {
			const 类型 = 匹配[1].toLowerCase();
			state.我的SOCKS5账号 = 匹配[2].split('/')[0];
			state.启用SOCKS5反代 = (类型.includes('sstp') ? 'sstp' : 类型.includes('turn') ? 'turn' : 类型.includes('https') ? 'https' : 类型.includes('http') ? 'http' : 'socks5') as typeof state.启用SOCKS5反代;
			if (类型.startsWith('g')) state.启用SOCKS5全局反代 = true;
		} else if ((匹配 = /\/(proxyip[.=]|pyip=|ip=)([^?#\s]+)/.exec(pathLower))) {
			const 路径反代值 = 提取路径值(匹配[2]);
			if (!解析代理URL(路径反代值)) {
				设置反代IP(路径反代值);
				return;
			}
		}
	}

	if (!state.我的SOCKS5账号) {
		state.启用SOCKS5反代 = null;
		return;
	}

	try {
		state.parsedSocks5Address = 获取SOCKS5账号(state.我的SOCKS5账号, 获取代理默认端口(state.启用SOCKS5反代));
		if (searchParams.get('socks5')) state.启用SOCKS5反代 = 'socks5';
		else if (searchParams.get('http')) state.启用SOCKS5反代 = 'http';
		else if (searchParams.get('https')) state.启用SOCKS5反代 = 'https';
		else if (searchParams.get('turn')) state.启用SOCKS5反代 = 'turn';
		else if (searchParams.get('sstp')) state.启用SOCKS5反代 = 'sstp';
		else state.启用SOCKS5反代 = state.启用SOCKS5反代 || 'socks5';
	} catch (err) {
		console.error('解析SOCKS5地址失败:', (err as { message?: string })?.message || err);
		state.启用SOCKS5反代 = null;
	}
}
