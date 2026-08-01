// 订阅链接里要用到的两个共享小工具：传输协议字段名 + 路径参数值。

import { 随机路径 } from './utils';

export interface 传输协议Info {
	type: string;
	路径字段名: string;
	域名字段名: string;
}

export function 获取传输协议配置(配置: { 传输协议?: string; gRPC模式?: string; XHTTP模式?: string } = {}): 传输协议Info {
	const 是gRPC = 配置.传输协议 === 'grpc';
	const 是XHTTP = 配置.传输协议 === 'xhttp';
	// XHTTP 模式: stream-one (默认) / stream-up / packet-up
	const xhttpMode = 配置.XHTTP模式 || 'stream-one';
	return {
		type: 是gRPC
			? (配置.gRPC模式 === 'multi' ? 'grpc&mode=multi' : 'grpc&mode=gun')
			: 是XHTTP
				? `xhttp&mode=${xhttpMode}`
				: 'ws',
		路径字段名: 是gRPC ? 'serviceName' : 'path',
		域名字段名: 是gRPC ? 'authority' : 'host',
	};
}

export function 获取传输路径参数值(配置: { 传输协议?: string; 随机路径?: boolean } = {}, 节点路径 = '/', 作为优选订阅生成器 = false): string {
	const 路径值 = 作为优选订阅生成器 ? '/' : 配置.随机路径 ? 随机路径(节点路径) : 节点路径;
	if (配置.传输协议 !== 'grpc') return 路径值;
	return 路径值.split('?')[0] || '/';
}
