// 优选订阅生成器拉取 + 优选 API 多源解析。

import { TOKENS } from './tokens';
const 优选IP_IPV6_PATTERN = /^[^\[\]]*:[^\[\]]*:[^\[\]]/;

export interface 优选API结果 {
	优选IP: string[];
	链接列表: string[];
	需要订阅转换订阅URLs: string[];
	反代IP池: string[];
}

export async function 获取优选订阅生成器数据(优选订阅生成器HOST: string): Promise<[string[], string]> {
	const 优选IP: string[] = [];
	let 其他节点LINK = '';
	let 格式化HOST = 优选订阅生成器HOST.replace(/^sub:\/\//i, 'https://').split('#')[0].split('?')[0];
	if (!/^https?:\/\//i.test(格式化HOST)) 格式化HOST = `https://${格式化HOST}`;

	try {
		const url = new URL(格式化HOST);
		格式化HOST = url.origin;
	} catch (error) {
		优选IP.push(`127.0.0.1:1234#${优选订阅生成器HOST}优选订阅生成器格式化异常:${(error as { message?: string })?.message || error}`);
		return [优选IP, 其他节点LINK];
	}

	const 优选订阅生成器URL = `${格式化HOST}/sub?host=example.com&uuid=00000000-0000-4000-8000-000000000000`;

	try {
		const response = await fetch(优选订阅生成器URL, { headers: { 'User-Agent': 'v2rayN/edgetunnel (https://github.com/cmliu/edgetunnel)' } });
		if (!response.ok) {
			优选IP.push(`127.0.0.1:1234#${优选订阅生成器HOST}优选订阅生成器异常:${response.statusText}`);
			return [优选IP, 其他节点LINK];
		}

		const 优选订阅生成器返回订阅内容 = atob(await response.text());
		const 订阅行列表 = 优选订阅生成器返回订阅内容.includes('\r\n') ? 优选订阅生成器返回订阅内容.split('\r\n') : 优选订阅生成器返回订阅内容.split('\n');

		for (const 行内容 of 订阅行列表) {
			if (!行内容.trim()) continue;
			if (行内容.includes('00000000-0000-4000-8000-000000000000') && 行内容.includes('example.com')) {
				const 地址匹配 = 行内容.match(/:\/\/[^@]+@([^?]+)/);
				if (地址匹配) {
					let 备注 = '';
					const 地址端口 = 地址匹配[1];
					const 备注匹配 = 行内容.match(/#(.+)$/);
					if (备注匹配) 备注 = '#' + decodeURIComponent(备注匹配[1]);
					优选IP.push(地址端口 + 备注);
				}
			} else {
				其他节点LINK += 行内容 + '\n';
			}
		}
	} catch (error) {
		优选IP.push(`127.0.0.1:1234#${优选订阅生成器HOST}优选订阅生成器异常:${(error as { message?: string })?.message || error}`);
	}

	return [优选IP, 其他节点LINK];
}

export async function 请求优选API(urls: string[], 默认端口: string | number = '443', 超时时间 = 3000): Promise<[string[], string[], string[], string[]]> {
	if (!urls?.length) return [[], [], [], []];
	const results = new Set<string>();
	const 反代IP池 = new Set<string>();
	let 订阅链接响应的明文LINK内容 = '';
	const 需要订阅转换订阅URLs: string[] = [];

	await Promise.allSettled(urls.map(async (url) => {
		const hashIndex = url.indexOf('#');
		const urlWithoutHash = hashIndex > -1 ? url.substring(0, hashIndex) : url;
		const API备注名 = hashIndex > -1 ? decodeURIComponent(url.substring(hashIndex + 1)) : null;
		const 优选IP作为反代IP = url.toLowerCase().includes('proxyip=true');
		if (urlWithoutHash.toLowerCase().startsWith('sub://')) {
			try {
				const [优选IP, 其他节点LINK] = await 获取优选订阅生成器数据(urlWithoutHash);
				if (API备注名) {
					for (const ip of 优选IP) {
						const 处理后IP = ip.includes('#') ? `${ip} [${API备注名}]` : `${ip}#[${API备注名}]`;
						results.add(处理后IP);
						if (优选IP作为反代IP) 反代IP池.add(ip.split('#')[0]);
					}
				} else {
					for (const ip of 优选IP) {
						results.add(ip);
						if (优选IP作为反代IP) 反代IP池.add(ip.split('#')[0]);
					}
				}
				if (其他节点LINK && API备注名) {
					const 处理后LINK内容 = 其他节点LINK.replace(/([a-z][a-z0-9+\-.]*:\/\/[^\r\n]*?)(\r?\n|$)/gi, (match, link, lineEnd) => {
						void match;
						const 完整链接 = link.includes('#') ? `${link}${encodeURIComponent(` [${API备注名}]`)}` : `${link}${encodeURIComponent(`#[${API备注名}]`)}`;
						return `${完整链接}${lineEnd}`;
					});
					订阅链接响应的明文LINK内容 += 处理后LINK内容;
				} else if (其他节点LINK) {
					订阅链接响应的明文LINK内容 += 其他节点LINK;
				}
			} catch { /* ignore */ }
			return;
		}

		try {
			const controller = new AbortController();
			const timeoutId = setTimeout(() => controller.abort(), 超时时间);
			const response = await fetch(urlWithoutHash, { signal: controller.signal });
			clearTimeout(timeoutId);
			let text = '';
			try {
				const buffer = await response.arrayBuffer();
				const contentType = (response.headers.get('content-type') || '').toLowerCase();
				const charset = contentType.match(/charset=([^\s;]+)/i)?.[1]?.toLowerCase() || '';

				let decoders = ['utf-8', 'gb2312'];
				if (charset.includes('gb') || charset.includes('gbk') || charset.includes('gb2312')) decoders = ['gb2312', 'utf-8'];

				let decodeSuccess = false;
				for (const decoder of decoders) {
					try {
						const decoded = new TextDecoder(decoder).decode(buffer);
						if (decoded && decoded.length > 0 && !decoded.includes('\ufffd')) {
							text = decoded;
							decodeSuccess = true;
							break;
						}
					} catch { /* try next */ }
				}
				if (!decodeSuccess) text = await response.text();
				if (!text || text.trim().length === 0) return;
			} catch (e) {
				console.error('Failed to decode response:', e);
				return;
			}

			let 预处理订阅明文内容 = text;
			const cleanText = typeof text === 'string' ? text.replace(/\s/g, '') : '';
			if (cleanText.length > 0 && cleanText.length % 4 === 0 && /^[A-Za-z0-9+/]+={0,2}$/.test(cleanText)) {
				try {
					const bytes = new Uint8Array(atob(cleanText).split('').map((c) => c.charCodeAt(0)));
					预处理订阅明文内容 = new TextDecoder('utf-8').decode(bytes);
				} catch { /* ignore */ }
			}
			if (预处理订阅明文内容.split('#')[0].includes('://')) {
				if (API备注名) {
					const 处理后LINK内容 = 预处理订阅明文内容.replace(/([a-z][a-z0-9+\-.]*:\/\/[^\r\n]*?)(\r?\n|$)/gi, (match, link, lineEnd) => {
						void match;
						const 完整链接 = link.includes('#') ? `${link}${encodeURIComponent(` [${API备注名}]`)}` : `${link}${encodeURIComponent(`#[${API备注名}]`)}`;
						return `${完整链接}${lineEnd}`;
					});
					订阅链接响应的明文LINK内容 += 处理后LINK内容 + '\n';
				} else {
					订阅链接响应的明文LINK内容 += 预处理订阅明文内容 + '\n';
				}
				return;
			}

			const lines = text.trim().split('\n').map((l) => l.trim()).filter(Boolean);
			const isCSV = lines.length > 1 && lines[0].includes(',');
			const parsedUrl = new URL(urlWithoutHash);
			if (!isCSV) {
				lines.forEach((line) => {
					const lineHashIndex = line.indexOf('#');
					const [hostPart, remark] = lineHashIndex > -1 ? [line.substring(0, lineHashIndex), line.substring(lineHashIndex)] : [line, ''];
					let hasPort = false;
					if (hostPart.startsWith('[')) {
						hasPort = /\]:(\d+)$/.test(hostPart);
					} else {
						const colonIndex = hostPart.lastIndexOf(':');
						hasPort = colonIndex > -1 && /^\d+$/.test(hostPart.substring(colonIndex + 1));
					}
					const port = parsedUrl.searchParams.get('port') || 默认端口;
					const ipItem = hasPort ? line : `${hostPart}:${port}${remark}`;
					if (API备注名) {
						const 处理后IP = ipItem.includes('#') ? `${ipItem} [${API备注名}]` : `${ipItem}#[${API备注名}]`;
						results.add(处理后IP);
					} else {
						results.add(ipItem);
					}
					if (优选IP作为反代IP) 反代IP池.add(ipItem.split('#')[0]);
				});
			} else {
				const headers = lines[0].split(',').map((h) => h.trim());
				const dataLines = lines.slice(1);
				if (headers.includes('IP地址') && headers.includes('端口') && headers.includes('数据中心')) {
					const ipIdx = headers.indexOf('IP地址');
					const portIdx = headers.indexOf('端口');
					const remarkIdx = headers.indexOf('国家') > -1 ? headers.indexOf('国家') : headers.indexOf('城市') > -1 ? headers.indexOf('城市') : headers.indexOf('数据中心');
					const tlsIdx = headers.indexOf('TLS');
					dataLines.forEach((line) => {
						const cols = line.split(',').map((c) => c.trim());
						if (tlsIdx !== -1 && cols[tlsIdx]?.toLowerCase() !== 'true') return;
						const wrappedIP = 优选IP_IPV6_PATTERN.test(cols[ipIdx]) ? `[${cols[ipIdx]}]` : cols[ipIdx];
						const ipItem = `${wrappedIP}:${cols[portIdx]}#${cols[remarkIdx]}`;
						if (API备注名) results.add(`${ipItem} [${API备注名}]`);
						else results.add(ipItem);
						if (优选IP作为反代IP) 反代IP池.add(`${wrappedIP}:${cols[portIdx]}`);
					});
				} else if (headers.some((h) => h.includes('IP')) && headers.some((h) => h.includes('延迟')) && headers.some((h) => h.includes('下载速度'))) {
					const ipIdx = headers.findIndex((h) => h.includes('IP'));
					const delayIdx = headers.findIndex((h) => h.includes('延迟'));
					const speedIdx = headers.findIndex((h) => h.includes('下载速度'));
					const port = parsedUrl.searchParams.get('port') || 默认端口;
					dataLines.forEach((line) => {
						const cols = line.split(',').map((c) => c.trim());
						const wrappedIP = 优选IP_IPV6_PATTERN.test(cols[ipIdx]) ? `[${cols[ipIdx]}]` : cols[ipIdx];
						const ipItem = `${wrappedIP}:${port}#CF优选 ${cols[delayIdx]}ms ${cols[speedIdx]}MB/s`;
						if (API备注名) results.add(`${ipItem} [${API备注名}]`);
						else results.add(ipItem);
						if (优选IP作为反代IP) 反代IP池.add(`${wrappedIP}:${port}`);
					});
				}
			}
		} catch { /* ignore */ }
	}));

	const LINK数组 = 订阅链接响应的明文LINK内容.trim()
		? [...new Set(订阅链接响应的明文LINK内容.split(/\r?\n/).filter((line) => line.trim() !== ''))]
		: [];
	return [Array.from(results), LINK数组, 需要订阅转换订阅URLs, Array.from(反代IP池)];
}
