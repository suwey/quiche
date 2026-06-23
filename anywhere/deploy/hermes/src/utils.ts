// 字节、IP、超时之类的小工具。

export function 数据转Uint8Array(data: ArrayBuffer | ArrayBufferView | Uint8Array | string | null | undefined): Uint8Array {
	if (data instanceof Uint8Array) return data;
	if (data instanceof ArrayBuffer) return new Uint8Array(data);
	if (ArrayBuffer.isView(data)) return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
	if (typeof data === 'string') return new TextEncoder().encode(data);
	return new Uint8Array(0);
}

export function 拼接字节数据(...chunkList: Array<Uint8Array | ArrayBuffer | ArrayBufferView | null | undefined>): Uint8Array {
	if (!chunkList || chunkList.length === 0) return new Uint8Array(0);
	const chunks = chunkList.map((c) => 数据转Uint8Array(c ?? null));
	let total = 0;
	for (const c of chunks) total += c.byteLength;
	const result = new Uint8Array(total);
	let offset = 0;
	for (const c of chunks) {
		result.set(c, offset);
		offset += c.byteLength;
	}
	return result;
}

export function 有效数据长度(data: unknown): number {
	if (!data) return 0;
	const view = data as { byteLength?: unknown; length?: unknown };
	if (typeof view.byteLength === 'number') return view.byteLength;
	if (typeof view.length === 'number') return view.length;
	return 0;
}

export function stripIPv6Brackets(hostname = ''): string {
	const host = String(hostname || '').trim();
	return host.startsWith('[') && host.endsWith(']') ? host.slice(1, -1) : host;
}

export function isIPHostname(hostname = ''): boolean {
	const host = stripIPv6Brackets(hostname);
	const ipv4Regex = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;
	if (ipv4Regex.test(host)) return true;
	if (!host.includes(':')) return false;
	try {
		new URL(`http://[${host}]/`);
		return true;
	} catch {
		return false;
	}
}

export function isIPv4(value: unknown): boolean {
	const parts = String(value || '').split('.');
	return parts.length === 4 && parts.every((part) => /^\d{1,3}$/.test(part) && Number(part) >= 0 && Number(part) <= 255);
}

export async function withTimeout<T>(promise: Promise<T>, timeoutMs: number, message: string): Promise<T> {
	let timer: ReturnType<typeof setTimeout> | undefined;
	try {
		return await Promise.race([
			promise,
			new Promise<never>((_, reject) => {
				timer = setTimeout(() => reject(new Error(message)), timeoutMs);
			}),
		]);
	} finally {
		if (timer !== undefined) clearTimeout(timer);
	}
}

export function isSpeedTestSite(hostname: string): boolean {
	const speedTestDomains = [atob('c3BlZWQuY2xvdWRmbGFyZS5jb20=')];
	if (speedTestDomains.includes(hostname)) return true;
	for (const domain of speedTestDomains) {
		if (hostname.endsWith('.' + domain) || hostname === domain) return true;
	}
	return false;
}

export function closeSocketQuietly(socket: { readyState?: number; close?: () => void } | null | undefined): void {
	if (!socket) return;
	try {
		if (socket.readyState === 1 /* OPEN */ || socket.readyState === 2 /* CLOSING */) {
			socket.close?.();
		}
	} catch {
		/* ignore */
	}
}

export async function WebSocket发送并等待(webSocket: { send(data: ArrayBuffer | ArrayBufferView): unknown }, payload: ArrayBuffer | ArrayBufferView): Promise<void> {
	const sendResult = webSocket.send(payload);
	if (sendResult && typeof (sendResult as { then?: unknown }).then === 'function') {
		await (sendResult as Promise<unknown>);
	}
}

export async function 整理成数组(内容: string): Promise<string[]> {
	let 替换后的内容 = 内容.replace(/[\t"'\r\n]+/g, ',').replace(/,+/g, ',');
	if (替换后的内容.charAt(0) === ',') 替换后的内容 = 替换后的内容.slice(1);
	if (替换后的内容.charAt(替换后的内容.length - 1) === ',') 替换后的内容 = 替换后的内容.slice(0, 替换后的内容.length - 1);
	return 替换后的内容.split(',');
}

export async function MD5MD5(文本: string): Promise<string> {
	const 编码器 = new TextEncoder();
	const 第一次哈希 = await crypto.subtle.digest('MD5', 编码器.encode(文本));
	const 第一次十六进制 = Array.from(new Uint8Array(第一次哈希)).map((b) => b.toString(16).padStart(2, '0')).join('');
	const 第二次哈希 = await crypto.subtle.digest('MD5', 编码器.encode(第一次十六进制.slice(7, 27)));
	return Array.from(new Uint8Array(第二次哈希)).map((b) => b.toString(16).padStart(2, '0')).join('').toLowerCase();
}

export function 掩码敏感信息(文本: unknown, 前缀长度 = 3, 后缀长度 = 2): unknown {
	if (!文本 || typeof 文本 !== 'string') return 文本;
	if (文本.length <= 前缀长度 + 后缀长度) return 文本;
	const 前缀 = 文本.slice(0, 前缀长度);
	const 后缀 = 文本.slice(-后缀长度);
	const 星号数量 = 文本.length - 前缀长度 - 后缀长度;
	return `${前缀}${'*'.repeat(星号数量)}${后缀}`;
}

export function 替换星号为随机字符(内容: string): string {
	if (typeof 内容 !== 'string' || !内容.includes('*')) return 内容;
	const 字符集 = 'abcdefghijklmnopqrstuvwxyz0123456789';
	return 内容.replace(/\*/g, () => {
		let s = '';
		const len = Math.floor(Math.random() * 14) + 3;
		for (let i = 0; i < len; i++) s += 字符集[Math.floor(Math.random() * 字符集.length)];
		return s;
	});
}

export function 随机路径(完整节点路径 = '/'): string {
	const 常用路径目录 = ['about', 'account', 'acg', 'act', 'activity', 'ad', 'ads', 'ajax', 'album', 'albums', 'anime', 'api', 'app', 'apps', 'archive', 'archives', 'article', 'articles', 'ask', 'auth', 'avatar', 'bbs', 'bd', 'blog', 'blogs', 'book', 'books', 'bt', 'buy', 'cart', 'category', 'categories', 'cb', 'channel', 'channels', 'chat', 'china', 'city', 'class', 'classify', 'clip', 'clips', 'club', 'cn', 'code', 'collect', 'collection', 'comic', 'comics', 'community', 'company', 'config', 'contact', 'content', 'course', 'courses', 'cp', 'data', 'detail', 'details', 'dh', 'directory', 'discount', 'discuss', 'dl', 'dload', 'doc', 'docs', 'document', 'documents', 'doujin', 'download', 'downloads', 'drama', 'edu', 'en', 'ep', 'episode', 'episodes', 'event', 'events', 'f', 'faq', 'favorite', 'favourites', 'favs', 'feedback', 'file', 'files', 'film', 'films', 'forum', 'forums', 'friend', 'friends', 'game', 'games', 'gif', 'go', 'go.html', 'go.php', 'group', 'groups', 'help', 'home', 'hot', 'htm', 'html', 'image', 'images', 'img', 'index', 'info', 'intro', 'item', 'items', 'ja', 'jp', 'jump', 'jump.html', 'jump.php', 'jumping', 'knowledge', 'lang', 'lesson', 'lessons', 'lib', 'library', 'link', 'links', 'list', 'live', 'lives', 'm', 'mag', 'magnet', 'mall', 'manhua', 'map', 'member', 'members', 'message', 'messages', 'mobile', 'movie', 'movies', 'music', 'my', 'new', 'news', 'note', 'novel', 'novels', 'online', 'order', 'out', 'out.html', 'out.php', 'outbound', 'p', 'page', 'pages', 'pay', 'payment', 'pdf', 'photo', 'photos', 'pic', 'pics', 'picture', 'pictures', 'play', 'player', 'playlist', 'post', 'posts', 'product', 'products', 'program', 'programs', 'project', 'qa', 'question', 'rank', 'ranking', 'read', 'readme', 'redirect', 'redirect.html', 'redirect.php', 'reg', 'register', 'res', 'resource', 'retrieve', 'sale', 'search', 'season', 'seasons', 'section', 'seller', 'series', 'service', 'services', 'setting', 'settings', 'share', 'shop', 'show', 'shows', 'site', 'soft', 'sort', 'source', 'special', 'star', 'stars', 'static', 'stock', 'store', 'stream', 'streaming', 'streams', 'student', 'study', 'tag', 'tags', 'task', 'teacher', 'team', 'tech', 'temp', 'test', 'thread', 'tool', 'tools', 'topic', 'topics', 'torrent', 'trade', 'travel', 'tv', 'txt', 'type', 'u', 'upload', 'uploads', 'url', 'urls', 'user', 'users', 'v', 'version', 'videos', 'view', 'vip', 'vod', 'watch', 'web', 'wenku', 'wiki', 'work', 'www', 'zh', 'zh-cn', 'zh-tw', 'zip'];
	const 随机数 = Math.floor(Math.random() * 3 + 1);
	const 路径片段 = 常用路径目录.slice().sort(() => 0.5 - Math.random()).slice(0, 随机数).join('/');
	if (完整节点路径 === '/') return `/${路径片段}`;
	return `/${路径片段 + 完整节点路径.replace('/?', '?')}`;
}

export function base64SecretEncode(plaintext: string, secret: string): string {
	const encoder = new TextEncoder();
	const data = encoder.encode(plaintext);
	const key = encoder.encode(secret);
	const mixed = new Uint8Array(data.length);
	for (let i = 0; i < data.length; i++) mixed[i] = data[i] ^ key[i % key.length];
	let binary = '';
	for (let i = 0; i < mixed.length; i++) binary += String.fromCharCode(mixed[i]);
	return btoa(binary);
}

export function base64SecretDecode(encoded: string, secret: string): string {
	const binary = atob(encoded);
	const mixed = new Uint8Array(binary.length);
	for (let i = 0; i < binary.length; i++) mixed[i] = binary.charCodeAt(i);
	const encoder = new TextEncoder();
	const key = encoder.encode(secret);
	const data = new Uint8Array(mixed.length);
	for (let i = 0; i < mixed.length; i++) data[i] = mixed[i] ^ key[i % key.length];
	return new TextDecoder().decode(data);
}

/** SHA-224，木马握手用。 */
export function sha224(s: string): string {
	const K = [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2];
	const r = (n: number, b: number) => ((n >>> b) | (n << (32 - b))) >>> 0;
	let str = unescape(encodeURIComponent(s));
	const l = str.length * 8;
	str += String.fromCharCode(0x80);
	while ((str.length * 8) % 512 !== 448) str += String.fromCharCode(0);
	const h = [0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4];
	const hi = Math.floor(l / 0x100000000);
	const lo = l & 0xffffffff;
	str += String.fromCharCode((hi >>> 24) & 0xff, (hi >>> 16) & 0xff, (hi >>> 8) & 0xff, hi & 0xff, (lo >>> 24) & 0xff, (lo >>> 16) & 0xff, (lo >>> 8) & 0xff, lo & 0xff);
	const w: number[] = [];
	for (let i = 0; i < str.length; i += 4) w.push((str.charCodeAt(i) << 24) | (str.charCodeAt(i + 1) << 16) | (str.charCodeAt(i + 2) << 8) | str.charCodeAt(i + 3));
	for (let i = 0; i < w.length; i += 16) {
		const x = new Array<number>(64).fill(0);
		for (let j = 0; j < 16; j++) x[j] = w[i + j];
		for (let j = 16; j < 64; j++) {
			const s0 = r(x[j - 15], 7) ^ r(x[j - 15], 18) ^ (x[j - 15] >>> 3);
			const s1 = r(x[j - 2], 17) ^ r(x[j - 2], 19) ^ (x[j - 2] >>> 10);
			x[j] = (x[j - 16] + s0 + x[j - 7] + s1) >>> 0;
		}
		let [a, b, c, d, e, f, g, h0] = h;
		for (let j = 0; j < 64; j++) {
			const S1 = r(e, 6) ^ r(e, 11) ^ r(e, 25);
			const ch = (e & f) ^ (~e & g);
			const t1 = (h0 + S1 + ch + K[j] + x[j]) >>> 0;
			const S0 = r(a, 2) ^ r(a, 13) ^ r(a, 22);
			const maj = (a & b) ^ (a & c) ^ (b & c);
			const t2 = (S0 + maj) >>> 0;
			h0 = g;
			g = f;
			f = e;
			e = (d + t1) >>> 0;
			d = c;
			c = b;
			b = a;
			a = (t1 + t2) >>> 0;
		}
		const next = [a, b, c, d, e, f, g, h0];
		for (let j = 0; j < 8; j++) h[j] = (h[j] + next[j]) >>> 0;
	}
	let hex = '';
	for (let i = 0; i < 7; i++) {
		for (let j = 24; j >= 0; j -= 8) hex += ((h[i] >>> j) & 0xff).toString(16).padStart(2, '0');
	}
	return hex;
}

/** Varint：原协议自定义的 1/2/4 字节变长编码（高 2 位标记长度）。 */
export interface VarintRead {
	value: number;
	bytesRead: number;
}

export function 解码Varint(data: Uint8Array, offset: number): VarintRead {
	const b = data[offset];
	if ((b & 0xc0) === 0x00) return { value: b, bytesRead: 1 };
	if ((b & 0xc0) === 0x40) return { value: ((b & 0x3f) << 8) | data[offset + 1], bytesRead: 2 };
	// 0x80 prefix → 4-byte varint; 0xc0 prefix → 8-byte varint
	if ((b & 0xc0) === 0x80) {
		return {
			value: ((b & 0x3f) << 24) | (data[offset + 1] << 16) | (data[offset + 2] << 8) | data[offset + 3],
			bytesRead: 4,
		};
	}
	// 8-byte varint (0xc0 prefix) — JS bitwise ops are 32-bit, so use multiplication
	const hi = ((b & 0x3f) << 24) | (data[offset + 1] << 16) | (data[offset + 2] << 8) | data[offset + 3];
	const lo = (data[offset + 4] << 24) | (data[offset + 5] << 16) | (data[offset + 6] << 8) | data[offset + 7];
	return { value: hi * 0x100000000 + lo, bytesRead: 8 };
}

export function 编码Varint(value: number): Uint8Array {
	if (value < 64) return new Uint8Array([value]);
	if (value < 16384) return new Uint8Array([0x40 | (value >> 8), value & 0xff]);
	return new Uint8Array([0x80 | (value >> 24), (value >> 16) & 0xff, (value >> 8) & 0xff, value & 0xff]);
}

export function 编码帧(streamId: number, flags: number, payload: Uint8Array): Uint8Array {
	const sid = 编码Varint(streamId);
	const len = 编码Varint(payload.length);
	const frame = new Uint8Array(sid.length + 1 + len.length + payload.length);
	frame.set(sid, 0);
	frame[sid.length] = flags;
	frame.set(len, sid.length + 1);
	frame.set(payload, sid.length + 1 + len.length);
	return frame;
}
