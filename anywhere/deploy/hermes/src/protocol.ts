// 魏烈思 / 木马 协议握手包解析。

import { 数据转Uint8Array, sha224 } from './utils';
import type { ParsedRequest } from './types';

export const BLESS文本解码器 = new TextDecoder();
const 木马文本解码器 = new TextDecoder();

const UUID字节缓存 = new Map<string, Uint8Array>();

function 读取十六进制半字节(code: number): number {
	if (code >= 48 && code <= 57) return code - 48;
	const lower = code | 32;
	if (lower >= 97 && lower <= 102) return lower - 87;
	return -1;
}

export function 获取UUID字节(uuid: string): Uint8Array | null {
	const key = String(uuid || '');
	const cached = UUID字节缓存.get(key);
	if (cached) return cached;

	const clean = key.replace(/-/g, '');
	if (clean.length !== 32) return null;

	const bytes = new Uint8Array(16);
	for (let i = 0; i < 16; i++) {
		const high = 读取十六进制半字节(clean.charCodeAt(i * 2));
		const low = 读取十六进制半字节(clean.charCodeAt(i * 2 + 1));
		if (high < 0 || low < 0) return null;
		bytes[i] = (high << 4) | low;
	}

	if (UUID字节缓存.size >= 32) UUID字节缓存.clear();
	UUID字节缓存.set(key, bytes);
	return bytes;
}

export function UUID字节匹配(data: Uint8Array, offset: number, uuid: string): boolean {
	const expected = 获取UUID字节(uuid);
	if (!expected || data.byteLength < offset + 16) return false;
	for (let i = 0; i < 16; i++) {
		if (data[offset + i] !== expected[i]) return false;
	}
	return true;
}

export function 解析木马请求(buffer: ArrayBuffer | ArrayBufferView | Uint8Array, passwordPlainText: string): ParsedRequest {
	const data = 数据转Uint8Array(buffer);
	const sha224Password = sha224(passwordPlainText);
	if (data.byteLength < 58) return { hasError: true, message: 'invalid data' };
	const crLfIndex = 56;
	if (data[crLfIndex] !== 0x0d || data[crLfIndex + 1] !== 0x0a) return { hasError: true, message: 'invalid header format' };
	for (let i = 0; i < crLfIndex; i++) {
		if (data[i] !== sha224Password.charCodeAt(i)) return { hasError: true, message: 'invalid password' };
	}

	const socks5Index = crLfIndex + 2;
	if (data.byteLength < socks5Index + 6) return { hasError: true, message: 'invalid S5 request data' };

	const cmd = data[socks5Index];
	if (cmd !== 1 && cmd !== 3) return { hasError: true, message: 'unsupported command, only TCP/UDP is allowed' };
	const isUDP = cmd === 3;

	const atype = data[socks5Index + 1];
	let addressLength = 0;
	let addressIndex = socks5Index + 2;
	let address = '';
	switch (atype) {
		case 1:
			addressLength = 4;
			if (data.byteLength < addressIndex + addressLength + 4) return { hasError: true, message: 'invalid S5 request data' };
			address = `${data[addressIndex]}.${data[addressIndex + 1]}.${data[addressIndex + 2]}.${data[addressIndex + 3]}`;
			break;
		case 3: {
			if (data.byteLength < addressIndex + 1) return { hasError: true, message: 'invalid S5 request data' };
			addressLength = data[addressIndex];
			addressIndex += 1;
			if (data.byteLength < addressIndex + addressLength + 4) return { hasError: true, message: 'invalid S5 request data' };
			address = 木马文本解码器.decode(data.subarray(addressIndex, addressIndex + addressLength));
			break;
		}
		case 4: {
			addressLength = 16;
			if (data.byteLength < addressIndex + addressLength + 4) return { hasError: true, message: 'invalid S5 request data' };
			const ipv6: string[] = [];
			for (let i = 0; i < 8; i++) {
				const partIndex = addressIndex + i * 2;
				ipv6.push(((data[partIndex] << 8) | data[partIndex + 1]).toString(16));
			}
			address = ipv6.join(':');
			break;
		}
		default:
			return { hasError: true, message: `invalid addressType is ${atype}` };
	}

	if (!address) return { hasError: true, message: `address is empty, addressType is ${atype}` };

	const portIndex = addressIndex + addressLength;
	if (data.byteLength < portIndex + 4) return { hasError: true, message: 'invalid S5 request data' };
	const portRemote = (data[portIndex] << 8) | data[portIndex + 1];

	return {
		hasError: false,
		addressType: atype,
		port: portRemote,
		hostname: address,
		isUDP,
		rawClientData: data.subarray(portIndex + 4),
	};
}

export function 解析魏烈思请求(chunk: ArrayBuffer | ArrayBufferView | Uint8Array, token: string): ParsedRequest {
	const data = 数据转Uint8Array(chunk);
	const length = data.byteLength;
	if (length < 24) return { hasError: true, message: 'Invalid data' };
	const version = data[0];
	if (!UUID字节匹配(data, 1, token)) return { hasError: true, message: 'Invalid uuid' };

	const optLen = data[17];
	const cmdIndex = 18 + optLen;
	if (length < cmdIndex + 4) return { hasError: true, message: 'Invalid data' };

	const cmd = data[cmdIndex];
	let isUDP = false;
	if (cmd === 1) {
		// TCP
	} else if (cmd === 2) {
		isUDP = true;
	} else {
		return { hasError: true, message: 'Invalid command' };
	}

	const portIdx = cmdIndex + 1;
	const port = (data[portIdx] << 8) | data[portIdx + 1];
	let addrValIdx = portIdx + 3;
	let addrLen = 0;
	let hostname = '';
	const addressType = data[portIdx + 2];
	switch (addressType) {
		case 1:
			addrLen = 4;
			if (length < addrValIdx + addrLen) return { hasError: true, message: 'Invalid IPv4 address length' };
			hostname = `${data[addrValIdx]}.${data[addrValIdx + 1]}.${data[addrValIdx + 2]}.${data[addrValIdx + 3]}`;
			break;
		case 2:
			if (length < addrValIdx + 1) return { hasError: true, message: 'Invalid domain length' };
			addrLen = data[addrValIdx];
			addrValIdx += 1;
			if (length < addrValIdx + addrLen) return { hasError: true, message: 'Invalid domain data' };
			hostname = BLESS文本解码器.decode(data.subarray(addrValIdx, addrValIdx + addrLen));
			break;
		case 3: {
			addrLen = 16;
			if (length < addrValIdx + addrLen) return { hasError: true, message: 'Invalid IPv6 address length' };
			const ipv6: string[] = [];
			for (let i = 0; i < 8; i++) {
				const base = addrValIdx + i * 2;
				ipv6.push(((data[base] << 8) | data[base + 1]).toString(16));
			}
			hostname = ipv6.join(':');
			break;
		}
		default:
			return { hasError: true, message: `Invalid address type: ${addressType}` };
	}
	if (!hostname) return { hasError: true, message: `Invalid address: ${addressType}` };
	const rawIndex = addrValIdx + addrLen;
	return { hasError: false, addressType, port, hostname, isUDP, rawClientData: data.subarray(rawIndex), version };
}

export function 是有效WS早期数据(bytes: Uint8Array | null | undefined, token: string): boolean {
	if (!bytes?.byteLength) return false;
	if (bytes.byteLength >= 18 && UUID字节匹配(bytes, 1, token)) return true;
	if (bytes.byteLength < 58 || bytes[56] !== 0x0d || bytes[57] !== 0x0a) return false;

	const bbjanPassword = sha224(token);
	for (let i = 0; i < 56; i++) {
		if (bytes[i] !== bbjanPassword.charCodeAt(i)) return false;
	}
	return true;
}

export function 解码WS早期数据(header: string, token: string, 早期数据最大字节: number, 早期数据最大头长度: number): Uint8Array | null {
	if (!header) return null;
	if (header.length > 早期数据最大头长度) throw new Error('early data is too large');

	let bytes: Uint8Array | undefined;
	const FromBase64 = (Uint8Array as unknown as { fromBase64?: (s: string, opts: { alphabet: string }) => Uint8Array }).fromBase64;
	if (typeof FromBase64 === 'function') {
		try {
			bytes = FromBase64(header, { alphabet: 'base64url' });
		} catch {
			/* fall through */
		}
	}
	if (!bytes) {
		let normalized = header.replace(/-/g, '+').replace(/_/g, '/');
		const padding = normalized.length % 4;
		if (padding) normalized += '='.repeat(4 - padding);
		let binaryString: string;
		try {
			binaryString = atob(normalized);
		} catch {
			return null;
		}
		bytes = new Uint8Array(binaryString.length);
		for (let i = 0; i < binaryString.length; i++) bytes[i] = binaryString.charCodeAt(i);
	}

	if (bytes.byteLength > 早期数据最大字节) throw new Error('early data is too large');
	return 是有效WS早期数据(bytes, token) ? bytes : null;
}
