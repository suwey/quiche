// 简化版 TLS 1.2/1.3 客户端，原作: @Alexandre_Kojeve

import { 数据转Uint8Array } from './utils';
import type { TCPSocket } from './types';

const TLS_VERSION_10 = 769;
const TLS_VERSION_12 = 771;
const TLS_VERSION_13 = 772;
const CONTENT_TYPE_CHANGE_CIPHER_SPEC = 20;
const CONTENT_TYPE_ALERT = 21;
const CONTENT_TYPE_HANDSHAKE = 22;
const CONTENT_TYPE_APPLICATION_DATA = 23;
const HANDSHAKE_TYPE_CLIENT_HELLO = 1;
const HANDSHAKE_TYPE_SERVER_HELLO = 2;
const HANDSHAKE_TYPE_NEW_SESSION_TICKET = 4;
const HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS = 8;
const HANDSHAKE_TYPE_CERTIFICATE = 11;
const HANDSHAKE_TYPE_SERVER_KEY_EXCHANGE = 12;
const HANDSHAKE_TYPE_CERTIFICATE_REQUEST = 13;
const HANDSHAKE_TYPE_SERVER_HELLO_DONE = 14;
const HANDSHAKE_TYPE_CERTIFICATE_VERIFY = 15;
const HANDSHAKE_TYPE_CLIENT_KEY_EXCHANGE = 16;
const HANDSHAKE_TYPE_FINISHED = 20;
const HANDSHAKE_TYPE_KEY_UPDATE = 24;
const EXT_SERVER_NAME = 0;
const EXT_SUPPORTED_GROUPS = 10;
const EXT_EC_POINT_FORMATS = 11;
const EXT_SIGNATURE_ALGORITHMS = 13;
const EXT_APPLICATION_LAYER_PROTOCOL_NEGOTIATION = 16;
const EXT_SUPPORTED_VERSIONS = 43;
const EXT_PSK_KEY_EXCHANGE_MODES = 45;
const EXT_KEY_SHARE = 51;
const ALERT_CLOSE_NOTIFY = 0;
const ALERT_LEVEL_WARNING = 1;
const ALERT_UNRECOGNIZED_NAME = 112;
const TLS_MAX_PLAINTEXT_FRAGMENT = 16 * 1024;

const shouldIgnoreTlsAlert = (fragment: Uint8Array | undefined): boolean =>
	fragment?.[0] === ALERT_LEVEL_WARNING && fragment?.[1] === ALERT_UNRECOGNIZED_NAME;

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();
const EMPTY_BYTES = new Uint8Array(0);

interface CipherConfig {
	id: number;
	keyLen: number;
	ivLen: number;
	hash: string;
	tls13?: boolean;
	chacha?: boolean;
	kex?: string;
}

const CIPHER_SUITES_BY_ID: Record<number, CipherConfig> = {
	4865: { id: 4865, keyLen: 16, ivLen: 12, hash: 'SHA-256', tls13: true },
	4866: { id: 4866, keyLen: 32, ivLen: 12, hash: 'SHA-384', tls13: true },
	4867: { id: 4867, keyLen: 32, ivLen: 12, hash: 'SHA-256', tls13: true, chacha: true },
	49199: { id: 49199, keyLen: 16, ivLen: 4, hash: 'SHA-256', kex: 'ECDHE' },
	49200: { id: 49200, keyLen: 32, ivLen: 4, hash: 'SHA-384', kex: 'ECDHE' },
	52392: { id: 52392, keyLen: 32, ivLen: 12, hash: 'SHA-256', kex: 'ECDHE', chacha: true },
	49195: { id: 49195, keyLen: 16, ivLen: 4, hash: 'SHA-256', kex: 'ECDHE' },
	49196: { id: 49196, keyLen: 32, ivLen: 4, hash: 'SHA-384', kex: 'ECDHE' },
	52393: { id: 52393, keyLen: 32, ivLen: 12, hash: 'SHA-256', kex: 'ECDHE', chacha: true },
};
const GROUPS_BY_ID: Record<number, string> = {
	29: 'X25519',
	23: 'P-256',
};
const SUPPORTED_SIGNATURE_ALGORITHMS = [2052, 2053, 2054, 1025, 1281, 1537, 1027, 1283, 1539];

type TlsBytePart = number | number[] | Uint8Array | TlsBytePart[];

const flattenBytes = (values: TlsBytePart[]): number[] =>
	values.flatMap((value) =>
		value instanceof Uint8Array ? Array.from(value) : Array.isArray(value) ? flattenBytes(value) : typeof value === 'number' ? [value] : []
	);
const tlsBytes = (...parts: TlsBytePart[]): Uint8Array => new Uint8Array(flattenBytes(parts));
const uint16be = (value: number): number[] => [(value >> 8) & 255, 255 & value];
const readUint16 = (buffer: Uint8Array, offset: number): number => (buffer[offset] << 8) | buffer[offset + 1];
const readUint24 = (buffer: Uint8Array, offset: number): number => (buffer[offset] << 16) | (buffer[offset + 1] << 8) | buffer[offset + 2];
const concatBytes = (...chunks: Uint8Array[]): Uint8Array => {
	const nonEmpty = chunks.filter((c) => c && c.length > 0);
	const length = nonEmpty.reduce((t, c) => t + c.length, 0);
	const result = new Uint8Array(length);
	let offset = 0;
	for (const c of nonEmpty) {
		result.set(c, offset);
		offset += c.length;
	}
	return result;
};
const randomBytes = (length: number): Uint8Array => crypto.getRandomValues(new Uint8Array(length));
const constantTimeEqual = (left: Uint8Array, right: Uint8Array): boolean => {
	if (!left || !right || left.length !== right.length) return false;
	let diff = 0;
	for (let i = 0; i < left.length; i++) diff |= left[i] ^ right[i];
	return diff === 0;
};
const hashByteLength = (hash: string): number => (hash === 'SHA-512' ? 64 : hash === 'SHA-384' ? 48 : 32);
async function hmac(hash: string, key: Uint8Array, data: Uint8Array): Promise<Uint8Array> {
	const cryptoKey = await crypto.subtle.importKey('raw', key, { name: 'HMAC', hash }, false, ['sign']);
	return new Uint8Array(await crypto.subtle.sign('HMAC', cryptoKey, data));
}
async function digestBytes(hash: string, data: Uint8Array): Promise<Uint8Array> {
	return new Uint8Array(await crypto.subtle.digest(hash, data));
}
async function tls12Prf(secret: Uint8Array, label: string, seed: Uint8Array, length: number, hash = 'SHA-256'): Promise<Uint8Array> {
	const labelSeed = concatBytes(textEncoder.encode(label), seed);
	let output: Uint8Array = new Uint8Array(0);
	let currentA = labelSeed;
	while (output.length < length) {
		currentA = await hmac(hash, secret, currentA);
		const block = await hmac(hash, secret, concatBytes(currentA, labelSeed));
		output = concatBytes(output, block);
	}
	return output.slice(0, length);
}
async function hkdfExtract(hash: string, salt: Uint8Array | null, ikm: Uint8Array): Promise<Uint8Array> {
	const realSalt = salt && salt.length ? salt : new Uint8Array(hashByteLength(hash));
	return hmac(hash, realSalt, ikm);
}
async function hkdfExpandLabel(hash: string, secret: Uint8Array, label: string, context: Uint8Array, length: number): Promise<Uint8Array> {
	const fullLabel = textEncoder.encode('tls13 ' + label);
	const info = tlsBytes(uint16be(length), fullLabel.length, fullLabel, context.length, context);
	const hashLen = hashByteLength(hash);
	const roundCount = Math.ceil(length / hashLen);
	let output: Uint8Array = new Uint8Array(0);
	let previousBlock: Uint8Array = new Uint8Array(0);
	for (let round = 1; round <= roundCount; round++) {
		previousBlock = await hmac(hash, secret, concatBytes(previousBlock, info, new Uint8Array([round])));
		output = concatBytes(output, previousBlock);
	}
	return output.slice(0, length);
}

interface KeyShareGenerated {
	keyPair: CryptoKeyPair;
	publicKeyRaw: Uint8Array;
}

async function generateKeyShare(group = 'P-256'): Promise<KeyShareGenerated> {
	const algorithm = group === 'X25519' ? { name: 'X25519' } : { name: 'ECDH', namedCurve: group };
	const keyPair = (await crypto.subtle.generateKey(algorithm, true, ['deriveBits'])) as CryptoKeyPair;
	const publicKeyRaw = (await crypto.subtle.exportKey('raw', keyPair.publicKey)) as ArrayBuffer;
	return { keyPair, publicKeyRaw: new Uint8Array(publicKeyRaw) };
}
async function deriveSharedSecret(privateKey: CryptoKey, peerPublicKey: Uint8Array, group = 'P-256'): Promise<Uint8Array> {
	const algorithm = group === 'X25519' ? { name: 'X25519' } : { name: 'ECDH', namedCurve: group };
	const peerKey = await crypto.subtle.importKey('raw', peerPublicKey, algorithm, false, []);
	const bits = group === 'P-384' ? 384 : group === 'P-521' ? 528 : 256;
	return new Uint8Array(await crypto.subtle.deriveBits({ name: algorithm.name, public: peerKey } as unknown as { name: string; public: CryptoKey }, privateKey, bits));
}
type AesKeyUsage = 'encrypt' | 'decrypt' | 'sign' | 'verify' | 'deriveKey' | 'deriveBits' | 'wrapKey' | 'unwrapKey';
async function importAesGcmKey(key: Uint8Array, usages: AesKeyUsage[]): Promise<CryptoKey> {
	return crypto.subtle.importKey('raw', key, { name: 'AES-GCM' }, false, usages);
}
async function aesGcmEncryptWithKey(cryptoKey: CryptoKey, iv: Uint8Array, plaintext: Uint8Array, additionalData: Uint8Array): Promise<Uint8Array> {
	return new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData, tagLength: 128 }, cryptoKey, plaintext));
}
async function aesGcmDecryptWithKey(cryptoKey: CryptoKey, iv: Uint8Array, ciphertext: Uint8Array, additionalData: Uint8Array): Promise<Uint8Array> {
	return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv, additionalData, tagLength: 128 }, cryptoKey, ciphertext));
}

// --- ChaCha20-Poly1305 (软件实现，配合 cipher-suite 不强制 ChaCha 时绕过) ---
const rotateLeft32 = (value: number, bits: number): number => ((value << bits) | (value >>> (32 - bits))) >>> 0;
function chachaQuarterRound(state: Uint32Array, a: number, b: number, c: number, d: number): void {
	state[a] = (state[a] + state[b]) >>> 0;
	state[d] = rotateLeft32(state[d] ^ state[a], 16);
	state[c] = (state[c] + state[d]) >>> 0;
	state[b] = rotateLeft32(state[b] ^ state[c], 12);
	state[a] = (state[a] + state[b]) >>> 0;
	state[d] = rotateLeft32(state[d] ^ state[a], 8);
	state[c] = (state[c] + state[d]) >>> 0;
	state[b] = rotateLeft32(state[b] ^ state[c], 7);
}
function chacha20Block(key: Uint8Array, counter: number, nonce: Uint8Array): Uint8Array {
	const state = new Uint32Array(16);
	state[0] = 1634760805;
	state[1] = 857760878;
	state[2] = 2036477234;
	state[3] = 1797285236;
	const keyView = new DataView(key.buffer, key.byteOffset, key.byteLength);
	for (let i = 0; i < 8; i++) state[4 + i] = keyView.getUint32(4 * i, true);
	state[12] = counter;
	const nonceView = new DataView(nonce.buffer, nonce.byteOffset, nonce.byteLength);
	state[13] = nonceView.getUint32(0, true);
	state[14] = nonceView.getUint32(4, true);
	state[15] = nonceView.getUint32(8, true);
	const working = new Uint32Array(state);
	for (let r = 0; r < 10; r++) {
		chachaQuarterRound(working, 0, 4, 8, 12);
		chachaQuarterRound(working, 1, 5, 9, 13);
		chachaQuarterRound(working, 2, 6, 10, 14);
		chachaQuarterRound(working, 3, 7, 11, 15);
		chachaQuarterRound(working, 0, 5, 10, 15);
		chachaQuarterRound(working, 1, 6, 11, 12);
		chachaQuarterRound(working, 2, 7, 8, 13);
		chachaQuarterRound(working, 3, 4, 9, 14);
	}
	for (let i = 0; i < 16; i++) working[i] = (working[i] + state[i]) >>> 0;
	return new Uint8Array(working.buffer.slice(0));
}
function chacha20Xor(key: Uint8Array, nonce: Uint8Array, data: Uint8Array): Uint8Array {
	const output = new Uint8Array(data.length);
	let counter = 1;
	for (let offset = 0; offset < data.length; offset += 64) {
		const block = chacha20Block(key, counter++, nonce);
		const len = Math.min(64, data.length - offset);
		for (let i = 0; i < len; i++) output[offset + i] = data[offset + i] ^ block[i];
	}
	return output;
}
function poly1305Mac(key: Uint8Array, message: Uint8Array): Uint8Array {
	const rBytes = key.slice(0, 16);
	const clamped = new Uint8Array(rBytes);
	clamped[3] &= 15;
	clamped[7] &= 15;
	clamped[11] &= 15;
	clamped[15] &= 15;
	clamped[4] &= 252;
	clamped[8] &= 252;
	clamped[12] &= 252;
	const sKey = key.slice(16, 32);
	const accumulator: bigint[] = [0n, 0n, 0n, 0n, 0n];
	const rLimbs: bigint[] = [
		0x3ffffffn & BigInt(clamped[0] | (clamped[1] << 8) | (clamped[2] << 16) | (clamped[3] << 24)),
		0x3ffffffn & BigInt((clamped[3] >> 2) | (clamped[4] << 6) | (clamped[5] << 14) | (clamped[6] << 22)),
		0x3ffffffn & BigInt((clamped[6] >> 4) | (clamped[7] << 4) | (clamped[8] << 12) | (clamped[9] << 20)),
		0x3ffffffn & BigInt((clamped[9] >> 6) | (clamped[10] << 2) | (clamped[11] << 10) | (clamped[12] << 18)),
		0x3ffffffn & BigInt(clamped[13] | (clamped[14] << 8) | (clamped[15] << 16)),
	];
	for (let offset = 0; offset < message.length; offset += 16) {
		const chunk = message.slice(offset, offset + 16);
		const padded = new Uint8Array(17);
		padded.set(chunk);
		padded[chunk.length] = 1;
		accumulator[0] += BigInt(padded[0] | (padded[1] << 8) | (padded[2] << 16) | ((3 & padded[3]) << 24));
		accumulator[1] += BigInt((padded[3] >> 2) | (padded[4] << 6) | (padded[5] << 14) | ((15 & padded[6]) << 22));
		accumulator[2] += BigInt((padded[6] >> 4) | (padded[7] << 4) | (padded[8] << 12) | ((63 & padded[9]) << 20));
		accumulator[3] += BigInt((padded[9] >> 6) | (padded[10] << 2) | (padded[11] << 10) | (padded[12] << 18));
		accumulator[4] += BigInt(padded[13] | (padded[14] << 8) | (padded[15] << 16) | (padded[16] << 24));
		const product: bigint[] = [0n, 0n, 0n, 0n, 0n];
		for (let i = 0; i < 5; i++) {
			for (let j = 0; j < 5; j++) {
				const idx = i + j;
				if (idx < 5) product[idx] += accumulator[i] * rLimbs[j];
				else product[idx - 5] += accumulator[i] * rLimbs[j] * 5n;
			}
		}
		let carry = 0n;
		for (let i = 0; i < 5; i++) {
			product[i] += carry;
			accumulator[i] = 0x3ffffffn & product[i];
			carry = product[i] >> 26n;
		}
		accumulator[0] += 5n * carry;
		carry = accumulator[0] >> 26n;
		accumulator[0] &= 0x3ffffffn;
		accumulator[1] += carry;
	}
	let tagValue = accumulator[0] | (accumulator[1] << 26n) | (accumulator[2] << 52n) | (accumulator[3] << 78n) | (accumulator[4] << 104n);
	tagValue = (tagValue + sKey.reduce((total, byte, i) => total + (BigInt(byte) << BigInt(8 * i)), 0n)) & ((1n << 128n) - 1n);
	const tag = new Uint8Array(16);
	for (let i = 0; i < 16; i++) tag[i] = Number((tagValue >> BigInt(8 * i)) & 0xffn);
	return tag;
}
function chacha20Poly1305Encrypt(key: Uint8Array, nonce: Uint8Array, plaintext: Uint8Array, additionalData: Uint8Array): Uint8Array {
	const polyKey = chacha20Block(key, 0, nonce).slice(0, 32);
	const ciphertext = chacha20Xor(key, nonce, plaintext);
	const aadPad = (16 - (additionalData.length % 16)) % 16;
	const ctPad = (16 - (ciphertext.length % 16)) % 16;
	const macData = new Uint8Array(additionalData.length + aadPad + ciphertext.length + ctPad + 16);
	macData.set(additionalData, 0);
	macData.set(ciphertext, additionalData.length + aadPad);
	const lengthView = new DataView(macData.buffer, additionalData.length + aadPad + ciphertext.length + ctPad);
	lengthView.setBigUint64(0, BigInt(additionalData.length), true);
	lengthView.setBigUint64(8, BigInt(ciphertext.length), true);
	const tag = poly1305Mac(polyKey, macData);
	return concatBytes(ciphertext, tag);
}
function chacha20Poly1305Decrypt(key: Uint8Array, nonce: Uint8Array, ciphertext: Uint8Array, additionalData: Uint8Array): Uint8Array {
	if (ciphertext.length < 16) throw new Error('Ciphertext too short');
	const tag = ciphertext.slice(-16);
	const encryptedData = ciphertext.slice(0, -16);
	const polyKey = chacha20Block(key, 0, nonce).slice(0, 32);
	const aadPad = (16 - (additionalData.length % 16)) % 16;
	const ctPad = (16 - (encryptedData.length % 16)) % 16;
	const macData = new Uint8Array(additionalData.length + aadPad + encryptedData.length + ctPad + 16);
	macData.set(additionalData, 0);
	macData.set(encryptedData, additionalData.length + aadPad);
	const lengthView = new DataView(macData.buffer, additionalData.length + aadPad + encryptedData.length + ctPad);
	lengthView.setBigUint64(0, BigInt(additionalData.length), true);
	lengthView.setBigUint64(8, BigInt(encryptedData.length), true);
	const expectedTag = poly1305Mac(polyKey, macData);
	let diff = 0;
	for (let i = 0; i < 16; i++) diff |= tag[i] ^ expectedTag[i];
	if (diff !== 0) throw new Error('ChaCha20-Poly1305 authentication failed');
	return chacha20Xor(key, nonce, encryptedData);
}

function buildTlsRecord(contentType: number, fragment: Uint8Array | ArrayBuffer | ArrayBufferView, version = TLS_VERSION_12): Uint8Array {
	const data = 数据转Uint8Array(fragment);
	const record = new Uint8Array(5 + data.byteLength);
	record[0] = contentType;
	record[1] = (version >> 8) & 255;
	record[2] = version & 255;
	record[3] = (data.byteLength >> 8) & 255;
	record[4] = data.byteLength & 255;
	record.set(data, 5);
	return record;
}
function buildHandshakeMessage(handshakeType: number, body: Uint8Array): Uint8Array {
	return tlsBytes(handshakeType, [(body.length >> 16) & 255, (body.length >> 8) & 255, 255 & body.length], body);
}

interface TlsRecord {
	type: number;
	version: number;
	length: number;
	fragment: Uint8Array;
}

class TlsRecordParser {
	private buffer: Uint8Array = new Uint8Array(0);
	feed(chunk: Uint8Array | ArrayBuffer | ArrayBufferView): void {
		const bytes = 数据转Uint8Array(chunk);
		this.buffer = this.buffer.length ? concatBytes(this.buffer, bytes) : bytes;
	}
	next(): TlsRecord | null {
		if (this.buffer.length < 5) return null;
		const contentType = this.buffer[0];
		const version = readUint16(this.buffer, 1);
		const length = readUint16(this.buffer, 3);
		if (this.buffer.length < 5 + length) return null;
		const fragment = this.buffer.subarray(5, 5 + length);
		this.buffer = this.buffer.subarray(5 + length);
		return { type: contentType, version, length, fragment };
	}
}

interface HandshakeMessage {
	type: number;
	length: number;
	body: Uint8Array;
	raw: Uint8Array;
}

class TlsHandshakeParser {
	private buffer: Uint8Array = new Uint8Array(0);
	feed(chunk: Uint8Array): void {
		const bytes = 数据转Uint8Array(chunk);
		this.buffer = this.buffer.length ? concatBytes(this.buffer, bytes) : bytes;
	}
	next(): HandshakeMessage | null {
		if (this.buffer.length < 4) return null;
		const handshakeType = this.buffer[0];
		const length = readUint24(this.buffer, 1);
		if (this.buffer.length < 4 + length) return null;
		const body = this.buffer.subarray(4, 4 + length);
		const raw = this.buffer.subarray(0, 4 + length);
		this.buffer = this.buffer.subarray(4 + length);
		return { type: handshakeType, length, body, raw };
	}
}

interface ServerHelloParsed {
	version: number;
	serverRandom: Uint8Array;
	sessionId: Uint8Array;
	cipherSuite: number;
	compression: number;
	selectedVersion: number;
	keyShare: { group: number; key: Uint8Array } | null;
	alpn: string | null;
	isHRR: boolean;
	isTls13: boolean;
}

function parseServerHello(body: Uint8Array): ServerHelloParsed {
	let offset = 0;
	const legacyVersion = readUint16(body, offset);
	offset += 2;
	const serverRandom = body.slice(offset, offset + 32);
	offset += 32;
	const sessionIdLength = body[offset++];
	const sessionId = body.slice(offset, offset + sessionIdLength);
	offset += sessionIdLength;
	const cipherSuite = readUint16(body, offset);
	offset += 2;
	const compression = body[offset++];
	let selectedVersion = legacyVersion;
	let keyShare: { group: number; key: Uint8Array } | null = null;
	let alpn: string | null = null;
	if (offset < body.length) {
		const extensionsLength = readUint16(body, offset);
		offset += 2;
		const extensionsEnd = offset + extensionsLength;
		while (offset + 4 <= extensionsEnd) {
			const extType = readUint16(body, offset);
			offset += 2;
			const extLen = readUint16(body, offset);
			offset += 2;
			const extData = body.slice(offset, offset + extLen);
			offset += extLen;
			if (extType === EXT_SUPPORTED_VERSIONS && extLen >= 2) selectedVersion = readUint16(extData, 0);
			else if (extType === EXT_KEY_SHARE && extLen >= 4) {
				const group = readUint16(extData, 0);
				const keyLength = readUint16(extData, 2);
				keyShare = { group, key: extData.slice(4, 4 + keyLength) };
			} else if (extType === EXT_APPLICATION_LAYER_PROTOCOL_NEGOTIATION && extLen >= 3) {
				alpn = textDecoder.decode(extData.slice(3, 3 + extData[2]));
			}
		}
	}
	const helloRetryRequestRandom = new Uint8Array([207, 33, 173, 116, 229, 154, 97, 17, 190, 29, 140, 2, 30, 101, 184, 145, 194, 162, 17, 22, 122, 187, 140, 94, 7, 158, 9, 226, 200, 168, 51, 156]);
	return {
		version: legacyVersion,
		serverRandom,
		sessionId,
		cipherSuite,
		compression,
		selectedVersion,
		keyShare,
		alpn,
		isHRR: constantTimeEqual(serverRandom, helloRetryRequestRandom),
		isTls13: selectedVersion === TLS_VERSION_13,
	};
}

interface ServerKeyExchangeParsed {
	namedCurve: number;
	serverPublicKey: Uint8Array;
}

function parseServerKeyExchange(body: Uint8Array): ServerKeyExchangeParsed {
	let offset = 1;
	const namedCurve = readUint16(body, offset);
	offset += 2;
	const keyLength = body[offset++];
	return { namedCurve, serverPublicKey: body.slice(offset, offset + keyLength) };
}

function extractLeafCertificate(body: Uint8Array, hasContext = 0): Uint8Array | null {
	let offset = 0;
	if (hasContext) {
		const ctxLen = body[offset++];
		offset += ctxLen;
	}
	if (offset + 3 > body.length) return null;
	const certificateListLength = readUint24(body, offset);
	offset += 3;
	if (!certificateListLength || offset + 3 > body.length) return null;
	const certificateLength = readUint24(body, offset);
	offset += 3;
	return certificateLength ? body.slice(offset, offset + certificateLength) : null;
}

function parseEncryptedExtensions(body: Uint8Array): { alpn: string | null } {
	const parsed: { alpn: string | null } = { alpn: null };
	let offset = 2;
	const extEnd = 2 + readUint16(body, 0);
	while (offset + 4 <= extEnd) {
		const extType = readUint16(body, offset);
		offset += 2;
		const extLen = readUint16(body, offset);
		offset += 2;
		if (extType === EXT_APPLICATION_LAYER_PROTOCOL_NEGOTIATION && extLen >= 3) {
			const protocolLength = body[offset + 2];
			if (protocolLength > 0 && offset + 3 + protocolLength <= offset + extLen) {
				parsed.alpn = textDecoder.decode(body.slice(offset + 3, offset + 3 + protocolLength));
			}
		}
		offset += extLen;
	}
	return parsed;
}

interface ClientHelloOptions {
	tls13?: boolean;
	tls12?: boolean;
	alpn?: string | string[] | null;
	chacha?: boolean;
}

function buildClientHello(
	clientRandom: Uint8Array,
	serverName: string,
	keyShares: { x25519?: Uint8Array; p256?: Uint8Array } | Uint8Array,
	{ tls13: enableTls13 = true, tls12: enableTls12 = true, alpn = null, chacha = true }: ClientHelloOptions = {}
): Uint8Array {
	const cipherIds: number[] = [];
	if (enableTls13) cipherIds.push(4865, 4866, ...(chacha ? [4867] : []));
	if (enableTls12) cipherIds.push(49199, 49200, 49195, 49196, ...(chacha ? [52392, 52393] : []));
	const cipherBytes = tlsBytes(...cipherIds.flatMap(uint16be));
	const extensions: Uint8Array[] = [tlsBytes(255, 1, 0, 1, 0)];
	if (serverName) {
		const sniBytes = textEncoder.encode(serverName);
		const sniList = tlsBytes(0, uint16be(sniBytes.length), sniBytes);
		extensions.push(tlsBytes(uint16be(EXT_SERVER_NAME), uint16be(sniList.length + 2), uint16be(sniList.length), sniList));
	}
	extensions.push(tlsBytes(uint16be(EXT_EC_POINT_FORMATS), 0, 2, 1, 0));
	extensions.push(tlsBytes(uint16be(EXT_SUPPORTED_GROUPS), 0, 6, 0, 4, 0, 29, 0, 23));
	const sigBytes = tlsBytes(...SUPPORTED_SIGNATURE_ALGORITHMS.flatMap(uint16be));
	extensions.push(tlsBytes(uint16be(EXT_SIGNATURE_ALGORITHMS), uint16be(sigBytes.length + 2), uint16be(sigBytes.length), sigBytes));
	const protocols = Array.isArray(alpn) ? alpn.filter(Boolean) : alpn ? [alpn] : [];
	if (protocols.length) {
		const alpnBytes = concatBytes(
			...protocols.map((p) => {
				const bytes = textEncoder.encode(p);
				return tlsBytes(bytes.length, bytes);
			})
		);
		extensions.push(tlsBytes(uint16be(EXT_APPLICATION_LAYER_PROTOCOL_NEGOTIATION), uint16be(alpnBytes.length + 2), uint16be(alpnBytes.length), alpnBytes));
	}
	if (enableTls13 && keyShares) {
		extensions.push(enableTls12 ? tlsBytes(uint16be(EXT_SUPPORTED_VERSIONS), 0, 5, 4, 3, 4, 3, 3) : tlsBytes(uint16be(EXT_SUPPORTED_VERSIONS), 0, 3, 2, 3, 4));
		extensions.push(tlsBytes(uint16be(EXT_PSK_KEY_EXCHANGE_MODES), 0, 2, 1, 1));
		let keyShareBytes: Uint8Array;
		const dual = keyShares as { x25519?: Uint8Array; p256?: Uint8Array };
		if (dual.x25519 && dual.p256) {
			keyShareBytes = concatBytes(tlsBytes(0, 29, uint16be(dual.x25519.length), dual.x25519), tlsBytes(0, 23, uint16be(dual.p256.length), dual.p256));
		} else if (dual.x25519) keyShareBytes = tlsBytes(0, 29, uint16be(dual.x25519.length), dual.x25519);
		else if (dual.p256) keyShareBytes = tlsBytes(0, 23, uint16be(dual.p256.length), dual.p256);
		else if (keyShares instanceof Uint8Array) keyShareBytes = tlsBytes(0, 23, uint16be(keyShares.length), keyShares);
		else throw new Error('Invalid keyShares');
		extensions.push(tlsBytes(uint16be(EXT_KEY_SHARE), uint16be(keyShareBytes.length + 2), uint16be(keyShareBytes.length), keyShareBytes));
	}
	const extensionsBytes = concatBytes(...extensions);
	return buildHandshakeMessage(
		HANDSHAKE_TYPE_CLIENT_HELLO,
		tlsBytes(uint16be(TLS_VERSION_12), clientRandom, 0, uint16be(cipherBytes.length), cipherBytes, 1, 0, uint16be(extensionsBytes.length), extensionsBytes)
	);
}

const uint64be = (sequenceNumber: bigint): Uint8Array => {
	const bytes = new Uint8Array(8);
	new DataView(bytes.buffer).setBigUint64(0, sequenceNumber, false);
	return bytes;
};
const xorSequenceIntoIv = (iv: Uint8Array, seq: bigint): Uint8Array => {
	const nonce = iv.slice();
	const seqBytes = uint64be(seq);
	for (let i = 0; i < 8; i++) nonce[nonce.length - 8 + i] ^= seqBytes[i];
	return nonce;
};
const deriveTrafficKeys = (hash: string, secret: Uint8Array, keyLen: number, ivLen: number): Promise<[Uint8Array, Uint8Array]> =>
	Promise.all([hkdfExpandLabel(hash, secret, 'key', EMPTY_BYTES, keyLen), hkdfExpandLabel(hash, secret, 'iv', EMPTY_BYTES, ivLen)]);

export interface TlsClientOptions {
	serverName?: string;
	tls13?: boolean;
	tls12?: boolean;
	alpn?: string | string[] | null;
	allowChacha?: boolean;
	insecure?: boolean;
	timeout?: number;
}

export class TlsClient {
	socket: TCPSocket;
	serverName: string;
	supportTls13: boolean;
	supportTls12: boolean;
	alpnProtocols: string[] | null;
	allowChacha: boolean;
	timeout: number;
	clientRandom: Uint8Array;
	serverRandom: Uint8Array | null = null;
	private handshakeChunks: Uint8Array[] = [];
	handshakeComplete = false;
	negotiatedAlpn: string | null = null;
	cipherSuite: number | null = null;
	cipherConfig: CipherConfig | null = null;
	isTls13 = false;
	private masterSecret: Uint8Array | null = null;
	private handshakeSecret: Uint8Array | null = null;
	private clientWriteKey: Uint8Array | null = null;
	private serverWriteKey: Uint8Array | null = null;
	private clientWriteIv: Uint8Array | null = null;
	private serverWriteIv: Uint8Array | null = null;
	private clientHandshakeKey: Uint8Array | null = null;
	private serverHandshakeKey: Uint8Array | null = null;
	private clientHandshakeIv: Uint8Array | null = null;
	private serverHandshakeIv: Uint8Array | null = null;
	private clientAppKey: Uint8Array | null = null;
	private serverAppKey: Uint8Array | null = null;
	private clientAppIv: Uint8Array | null = null;
	private serverAppIv: Uint8Array | null = null;
	private clientWriteCryptoKey: CryptoKey | null = null;
	private serverWriteCryptoKey: CryptoKey | null = null;
	private clientHandshakeCryptoKey: CryptoKey | null = null;
	private serverHandshakeCryptoKey: CryptoKey | null = null;
	private clientAppCryptoKey: CryptoKey | null = null;
	private serverAppCryptoKey: CryptoKey | null = null;
	private clientSeqNum = 0n;
	private serverSeqNum = 0n;
	private recordParser = new TlsRecordParser();
	private handshakeParser = new TlsHandshakeParser();
	private keyPairs = new Map<number, KeyShareGenerated>();
	private ecdhKeyPair: CryptoKeyPair | null = null;
	private sawCert = false;

	constructor(socket: TCPSocket, options: TlsClientOptions = {}) {
		this.socket = socket;
		this.serverName = options.serverName || '';
		this.supportTls13 = options.tls13 !== false;
		this.supportTls12 = options.tls12 !== false;
		if (!this.supportTls13 && !this.supportTls12) throw new Error('At least one TLS version must be enabled');
		this.alpnProtocols = Array.isArray(options.alpn) ? options.alpn : options.alpn ? [options.alpn] : null;
		this.allowChacha = options.allowChacha !== false;
		this.timeout = options.timeout ?? 30_000;
		this.clientRandom = randomBytes(32);
	}

	private recordHandshake(chunk: Uint8Array): void {
		this.handshakeChunks.push(chunk);
	}
	private transcript(): Uint8Array {
		return this.handshakeChunks.length === 1 ? this.handshakeChunks[0] : concatBytes(...this.handshakeChunks);
	}
	private getCipherConfig(cipherSuite: number): CipherConfig | null {
		return CIPHER_SUITES_BY_ID[cipherSuite] ?? null;
	}
	private async readChunk(reader: ReadableStreamDefaultReader<Uint8Array>): Promise<ReadableStreamReadResult<Uint8Array>> {
		if (!this.timeout) return reader.read();
		return Promise.race([
			reader.read(),
			new Promise<never>((_, reject) => setTimeout(() => reject(new Error('TLS read timeout')), this.timeout)),
		]);
	}
	private async readRecordsUntil(
		reader: ReadableStreamDefaultReader<Uint8Array>,
		predicate: (record: TlsRecord) => Promise<boolean | void> | boolean | void,
		closedError: string
	): Promise<void> {
		for (;;) {
			let record: TlsRecord | null;
			while ((record = this.recordParser.next())) {
				if (await predicate(record)) return;
			}
			const { value, done } = await this.readChunk(reader);
			if (done) throw new Error(closedError);
			this.recordParser.feed(value);
		}
	}
	private async readHandshakeUntil(
		reader: ReadableStreamDefaultReader<Uint8Array>,
		predicate: (message: HandshakeMessage) => Promise<boolean | void> | boolean | void,
		closedError: string
	): Promise<void> {
		let message: HandshakeMessage | null;
		while ((message = this.handshakeParser.next())) {
			if (await predicate(message)) return;
		}
		await this.readRecordsUntil(reader, async (record) => {
			if (record.type === CONTENT_TYPE_ALERT) {
				if (shouldIgnoreTlsAlert(record.fragment)) return;
				throw new Error(`TLS Alert: ${record.fragment[1]}`);
			}
			if (record.type === CONTENT_TYPE_HANDSHAKE) {
				this.handshakeParser.feed(record.fragment);
				let m: HandshakeMessage | null;
				while ((m = this.handshakeParser.next())) {
					if (await predicate(m)) return true;
				}
			}
		}, closedError);
	}
	private async acceptCertificate(certificate: Uint8Array | null): Promise<void> {
		if (!certificate?.length) throw new Error('Empty certificate');
		this.sawCert = true;
	}

	async handshake(): Promise<void> {
		const [p256Share, x25519Share] = await Promise.all([generateKeyShare('P-256'), generateKeyShare('X25519')]);
		this.keyPairs = new Map([
			[23, p256Share],
			[29, x25519Share],
		]);
		this.ecdhKeyPair = p256Share.keyPair;
		const reader = this.socket.readable.getReader();
		const writer = this.socket.writable.getWriter();
		try {
			const clientHello = buildClientHello(this.clientRandom, this.serverName, { x25519: x25519Share.publicKeyRaw, p256: p256Share.publicKeyRaw }, {
				tls13: this.supportTls13,
				tls12: this.supportTls12,
				alpn: this.alpnProtocols,
				chacha: this.allowChacha,
			});
			this.recordHandshake(clientHello);
			await writer.write(buildTlsRecord(CONTENT_TYPE_HANDSHAKE, clientHello, TLS_VERSION_10));
			const serverHello = await this.receiveServerHello(reader);
			if (serverHello.isHRR) throw new Error('HelloRetryRequest is not supported by TLSClientMini');
			if (serverHello.keyShare?.group && this.keyPairs.has(serverHello.keyShare.group)) {
				const selected = this.keyPairs.get(serverHello.keyShare.group);
				if (selected) this.ecdhKeyPair = selected.keyPair;
			}
			if (serverHello.isTls13) await this.handshakeTls13(reader, writer, serverHello);
			else await this.handshakeTls12(reader, writer);
			this.handshakeComplete = true;
		} finally {
			reader.releaseLock();
			writer.releaseLock();
		}
	}

	private async receiveServerHello(reader: ReadableStreamDefaultReader<Uint8Array>): Promise<ServerHelloParsed> {
		for (;;) {
			const { value, done } = await this.readChunk(reader);
			if (done) throw new Error('Connection closed waiting for ServerHello');
			this.recordParser.feed(value);
			let record: TlsRecord | null;
			while ((record = this.recordParser.next())) {
				if (record.type === CONTENT_TYPE_ALERT) {
					if (shouldIgnoreTlsAlert(record.fragment)) continue;
					throw new Error(`TLS Alert: level=${record.fragment[0]}, desc=${record.fragment[1]}`);
				}
				if (record.type !== CONTENT_TYPE_HANDSHAKE) continue;
				this.handshakeParser.feed(record.fragment);
				let message: HandshakeMessage | null;
				while ((message = this.handshakeParser.next())) {
					if (message.type !== HANDSHAKE_TYPE_SERVER_HELLO) continue;
					this.recordHandshake(message.raw);
					const sh = parseServerHello(message.body);
					this.serverRandom = sh.serverRandom;
					this.cipherSuite = sh.cipherSuite;
					this.cipherConfig = this.getCipherConfig(sh.cipherSuite);
					this.isTls13 = sh.isTls13;
					this.negotiatedAlpn = sh.alpn || null;
					if (!this.cipherConfig) throw new Error(`Unsupported cipher suite: 0x${sh.cipherSuite.toString(16)}`);
					return sh;
				}
			}
		}
	}

	private async handshakeTls12(reader: ReadableStreamDefaultReader<Uint8Array>, writer: WritableStreamDefaultWriter<Uint8Array>): Promise<void> {
		let serverKeyExchange: ServerKeyExchangeParsed | null = null;
		let sawServerHelloDone = false;
		await this.readHandshakeUntil(reader, async (message) => {
			switch (message.type) {
				case HANDSHAKE_TYPE_CERTIFICATE: {
					this.recordHandshake(message.raw);
					const cert = extractLeafCertificate(message.body, 1);
					if (!cert) throw new Error('Missing TLS 1.2 certificate');
					await this.acceptCertificate(cert);
					break;
				}
				case HANDSHAKE_TYPE_SERVER_KEY_EXCHANGE:
					this.recordHandshake(message.raw);
					serverKeyExchange = parseServerKeyExchange(message.body);
					break;
				case HANDSHAKE_TYPE_SERVER_HELLO_DONE:
					this.recordHandshake(message.raw);
					sawServerHelloDone = true;
					return true;
				case HANDSHAKE_TYPE_CERTIFICATE_REQUEST:
					throw new Error('Client certificate is not supported');
				default:
					this.recordHandshake(message.raw);
			}
		}, 'Connection closed during TLS 1.2 handshake');
		void sawServerHelloDone;
		if (!this.sawCert) throw new Error('Missing TLS 1.2 leaf certificate');
		if (!serverKeyExchange) throw new Error('Missing TLS 1.2 ServerKeyExchange');
		const ske: ServerKeyExchangeParsed = serverKeyExchange;
		const curveName = GROUPS_BY_ID[ske.namedCurve];
		if (!curveName) throw new Error(`Unsupported named curve: 0x${ske.namedCurve.toString(16)}`);
		const keyShare = this.keyPairs.get(ske.namedCurve);
		if (!keyShare) throw new Error(`Missing key pair for curve: 0x${ske.namedCurve.toString(16)}`);
		const preMaster = await deriveSharedSecret(keyShare.keyPair.privateKey, ske.serverPublicKey, curveName);
		const cke = buildHandshakeMessage(HANDSHAKE_TYPE_CLIENT_KEY_EXCHANGE, tlsBytes(keyShare.publicKeyRaw.length, keyShare.publicKeyRaw));
		this.recordHandshake(cke);
		const cfg = this.cipherConfig;
		if (!cfg || !this.serverRandom) throw new Error('TLS 1.2 missing parameters');
		const hashName = cfg.hash;
		this.masterSecret = await tls12Prf(preMaster, 'master secret', concatBytes(this.clientRandom, this.serverRandom), 48, hashName);
		const keyLen = cfg.keyLen;
		const ivLen = cfg.ivLen;
		const keyBlock = await tls12Prf(this.masterSecret, 'key expansion', concatBytes(this.serverRandom, this.clientRandom), 2 * keyLen + 2 * ivLen, hashName);
		this.clientWriteKey = keyBlock.slice(0, keyLen);
		this.serverWriteKey = keyBlock.slice(keyLen, 2 * keyLen);
		this.clientWriteIv = keyBlock.slice(2 * keyLen, 2 * keyLen + ivLen);
		this.serverWriteIv = keyBlock.slice(2 * keyLen + ivLen, 2 * keyLen + 2 * ivLen);
		if (!cfg.chacha) {
			[this.clientWriteCryptoKey, this.serverWriteCryptoKey] = await Promise.all([importAesGcmKey(this.clientWriteKey, ['encrypt']), importAesGcmKey(this.serverWriteKey, ['decrypt'])]);
		}
		await writer.write(buildTlsRecord(CONTENT_TYPE_HANDSHAKE, cke));
		await writer.write(buildTlsRecord(CONTENT_TYPE_CHANGE_CIPHER_SPEC, tlsBytes(1)));
		const verifyData = await tls12Prf(this.masterSecret, 'client finished', await digestBytes(hashName, this.transcript()), 12, hashName);
		const finished = buildHandshakeMessage(HANDSHAKE_TYPE_FINISHED, verifyData);
		this.recordHandshake(finished);
		await writer.write(buildTlsRecord(CONTENT_TYPE_HANDSHAKE, await this.encryptTls12(finished, CONTENT_TYPE_HANDSHAKE)));
		let sawCcs = false;
		await this.readRecordsUntil(reader, async (record) => {
			if (record.type === CONTENT_TYPE_ALERT) {
				if (shouldIgnoreTlsAlert(record.fragment)) return;
				throw new Error(`TLS Alert: ${record.fragment[1]}`);
			}
			if (record.type === CONTENT_TYPE_CHANGE_CIPHER_SPEC) {
				sawCcs = true;
				return;
			}
			if (record.type !== CONTENT_TYPE_HANDSHAKE || !sawCcs) return;
			const decrypted = await this.decryptTls12(record.fragment, CONTENT_TYPE_HANDSHAKE);
			if (decrypted[0] !== HANDSHAKE_TYPE_FINISHED) return;
			const verifyLength = readUint24(decrypted, 1);
			const serverVerify = decrypted.slice(4, 4 + verifyLength);
			if (!this.masterSecret) throw new Error('TLS 1.2 missing master secret');
			const expected = await tls12Prf(this.masterSecret, 'server finished', await digestBytes(hashName, this.transcript()), 12, hashName);
			if (!constantTimeEqual(serverVerify, expected)) throw new Error('TLS 1.2 server Finished verify failed');
			return true;
		}, 'Connection closed waiting for TLS 1.2 Finished');
	}

	private async handshakeTls13(reader: ReadableStreamDefaultReader<Uint8Array>, writer: WritableStreamDefaultWriter<Uint8Array>, serverHello: ServerHelloParsed): Promise<void> {
		const groupName = serverHello.keyShare?.group !== undefined ? GROUPS_BY_ID[serverHello.keyShare.group] : undefined;
		if (!groupName || !serverHello.keyShare?.key?.length) throw new Error('Missing TLS 1.3 key_share');
		const cfg = this.cipherConfig;
		if (!cfg || !this.ecdhKeyPair) throw new Error('TLS 1.3 missing parameters');
		const hashName = cfg.hash;
		const hashLen = hashByteLength(hashName);
		const keyLen = cfg.keyLen;
		const ivLen = cfg.ivLen;
		const sharedSecret = await deriveSharedSecret(this.ecdhKeyPair.privateKey, serverHello.keyShare.key, groupName);
		const earlySecret = await hkdfExtract(hashName, null, new Uint8Array(hashLen));
		const derivedSecret = await hkdfExpandLabel(hashName, earlySecret, 'derived', await digestBytes(hashName, EMPTY_BYTES), hashLen);
		this.handshakeSecret = await hkdfExtract(hashName, derivedSecret, sharedSecret);
		const transcriptHash = await digestBytes(hashName, this.transcript());
		const cHsTraffic = await hkdfExpandLabel(hashName, this.handshakeSecret, 'c hs traffic', transcriptHash, hashLen);
		const sHsTraffic = await hkdfExpandLabel(hashName, this.handshakeSecret, 's hs traffic', transcriptHash, hashLen);
		[this.clientHandshakeKey, this.clientHandshakeIv] = await deriveTrafficKeys(hashName, cHsTraffic, keyLen, ivLen);
		[this.serverHandshakeKey, this.serverHandshakeIv] = await deriveTrafficKeys(hashName, sHsTraffic, keyLen, ivLen);
		if (!cfg.chacha) {
			[this.clientHandshakeCryptoKey, this.serverHandshakeCryptoKey] = await Promise.all([importAesGcmKey(this.clientHandshakeKey, ['encrypt']), importAesGcmKey(this.serverHandshakeKey, ['decrypt'])]);
		}
		const serverFinishedKey = await hkdfExpandLabel(hashName, sHsTraffic, 'finished', EMPTY_BYTES, hashLen);
		let serverFinishedReceived = false;
		const handleHandshakeMessage = async (message: HandshakeMessage): Promise<void> => {
			switch (message.type) {
				case HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS: {
					const ee = parseEncryptedExtensions(message.body);
					if (ee.alpn) this.negotiatedAlpn = ee.alpn;
					this.recordHandshake(message.raw);
					break;
				}
				case HANDSHAKE_TYPE_CERTIFICATE: {
					const cert = extractLeafCertificate(message.body);
					if (!cert) throw new Error('Missing TLS 1.3 certificate');
					await this.acceptCertificate(cert);
					this.recordHandshake(message.raw);
					break;
				}
				case HANDSHAKE_TYPE_CERTIFICATE_REQUEST:
					throw new Error('Client certificate is not supported');
				case HANDSHAKE_TYPE_CERTIFICATE_VERIFY:
					this.recordHandshake(message.raw);
					break;
				case HANDSHAKE_TYPE_FINISHED: {
					const expected = await hmac(hashName, serverFinishedKey, await digestBytes(hashName, this.transcript()));
					if (!constantTimeEqual(expected, message.body)) throw new Error('TLS 1.3 server Finished verify failed');
					this.recordHandshake(message.raw);
					serverFinishedReceived = true;
					break;
				}
				default:
					this.recordHandshake(message.raw);
			}
		};
		await this.readRecordsUntil(reader, async (record) => {
			if (record.type === CONTENT_TYPE_CHANGE_CIPHER_SPEC || record.type === CONTENT_TYPE_HANDSHAKE) return;
			if (record.type === CONTENT_TYPE_ALERT) {
				if (shouldIgnoreTlsAlert(record.fragment)) return;
				throw new Error(`TLS Alert: ${record.fragment[1]}`);
			}
			if (record.type !== CONTENT_TYPE_APPLICATION_DATA) return;
			const decrypted = await this.decryptTls13Handshake(record.fragment);
			const innerType = decrypted[decrypted.length - 1];
			const plaintext = decrypted.slice(0, -1);
			if (innerType !== CONTENT_TYPE_HANDSHAKE) return;
			this.handshakeParser.feed(plaintext);
			let m: HandshakeMessage | null;
			while ((m = this.handshakeParser.next())) {
				await handleHandshakeMessage(m);
				if (serverFinishedReceived) return true;
			}
		}, 'Connection closed during TLS 1.3 handshake');
		const appTranscriptHash = await digestBytes(hashName, this.transcript());
		const masterDerived = await hkdfExpandLabel(hashName, this.handshakeSecret, 'derived', await digestBytes(hashName, EMPTY_BYTES), hashLen);
		const masterSecret = await hkdfExtract(hashName, masterDerived, new Uint8Array(hashLen));
		const cAp = await hkdfExpandLabel(hashName, masterSecret, 'c ap traffic', appTranscriptHash, hashLen);
		const sAp = await hkdfExpandLabel(hashName, masterSecret, 's ap traffic', appTranscriptHash, hashLen);
		[this.clientAppKey, this.clientAppIv] = await deriveTrafficKeys(hashName, cAp, keyLen, ivLen);
		[this.serverAppKey, this.serverAppIv] = await deriveTrafficKeys(hashName, sAp, keyLen, ivLen);
		if (!cfg.chacha) {
			[this.clientAppCryptoKey, this.serverAppCryptoKey] = await Promise.all([importAesGcmKey(this.clientAppKey, ['encrypt']), importAesGcmKey(this.serverAppKey, ['decrypt'])]);
		}
		const clientFinishedKey = await hkdfExpandLabel(hashName, cHsTraffic, 'finished', EMPTY_BYTES, hashLen);
		const clientVerify = await hmac(hashName, clientFinishedKey, await digestBytes(hashName, this.transcript()));
		const clientFinishedMessage = buildHandshakeMessage(HANDSHAKE_TYPE_FINISHED, clientVerify);
		this.recordHandshake(clientFinishedMessage);
		await writer.write(buildTlsRecord(CONTENT_TYPE_APPLICATION_DATA, await this.encryptTls13Handshake(concatBytes(clientFinishedMessage, new Uint8Array([CONTENT_TYPE_HANDSHAKE])))));
		this.clientSeqNum = 0n;
		this.serverSeqNum = 0n;
	}

	private async encryptTls12(plaintext: Uint8Array, contentType: number): Promise<Uint8Array> {
		const cfg = this.cipherConfig;
		if (!cfg || !this.clientWriteIv || !this.clientWriteKey) throw new Error('TLS 1.2 not initialized');
		const seq = this.clientSeqNum++;
		const seqBytes = uint64be(seq);
		const aad = concatBytes(seqBytes, new Uint8Array([contentType]), new Uint8Array(uint16be(TLS_VERSION_12)), new Uint8Array(uint16be(plaintext.length)));
		if (cfg.chacha) {
			const nonce = xorSequenceIntoIv(this.clientWriteIv, seq);
			return chacha20Poly1305Encrypt(this.clientWriteKey, nonce, plaintext, aad);
		}
		const explicit = randomBytes(8);
		this.clientWriteCryptoKey ||= await importAesGcmKey(this.clientWriteKey, ['encrypt']);
		return concatBytes(explicit, await aesGcmEncryptWithKey(this.clientWriteCryptoKey, concatBytes(this.clientWriteIv, explicit), plaintext, aad));
	}
	private async decryptTls12(ciphertext: Uint8Array, contentType: number): Promise<Uint8Array> {
		const cfg = this.cipherConfig;
		if (!cfg || !this.serverWriteIv || !this.serverWriteKey) throw new Error('TLS 1.2 not initialized');
		const seq = this.serverSeqNum++;
		const seqBytes = uint64be(seq);
		if (cfg.chacha) {
			const nonce = xorSequenceIntoIv(this.serverWriteIv, seq);
			return chacha20Poly1305Decrypt(
				this.serverWriteKey,
				nonce,
				ciphertext,
				concatBytes(seqBytes, new Uint8Array([contentType]), new Uint8Array(uint16be(TLS_VERSION_12)), new Uint8Array(uint16be(ciphertext.length - 16)))
			);
		}
		const explicit = ciphertext.subarray(0, 8);
		const encryptedData = ciphertext.subarray(8);
		this.serverWriteCryptoKey ||= await importAesGcmKey(this.serverWriteKey, ['decrypt']);
		return aesGcmDecryptWithKey(
			this.serverWriteCryptoKey,
			concatBytes(this.serverWriteIv, explicit),
			encryptedData,
			concatBytes(seqBytes, new Uint8Array([contentType]), new Uint8Array(uint16be(TLS_VERSION_12)), new Uint8Array(uint16be(encryptedData.length - 16)))
		);
	}
	private async encryptTls13Handshake(plaintext: Uint8Array): Promise<Uint8Array> {
		const cfg = this.cipherConfig;
		if (!cfg || !this.clientHandshakeIv || !this.clientHandshakeKey) throw new Error('TLS 1.3 not initialized');
		const nonce = xorSequenceIntoIv(this.clientHandshakeIv, this.clientSeqNum++);
		const aad = tlsBytes(CONTENT_TYPE_APPLICATION_DATA, 3, 3, uint16be(plaintext.length + 16));
		if (cfg.chacha) return chacha20Poly1305Encrypt(this.clientHandshakeKey, nonce, plaintext, aad);
		this.clientHandshakeCryptoKey ||= await importAesGcmKey(this.clientHandshakeKey, ['encrypt']);
		return aesGcmEncryptWithKey(this.clientHandshakeCryptoKey, nonce, plaintext, aad);
	}
	private async decryptTls13Handshake(ciphertext: Uint8Array): Promise<Uint8Array> {
		const cfg = this.cipherConfig;
		if (!cfg || !this.serverHandshakeIv || !this.serverHandshakeKey) throw new Error('TLS 1.3 not initialized');
		const nonce = xorSequenceIntoIv(this.serverHandshakeIv, this.serverSeqNum++);
		const aad = tlsBytes(CONTENT_TYPE_APPLICATION_DATA, 3, 3, uint16be(ciphertext.length));
		const decrypted = cfg.chacha
			? await chacha20Poly1305Decrypt(this.serverHandshakeKey, nonce, ciphertext, aad)
			: await aesGcmDecryptWithKey((this.serverHandshakeCryptoKey ||= await importAesGcmKey(this.serverHandshakeKey, ['decrypt'])), nonce, ciphertext, aad);
		let innerTypeIndex = decrypted.length - 1;
		while (innerTypeIndex >= 0 && !decrypted[innerTypeIndex]) innerTypeIndex--;
		return innerTypeIndex < 0 ? EMPTY_BYTES : decrypted.slice(0, innerTypeIndex + 1);
	}
	private async encryptTls13(data: Uint8Array): Promise<Uint8Array> {
		const cfg = this.cipherConfig;
		if (!cfg || !this.clientAppIv || !this.clientAppKey) throw new Error('TLS 1.3 app keys not initialized');
		const plaintext = concatBytes(data, new Uint8Array([CONTENT_TYPE_APPLICATION_DATA]));
		const nonce = xorSequenceIntoIv(this.clientAppIv, this.clientSeqNum++);
		const aad = tlsBytes(CONTENT_TYPE_APPLICATION_DATA, 3, 3, uint16be(plaintext.length + 16));
		if (cfg.chacha) return chacha20Poly1305Encrypt(this.clientAppKey, nonce, plaintext, aad);
		this.clientAppCryptoKey ||= await importAesGcmKey(this.clientAppKey, ['encrypt']);
		return aesGcmEncryptWithKey(this.clientAppCryptoKey, nonce, plaintext, aad);
	}
	private async decryptTls13(ciphertext: Uint8Array): Promise<{ data: Uint8Array; type: number }> {
		const cfg = this.cipherConfig;
		if (!cfg || !this.serverAppIv || !this.serverAppKey) throw new Error('TLS 1.3 app keys not initialized');
		const nonce = xorSequenceIntoIv(this.serverAppIv, this.serverSeqNum++);
		const aad = tlsBytes(CONTENT_TYPE_APPLICATION_DATA, 3, 3, uint16be(ciphertext.length));
		const plaintext = cfg.chacha
			? await chacha20Poly1305Decrypt(this.serverAppKey, nonce, ciphertext, aad)
			: await aesGcmDecryptWithKey((this.serverAppCryptoKey ||= await importAesGcmKey(this.serverAppKey, ['decrypt'])), nonce, ciphertext, aad);
		let innerTypeIndex = plaintext.length - 1;
		while (innerTypeIndex >= 0 && !plaintext[innerTypeIndex]) innerTypeIndex--;
		if (innerTypeIndex < 0) return { data: EMPTY_BYTES, type: 0 };
		return { data: plaintext.slice(0, innerTypeIndex), type: plaintext[innerTypeIndex] };
	}

	async write(data: Uint8Array | ArrayBuffer | ArrayBufferView): Promise<void> {
		if (!this.handshakeComplete) throw new Error('Handshake not complete');
		const plaintext = 数据转Uint8Array(data);
		if (!plaintext.byteLength) return;
		const writer = this.socket.writable.getWriter();
		try {
			const records: Uint8Array[] = [];
			for (let offset = 0; offset < plaintext.byteLength; offset += TLS_MAX_PLAINTEXT_FRAGMENT) {
				const chunk = plaintext.subarray(offset, Math.min(offset + TLS_MAX_PLAINTEXT_FRAGMENT, plaintext.byteLength));
				const encrypted = this.isTls13 ? await this.encryptTls13(chunk) : await this.encryptTls12(chunk, CONTENT_TYPE_APPLICATION_DATA);
				records.push(buildTlsRecord(CONTENT_TYPE_APPLICATION_DATA, encrypted));
			}
			await writer.write(records.length === 1 ? records[0] : concatBytes(...records));
		} finally {
			writer.releaseLock();
		}
	}

	async read(): Promise<Uint8Array | null> {
		for (;;) {
			let record: TlsRecord | null;
			while ((record = this.recordParser.next())) {
				if (record.type === CONTENT_TYPE_ALERT) {
					if (record.fragment[1] === ALERT_CLOSE_NOTIFY) return null;
					throw new Error(`TLS Alert: ${record.fragment[1]}`);
				}
				if (record.type !== CONTENT_TYPE_APPLICATION_DATA) continue;
				if (!this.isTls13) return this.decryptTls12(record.fragment, CONTENT_TYPE_APPLICATION_DATA);
				const { data, type } = await this.decryptTls13(record.fragment);
				if (type === CONTENT_TYPE_APPLICATION_DATA) return data;
				if (type === CONTENT_TYPE_ALERT) {
					if (data[1] === ALERT_CLOSE_NOTIFY) return null;
					throw new Error(`TLS Alert: ${data[1]}`);
				}
				if (type !== CONTENT_TYPE_HANDSHAKE) continue;
				this.handshakeParser.feed(data);
				let m: HandshakeMessage | null;
				while ((m = this.handshakeParser.next())) {
					if (m.type !== HANDSHAKE_TYPE_NEW_SESSION_TICKET && m.type === HANDSHAKE_TYPE_KEY_UPDATE) {
						throw new Error('TLS 1.3 KeyUpdate is not supported by TLSClientMini');
					}
				}
			}
			const reader = this.socket.readable.getReader();
			try {
				const { value, done } = await this.readChunk(reader);
				if (done) return null;
				this.recordParser.feed(value);
			} finally {
				reader.releaseLock();
			}
		}
	}

	close(): void {
		this.socket.close();
	}
}
