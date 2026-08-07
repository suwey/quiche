// SSTP (Secure Socket Tunneling Protocol) over HTTPS 客户端，
// 内部跑 PPP/IPCP，再封一层 IP+TCP。

import { DoH查询 } from './doh';
import { 数据转Uint8Array, 拼接字节数据, isIPv4, stripIPv6Brackets, withTimeout } from './utils';
import type { ParsedProxyAddress, TCPConnector, TCPSocket } from './types';

const CONNECT_TIMEOUT_MS = 9999;
const SSTP_TCP_MSS = 1400;
const SSTP_EMPTY_BYTES = new Uint8Array(0);

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

function readSstpUint16(bytes: Uint8Array, offset = 0): number {
	return (bytes[offset] << 8) | bytes[offset + 1];
}

function readSstpUint32(bytes: Uint8Array, offset = 0): number {
	return ((bytes[offset] << 24) | (bytes[offset + 1] << 16) | (bytes[offset + 2] << 8) | bytes[offset + 3]) >>> 0;
}

function randomSstpUint16(): number {
	return readSstpUint16(crypto.getRandomValues(new Uint8Array(2)));
}

function internetChecksum(bytes: Uint8Array, offset: number, length: number): number {
	let sum = 0;
	for (let index = offset; index < offset + length - 1; index += 2) sum += readSstpUint16(bytes, index);
	if (length & 1) sum += bytes[offset + length - 1] << 8;
	while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
	return ~sum & 0xffff;
}

interface PppOption {
	type: number;
	data: Uint8Array;
}

interface PppFrame {
	protocol: number;
	ipPacket?: Uint8Array;
	code?: number;
	id?: number;
	payload?: Uint8Array;
	rawPacket?: Uint8Array;
}

interface SstpPacket {
	isControl: boolean;
	body: Uint8Array;
}

export async function sstpConnect(proxy: ParsedProxyAddress, targetHost: string, targetPort: number, TCP连接: TCPConnector): Promise<TCPSocket> {
	const merged: ParsedProxyAddress = { ...proxy, username: proxy.username ?? undefined, password: proxy.password ?? undefined };
	let bufferedBytes: Uint8Array = SSTP_EMPTY_BYTES;
	let pppIdentifier = 1;
	let socket: TCPSocket | null = null;
	let reader: ReadableStreamDefaultReader<Uint8Array> | null = null;
	let writer: WritableStreamDefaultWriter<Uint8Array> | null = null;
	let closedSettled = false;
	let resolveClosed: (() => void) | null = null;
	let rejectClosed: ((err: unknown) => void) | null = null;
	const closed = new Promise<void>((resolve, reject) => {
		resolveClosed = resolve;
		rejectClosed = reject;
	});
	const settleClosed = (settle: ((value?: unknown) => void) | null, value?: unknown): void => {
		if (closedSettled) return;
		closedSettled = true;
		settle?.(value);
	};
	const close = (): void => {
		try { reader?.cancel().catch(() => { /* ignore */ }); } catch { /* ignore */ }
		try { reader?.releaseLock(); } catch { /* ignore */ }
		try { writer?.close().catch(() => { /* ignore */ }); } catch { /* ignore */ }
		try { writer?.releaseLock(); } catch { /* ignore */ }
		try { socket?.close(); } catch { /* ignore */ }
		settleClosed(resolveClosed);
	};

	const readSocketChunk = async (): Promise<Uint8Array> => {
		if (!reader) throw new Error('SSTP reader not ready');
		const { value, done } = await reader.read();
		if (done || !value) throw new Error('SSTP socket closed');
		return 数据转Uint8Array(value);
	};
	const readBytes = async (length: number): Promise<Uint8Array> => {
		while (bufferedBytes.byteLength < length) {
			const chunk = await readSocketChunk();
			bufferedBytes = bufferedBytes.byteLength ? 拼接字节数据(bufferedBytes, chunk) : chunk;
		}
		const result = bufferedBytes.subarray(0, length);
		bufferedBytes = bufferedBytes.subarray(length);
		return result;
	};
	const readHttpLine = async (): Promise<string> => {
		for (;;) {
			const lineEnd = bufferedBytes.indexOf(10);
			if (lineEnd >= 0) {
				const line = textDecoder.decode(bufferedBytes.subarray(0, lineEnd));
				bufferedBytes = bufferedBytes.subarray(lineEnd + 1);
				return line.replace(/\r$/, '');
			}
			const chunk = await readSocketChunk();
			bufferedBytes = bufferedBytes.byteLength ? 拼接字节数据(bufferedBytes, chunk) : chunk;
		}
	};
	const readPacket = async (timeoutMs = CONNECT_TIMEOUT_MS): Promise<SstpPacket> => {
		const header = await withTimeout(readBytes(4), timeoutMs, 'SSTP read timeout');
		const length = readSstpUint16(header, 2) & 0x0fff;
		if (length < 4) throw new Error('Invalid SSTP packet length');
		return {
			isControl: (header[1] & 1) !== 0,
			body: length > 4 ? await withTimeout(readBytes(length - 4), timeoutMs, 'SSTP packet body read timeout') : SSTP_EMPTY_BYTES,
		};
	};
	const buildSstpDataPacket = (pppFrame: Uint8Array): Uint8Array => {
		const packetLength = 6 + pppFrame.byteLength;
		const packet = new Uint8Array(packetLength);
		packet.set([0x10, 0x00, ((packetLength >> 8) & 0x0f) | 0x80, packetLength & 0xff, 0xff, 0x03]);
		packet.set(pppFrame, 6);
		return packet;
	};
	const buildPppConfigurePacket = (protocol: number, code: number, id: number, options: PppOption[] = []): Uint8Array => {
		const optionsLength = options.reduce((size, option) => size + 2 + option.data.byteLength, 0);
		const frame = new Uint8Array(6 + optionsLength);
		const view = new DataView(frame.buffer);
		view.setUint16(0, protocol);
		frame[2] = code;
		frame[3] = id;
		view.setUint16(4, 4 + optionsLength);
		options.reduce((offset, option) => {
			frame[offset] = option.type;
			frame[offset + 1] = 2 + option.data.byteLength;
			frame.set(option.data, offset + 2);
			return offset + 2 + option.data.byteLength;
		}, 6);
		return frame;
	};
	const parsePPPFrame = (data: Uint8Array): PppFrame | null => {
		const offset = data.byteLength >= 2 && data[0] === 0xff && data[1] === 0x03 ? 2 : 0;
		if (data.byteLength - offset < 4) return null;
		const protocol = readSstpUint16(data, offset);
		if (protocol === 0x0021) return { protocol, ipPacket: data.subarray(offset + 2) };
		if (data.byteLength - offset < 6) return null;
		return { protocol, code: data[offset + 2], id: data[offset + 3], payload: data.subarray(offset + 6), rawPacket: data.subarray(offset) };
	};
	const parsePppOptions = (data: Uint8Array): PppOption[] => {
		const options: PppOption[] = [];
		for (let offset = 0; offset + 2 <= data.byteLength;) {
			const type = data[offset];
			const length = data[offset + 1];
			if (length < 2 || offset + length > data.byteLength) break;
			options.push({ type, data: data.subarray(offset + 2, offset + length) });
			offset += length;
		}
		return options;
	};

	try {
		const serverHost = stripIPv6Brackets(merged.hostname);
		const serverPort = merged.port;
		socket = TCP连接({ hostname: serverHost, port: serverPort }, { secureTransport: 'on', allowHalfOpen: false });
		if (socket.opened) await withTimeout(socket.opened as Promise<unknown>, CONNECT_TIMEOUT_MS, 'SSTP server connection timed out');
		reader = socket.readable.getReader();
		writer = socket.writable.getWriter();

		const displayHost = serverHost.includes(':') ? `[${serverHost}]` : serverHost;
		const httpRequest = textEncoder.encode(
			`SSTP_DUPLEX_POST /sra_{BA195980-CD49-458b-9E23-C84EE0ADCD75}/ HTTP/1.1\r\n`
			+ `Host: ${Number(serverPort) === 443 ? displayHost : `${displayHost}:${serverPort}`}\r\n`
			+ 'Content-Length: 18446744073709551615\r\n'
			+ `SSTPCORRELATIONID: {${crypto.randomUUID()}}\r\n\r\n`
		);
		const encapsulatedProtocol = new Uint8Array(2);
		new DataView(encapsulatedProtocol.buffer).setUint16(0, 1);
		const maximumReceiveUnit = new Uint8Array(2);
		new DataView(maximumReceiveUnit.buffer).setUint16(0, 1500);
		const sstpConnectRequest = new Uint8Array(12 + encapsulatedProtocol.byteLength);
		const sstpConnectView = new DataView(sstpConnectRequest.buffer);
		sstpConnectRequest[0] = 0x10;
		sstpConnectRequest[1] = 0x01;
		sstpConnectView.setUint16(2, sstpConnectRequest.byteLength | 0x8000);
		sstpConnectView.setUint16(4, 0x0001);
		sstpConnectView.setUint16(6, 1);
		sstpConnectRequest[9] = 1;
		sstpConnectView.setUint16(10, 4 + encapsulatedProtocol.byteLength);
		sstpConnectRequest.set(encapsulatedProtocol, 12);

		await withTimeout(
			writer.write(拼接字节数据(httpRequest, sstpConnectRequest, buildSstpDataPacket(buildPppConfigurePacket(0xc021, 1, pppIdentifier++, [{ type: 1, data: maximumReceiveUnit }])))),
			CONNECT_TIMEOUT_MS,
			'SSTP HTTP handshake request timed out'
		);

		const statusLine = await withTimeout(readHttpLine(), CONNECT_TIMEOUT_MS, 'SSTP HTTP handshake timed out');
		for (;;) {
			const line = await withTimeout(readHttpLine(), CONNECT_TIMEOUT_MS, 'SSTP HTTP header read timed out');
			if (line === '') break;
		}
		if (!/HTTP\/\d(?:\.\d)?\s+2\d\d/i.test(statusLine)) throw new Error(`SSTP HTTP handshake failed: ${statusLine || 'invalid status'}`);

		let localLcpAcked = false;
		let peerLcpAcked = false;
		let papRequired = false;
		let papSent = false;
		let papDone = false;
		let ipcpStarted = false;
		let ipcpFinished = false;
		let sourceIp: string | null = null;
		const w: WritableStreamDefaultWriter<Uint8Array> = writer;
		const sendPapIfReady = async (): Promise<void> => {
			if (!localLcpAcked || !peerLcpAcked || !papRequired || papSent) return;
			if (merged.username === undefined || merged.password === undefined) throw new Error('SSTP server requires PAP authentication');
			const usernameBytes = textEncoder.encode(merged.username);
			const passwordBytes = textEncoder.encode(merged.password);
			if (usernameBytes.byteLength > 255 || passwordBytes.byteLength > 255) throw new Error('SSTP username/password is too long');
			const papLength = 6 + usernameBytes.byteLength + passwordBytes.byteLength;
			const frame = new Uint8Array(2 + papLength);
			const view = new DataView(frame.buffer);
			view.setUint16(0, 0xc023);
			frame[2] = 1;
			frame[3] = pppIdentifier++;
			view.setUint16(4, papLength);
			frame[6] = usernameBytes.byteLength;
			frame.set(usernameBytes, 7);
			frame[7 + usernameBytes.byteLength] = passwordBytes.byteLength;
			frame.set(passwordBytes, 8 + usernameBytes.byteLength);
			await withTimeout(w.write(buildSstpDataPacket(frame)), CONNECT_TIMEOUT_MS, 'SSTP PAP authentication request timed out');
			papSent = true;
		};
		const startIpcpIfReady = async (): Promise<void> => {
			if (!localLcpAcked || !peerLcpAcked || ipcpStarted || (papRequired && !papDone)) return;
			await withTimeout(
				w.write(buildSstpDataPacket(buildPppConfigurePacket(0x8021, 1, pppIdentifier++, [{ type: 3, data: new Uint8Array(4) }]))),
				CONNECT_TIMEOUT_MS,
				'SSTP IPCP request timed out'
			);
			ipcpStarted = true;
		};

		for (let round = 0; round < 50 && !ipcpFinished; round++) {
			const packet = await readPacket(CONNECT_TIMEOUT_MS);
			if (packet.isControl) continue;
			const ppp = parsePPPFrame(packet.body);
			if (!ppp || !ppp.rawPacket) continue;

			if (ppp.protocol === 0xc021) {
				if (ppp.code === 1 && ppp.payload) {
					const authOption = parsePppOptions(ppp.payload).find((option) => option.type === 3);
					if (authOption?.data?.byteLength && authOption.data.byteLength >= 2) {
						const authProtocol = readSstpUint16(authOption.data);
						if (authProtocol !== 0xc023) throw new Error(`SSTP unsupported PPP authentication protocol: 0x${authProtocol.toString(16)}`);
						papRequired = true;
					}
					const ack = new Uint8Array(ppp.rawPacket);
					ack[2] = 2;
					await withTimeout(w.write(buildSstpDataPacket(ack)), CONNECT_TIMEOUT_MS, 'SSTP LCP Configure-Ack timed out');
					peerLcpAcked = true;
					await sendPapIfReady();
					await startIpcpIfReady();
				} else if (ppp.code === 2) {
					localLcpAcked = true;
					await sendPapIfReady();
					await startIpcpIfReady();
				}
				continue;
			}

			if (ppp.protocol === 0xc023) {
				if (ppp.code === 2) {
					papDone = true;
					await startIpcpIfReady();
				} else if (ppp.code === 3) throw new Error('SSTP PAP authentication failed');
				continue;
			}

			if (ppp.protocol === 0x8021) {
				if (ppp.code === 1 && ppp.payload) {
					const ack = new Uint8Array(ppp.rawPacket);
					ack[2] = 2;
					await withTimeout(w.write(buildSstpDataPacket(ack)), CONNECT_TIMEOUT_MS, 'SSTP IPCP Configure-Ack timed out');
					await startIpcpIfReady();
				} else if (ppp.code === 3 && ppp.payload) {
					const addressOption = parsePppOptions(ppp.payload).find((option) => option.type === 3);
					if (addressOption?.data?.byteLength === 4) {
						sourceIp = [...addressOption.data].join('.');
						await withTimeout(
							w.write(buildSstpDataPacket(buildPppConfigurePacket(0x8021, 1, pppIdentifier++, [{ type: 3, data: addressOption.data }]))),
							CONNECT_TIMEOUT_MS,
							'SSTP IPCP address request timed out'
						);
						ipcpStarted = true;
					}
				} else if (ppp.code === 2 && ppp.payload) {
					const addressOption = parsePppOptions(ppp.payload).find((option) => option.type === 3);
					if (addressOption?.data?.byteLength === 4) sourceIp = [...addressOption.data].join('.');
					ipcpFinished = true;
				}
			}
		}
		if (!sourceIp) throw new Error('SSTP did not assign an IPv4 address');

		const target = stripIPv6Brackets(targetHost);
		let targetIp: string | null = isIPv4(target) ? target : null;
		if (!targetIp) {
			const records = await DoH查询(target, 'A');
			const recordData = records.find((item) => item.type === 1 && isIPv4(item.data))?.data;
			targetIp = typeof recordData === 'string' ? recordData : null;
		}
		if (!targetIp) throw new Error(`Could not resolve ${targetHost} to an IPv4 address for SSTP`);

		const sourcePort = 10000 + (randomSstpUint16() % 50000);
		const sourceAddress = new Uint8Array(String(sourceIp || '').split('.').map(Number));
		const destinationAddress = new Uint8Array(String(targetIp || '').split('.').map(Number));
		let sequenceNumber = readSstpUint32(crypto.getRandomValues(new Uint8Array(4)));
		let acknowledgementNumber = 0;
		const ipHeaderTemplate = new Uint8Array(20);
		ipHeaderTemplate.set([0x45, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 64, 6]);
		ipHeaderTemplate.set(sourceAddress, 12);
		ipHeaderTemplate.set(destinationAddress, 16);
		const tcpPseudoHeader = new Uint8Array(1432);
		tcpPseudoHeader.set(sourceAddress);
		tcpPseudoHeader.set(destinationAddress, 4);
		tcpPseudoHeader[9] = 6;

		const buildTcpFrame = (flags: number, payload: Uint8Array | ArrayBuffer | ArrayBufferView = SSTP_EMPTY_BYTES): Uint8Array => {
			const bytes = 数据转Uint8Array(payload);
			const payloadLength = bytes.byteLength;
			const tcpLength = 20 + payloadLength;
			const ipLength = 20 + tcpLength;
			const sstpLength = 8 + ipLength;
			const frame = new Uint8Array(sstpLength);
			const view = new DataView(frame.buffer);
			frame.set([0x10, 0x00, ((sstpLength >> 8) & 0x0f) | 0x80, sstpLength & 0xff, 0xff, 0x03, 0x00, 0x21]);
			frame.set(ipHeaderTemplate, 8);
			view.setUint16(10, ipLength);
			view.setUint16(12, randomSstpUint16());
			view.setUint16(18, internetChecksum(frame, 8, 20));
			view.setUint16(28, sourcePort);
			view.setUint16(30, targetPort);
			view.setUint32(32, sequenceNumber);
			view.setUint32(36, acknowledgementNumber);
			frame[40] = 0x50;
			frame[41] = flags;
			view.setUint16(42, 65535);
			if (payloadLength) frame.set(bytes, 48);
			tcpPseudoHeader[10] = tcpLength >> 8;
			tcpPseudoHeader[11] = tcpLength & 0xff;
			tcpPseudoHeader.set(frame.subarray(28, 28 + tcpLength), 12);
			view.setUint16(44, internetChecksum(tcpPseudoHeader, 0, 12 + tcpLength));
			return frame;
		};
		const matchIncomingIpPacket = (ipPacket: Uint8Array): { flags: number; sequence: number; payloadOffset: number } | null => {
			if (ipPacket.byteLength < 40 || ipPacket[9] !== 6) return null;
			const ipHeaderLength = (ipPacket[0] & 0x0f) * 4;
			if (ipPacket.byteLength < ipHeaderLength + 20) return null;
			if (readSstpUint16(ipPacket, ipHeaderLength) !== targetPort) return null;
			if (readSstpUint16(ipPacket, ipHeaderLength + 2) !== sourcePort) return null;
			return {
				flags: ipPacket[ipHeaderLength + 13],
				sequence: readSstpUint32(ipPacket, ipHeaderLength + 4),
				payloadOffset: ipHeaderLength + ((ipPacket[ipHeaderLength + 12] >> 4) & 0x0f) * 4,
			};
		};

		await withTimeout(w.write(buildTcpFrame(0x02)), CONNECT_TIMEOUT_MS, 'SSTP TCP SYN write timed out');
		sequenceNumber = (sequenceNumber + 1) >>> 0;
		let tcpReady = false;
		for (let attempt = 0; attempt < 30; attempt++) {
			const packet = await readPacket(CONNECT_TIMEOUT_MS);
			if (packet.isControl) continue;
			const ppp = parsePPPFrame(packet.body);
			if (!ppp || ppp.protocol !== 0x0021 || !ppp.ipPacket) continue;
			const tcp = matchIncomingIpPacket(ppp.ipPacket);
			if (!tcp || (tcp.flags & 0x12) !== 0x12) continue;
			acknowledgementNumber = (tcp.sequence + 1) >>> 0;
			await withTimeout(w.write(buildTcpFrame(0x10)), CONNECT_TIMEOUT_MS, 'SSTP TCP ACK write timed out');
			tcpReady = true;
			break;
		}
		if (!tcpReady) throw new Error('TCP handshake through SSTP timed out');

		type SstpController = ReadableStreamDefaultController<Uint8Array>;
		const controllerHolder: { value: SstpController | null } = { value: null };
		const readable = new ReadableStream<Uint8Array>({
			start(controller: SstpController) {
				controllerHolder.value = controller;
			},
			cancel() {
				close();
			},
		});

		(async () => {
			try {
				let pendingChunks: Uint8Array[] = [];
				let pendingLength = 0;
				const flush = (): void => {
					if (!pendingLength) return;
					if (!controllerHolder.value) throw new Error('SSTP readable stream is not ready');
					controllerHolder.value.enqueue(pendingChunks.length === 1 ? pendingChunks[0] : 拼接字节数据(...pendingChunks));
					pendingChunks = [];
					pendingLength = 0;
					w.write(buildTcpFrame(0x10)).catch(() => { /* ignore */ });
				};

				for (;;) {
					const packet = await readPacket(60000);
					if (packet.isControl) continue;
					const ppp = parsePPPFrame(packet.body);
					if (!ppp || ppp.protocol !== 0x0021 || !ppp.ipPacket) continue;
					const incoming = matchIncomingIpPacket(ppp.ipPacket);
					if (!incoming) continue;

					if (incoming.payloadOffset < ppp.ipPacket.byteLength) {
						const payload = ppp.ipPacket.subarray(incoming.payloadOffset);
						if (payload.byteLength) {
							acknowledgementNumber = (incoming.sequence + payload.byteLength) >>> 0;
							pendingChunks.push(new Uint8Array(payload));
							pendingLength += payload.byteLength;
						}
					}

					if (incoming.flags & 0x01) {
						flush();
						acknowledgementNumber = (acknowledgementNumber + 1) >>> 0;
						w.write(buildTcpFrame(0x11)).catch(() => { /* ignore */ });
						const controller = controllerHolder.value;
						if (controller) {
							try { controller.close(); } catch { /* ignore */ }
						}
						close();
						return;
					}

					if (bufferedBytes.byteLength < 4 || pendingLength >= 32768) flush();
				}
			} catch (error) {
				const controller = controllerHolder.value;
				if (controller) {
					try { controller.error(error); } catch { /* ignore */ }
				}
				settleClosed(rejectClosed, error);
				try { socket?.close(); } catch { /* ignore */ }
			}
		})();

		const writable = new WritableStream<Uint8Array>({
			async write(chunk) {
				const bytes = 数据转Uint8Array(chunk);
				if (!bytes.byteLength) return;
				if (bytes.byteLength <= SSTP_TCP_MSS) {
					await w.write(buildTcpFrame(0x18, bytes));
					sequenceNumber = (sequenceNumber + bytes.byteLength) >>> 0;
					return;
				}
				const frames: Uint8Array[] = [];
				for (let offset = 0; offset < bytes.byteLength; offset += SSTP_TCP_MSS) {
					const segment = bytes.subarray(offset, Math.min(offset + SSTP_TCP_MSS, bytes.byteLength));
					frames.push(buildTcpFrame(0x18, segment));
					sequenceNumber = (sequenceNumber + segment.byteLength) >>> 0;
				}
				await w.write(拼接字节数据(...frames));
			},
			close() {
				return w.write(buildTcpFrame(0x11)).then(() => undefined).catch(() => { /* ignore */ });
			},
			abort(error) {
				close();
				if (error) settleClosed(rejectClosed, error);
			},
		});

		const socketRef: TCPSocket = socket;
		return { readable, writable, closed, close: () => { close(); socketRef.close(); } };
	} catch (error) {
		close();
		throw error;
	}
}
