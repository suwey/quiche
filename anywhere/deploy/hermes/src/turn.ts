// TURN over TCP CONNECT 客户端。

import { DoH查询 } from './doh';
import { 数据转Uint8Array, 拼接字节数据, 有效数据长度, isIPv4, stripIPv6Brackets, withTimeout } from './utils';
import type { ParsedProxyAddress, TCPConnector, TCPSocket } from './types';

const CONNECT_TIMEOUT_MS = 9999;
const TURN_STUN_MAGIC_COOKIE = new Uint8Array([0x21, 0x12, 0xa4, 0x42]);

const TURN_STUN_TYPE = {
	ALLOCATE_REQUEST: 0x0003,
	ALLOCATE_SUCCESS: 0x0103,
	ALLOCATE_ERROR: 0x0113,
	CREATE_PERMISSION_REQUEST: 0x0008,
	CREATE_PERMISSION_SUCCESS: 0x0108,
	CONNECT_REQUEST: 0x000a,
	CONNECT_SUCCESS: 0x010a,
	CONNECTION_BIND_REQUEST: 0x000b,
	CONNECTION_BIND_SUCCESS: 0x010b,
} as const;

const TURN_STUN_ATTR = {
	USERNAME: 0x0006,
	MESSAGE_INTEGRITY: 0x0008,
	ERROR_CODE: 0x0009,
	XOR_PEER_ADDRESS: 0x0012,
	REALM: 0x0014,
	NONCE: 0x0015,
	REQUESTED_TRANSPORT: 0x0019,
	CONNECTION_ID: 0x002a,
} as const;

function turnStunPadding(length: number): number {
	return -length & 3;
}

function createTurnStunAttribute(type: number, value: Uint8Array): Uint8Array {
	const body = 数据转Uint8Array(value);
	const attribute = new Uint8Array(4 + body.byteLength + turnStunPadding(body.byteLength));
	const view = new DataView(attribute.buffer);
	view.setUint16(0, type);
	view.setUint16(2, body.byteLength);
	attribute.set(body, 4);
	return attribute;
}

function createTurnStunMessage(type: number, transactionId: Uint8Array, attributes: Uint8Array[]): Uint8Array {
	const body = 拼接字节数据(...attributes);
	const header = new Uint8Array(20);
	const view = new DataView(header.buffer);
	view.setUint16(0, type);
	view.setUint16(2, body.byteLength);
	header.set(TURN_STUN_MAGIC_COOKIE, 4);
	header.set(transactionId, 8);
	return 拼接字节数据(header, body);
}

function parseTurnErrorCode(data: Uint8Array | undefined): number {
	return data && data.byteLength >= 4 ? (data[2] & 7) * 100 + data[3] : 0;
}

async function addTurnMessageIntegrity(message: Uint8Array, key: Uint8Array): Promise<Uint8Array> {
	const signed = new Uint8Array(message);
	const view = new DataView(signed.buffer);
	view.setUint16(2, view.getUint16(2) + 24);
	const hmacKey = await crypto.subtle.importKey('raw', key, { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']);
	const signature = await crypto.subtle.sign('HMAC', hmacKey, signed);
	return 拼接字节数据(signed, createTurnStunAttribute(TURN_STUN_ATTR.MESSAGE_INTEGRITY, new Uint8Array(signature)));
}

interface TurnStunResponse {
	message: { type: number; attributes: Record<number, Uint8Array> };
	extraData: Uint8Array | null;
}

async function readTurnStunMessage(reader: ReadableStreamDefaultReader<Uint8Array>, bufferedData: Uint8Array | null = null, timeoutMessage = 'TURN response timed out'): Promise<TurnStunResponse> {
	let buffer = 有效数据长度(bufferedData) ? 数据转Uint8Array(bufferedData) : new Uint8Array(0);
	const pull = async (): Promise<void> => {
		const { done, value } = await withTimeout(reader.read(), CONNECT_TIMEOUT_MS, timeoutMessage);
		if (done) throw new Error('TURN server closed connection');
		if (value?.byteLength) buffer = 拼接字节数据(buffer, value);
	};
	while (buffer.byteLength < 20) await pull();

	const messageLength = 20 + ((buffer[2] << 8) | buffer[3]);
	if (messageLength > 65555) throw new Error('TURN response is too large');
	while (buffer.byteLength < messageLength) await pull();
	const messageBuffer = buffer.subarray(0, messageLength);
	if (TURN_STUN_MAGIC_COOKIE.some((value, index) => messageBuffer[4 + index] !== value)) throw new Error('Invalid TURN/STUN response');

	const view = new DataView(messageBuffer.buffer, messageBuffer.byteOffset, messageBuffer.byteLength);
	const attributes: Record<number, Uint8Array> = {};
	for (let offset = 20; offset + 4 <= messageLength;) {
		const type = view.getUint16(offset);
		const length = view.getUint16(offset + 2);
		if (offset + 4 + length > messageBuffer.byteLength) break;
		attributes[type] = messageBuffer.slice(offset + 4, offset + 4 + length);
		offset += 4 + length + turnStunPadding(length);
	}
	return {
		message: { type: view.getUint16(0), attributes },
		extraData: buffer.byteLength > messageLength ? buffer.subarray(messageLength) : null,
	};
}

export async function turnConnect(proxy: ParsedProxyAddress, targetHost: string, targetPort: number, TCP连接: TCPConnector): Promise<TCPSocket> {
	const merged: ParsedProxyAddress = { ...proxy, username: proxy.username ?? undefined, password: proxy.password ?? undefined };
	const resolvedTargetHost = stripIPv6Brackets(targetHost);
	let targetIp: string | null = isIPv4(resolvedTargetHost) ? resolvedTargetHost : null;
	if (!targetIp) {
		const records = await DoH查询(resolvedTargetHost, 'A');
		const recordData = records.find((item) => item.type === 1 && isIPv4(item.data))?.data;
		targetIp = typeof recordData === 'string' ? recordData : null;
	}
	if (!targetIp) throw new Error(`Could not resolve ${targetHost} to an IPv4 address for TURN CONNECT`);

	const turnHost = stripIPv6Brackets(merged.hostname);
	let controlSocket: TCPSocket | null = null;
	let dataSocket: TCPSocket | null = null;
	let controlWriter: WritableStreamDefaultWriter<Uint8Array> | null = null;
	let controlReader: ReadableStreamDefaultReader<Uint8Array> | null = null;
	let dataWriter: WritableStreamDefaultWriter<Uint8Array> | null = null;
	let dataReader: ReadableStreamDefaultReader<Uint8Array> | null = null;
	let dataReaderReleased = false;

	const close = (): void => {
		try { controlSocket?.close(); } catch { /* ignore */ }
		try { dataSocket?.close(); } catch { /* ignore */ }
	};
	const releaseDataReader = (): void => {
		if (dataReaderReleased) return;
		dataReaderReleased = true;
		try { dataReader?.releaseLock(); } catch { /* ignore */ }
	};

	const randomTurnTransactionId = (): Uint8Array => crypto.getRandomValues(new Uint8Array(12));
	const writeTurnBytes = async (writer: WritableStreamDefaultWriter<Uint8Array>, bytes: Uint8Array, timeoutMessage: string): Promise<void> => {
		await withTimeout(writer.write(bytes), CONNECT_TIMEOUT_MS, timeoutMessage);
	};

	try {
		controlSocket = TCP连接({ hostname: turnHost, port: merged.port });
		if (controlSocket.opened) await withTimeout(controlSocket.opened as Promise<unknown>, CONNECT_TIMEOUT_MS, 'TURN server connection timed out');
		controlWriter = controlSocket.writable.getWriter();
		controlReader = controlSocket.readable.getReader();

		const xorPeerAddress = new Uint8Array(8);
		xorPeerAddress[1] = 1;
		new DataView(xorPeerAddress.buffer).setUint16(2, targetPort ^ 0x2112);
		targetIp.split('.').forEach((value, index) => {
			xorPeerAddress[4 + index] = Number(value) ^ TURN_STUN_MAGIC_COOKIE[index];
		});
		const peerAddress = createTurnStunAttribute(TURN_STUN_ATTR.XOR_PEER_ADDRESS, xorPeerAddress);
		const requestedTransport = new Uint8Array([6, 0, 0, 0]);

		await writeTurnBytes(
			controlWriter,
			createTurnStunMessage(TURN_STUN_TYPE.ALLOCATE_REQUEST, randomTurnTransactionId(), [createTurnStunAttribute(TURN_STUN_ATTR.REQUESTED_TRANSPORT, requestedTransport)]),
			'TURN Allocate request timed out'
		);

		let turnResponse = await readTurnStunMessage(controlReader, null, 'TURN Allocate response timed out');
		let message = turnResponse.message;
		let bufferedData = turnResponse.extraData;
		let integrityKey: Uint8Array | null = null;
		let authAttributes: Uint8Array[] = [];
		const sign = (msg: Uint8Array): Promise<Uint8Array> => (integrityKey ? addTurnMessageIntegrity(msg, integrityKey) : Promise.resolve(msg));

		if (
			message.type === TURN_STUN_TYPE.ALLOCATE_ERROR
			&& merged.username !== undefined
			&& merged.password !== undefined
			&& parseTurnErrorCode(message.attributes[TURN_STUN_ATTR.ERROR_CODE]) === 401
		) {
			const realmBytes = message.attributes[TURN_STUN_ATTR.REALM];
			const nonce = message.attributes[TURN_STUN_ATTR.NONCE];
			if (!realmBytes || !nonce?.byteLength) throw new Error('TURN authentication challenge is missing realm or nonce');

			const realm = new TextDecoder().decode(realmBytes);
			integrityKey = new Uint8Array(await crypto.subtle.digest('MD5', new TextEncoder().encode(`${merged.username}:${realm}:${merged.password}`)));
			authAttributes = [
				createTurnStunAttribute(TURN_STUN_ATTR.USERNAME, new TextEncoder().encode(merged.username)),
				createTurnStunAttribute(TURN_STUN_ATTR.REALM, new TextEncoder().encode(realm)),
				createTurnStunAttribute(TURN_STUN_ATTR.NONCE, nonce),
			];

			const allocateRequest = await addTurnMessageIntegrity(
				createTurnStunMessage(TURN_STUN_TYPE.ALLOCATE_REQUEST, randomTurnTransactionId(), [createTurnStunAttribute(TURN_STUN_ATTR.REQUESTED_TRANSPORT, requestedTransport), ...authAttributes]),
				integrityKey
			);
			const pipelined = await Promise.all([
				sign(createTurnStunMessage(TURN_STUN_TYPE.CREATE_PERMISSION_REQUEST, randomTurnTransactionId(), [peerAddress, ...authAttributes])),
				sign(createTurnStunMessage(TURN_STUN_TYPE.CONNECT_REQUEST, randomTurnTransactionId(), [peerAddress, ...authAttributes])),
			]);
			await writeTurnBytes(controlWriter, 拼接字节数据(allocateRequest, ...pipelined), 'TURN authenticated Allocate request timed out');
			turnResponse = await readTurnStunMessage(controlReader, bufferedData, 'TURN authenticated Allocate response timed out');
			message = turnResponse.message;
			bufferedData = turnResponse.extraData;
		} else if (message.type === TURN_STUN_TYPE.ALLOCATE_SUCCESS) {
			const pipelined = await Promise.all([
				sign(createTurnStunMessage(TURN_STUN_TYPE.CREATE_PERMISSION_REQUEST, randomTurnTransactionId(), [peerAddress, ...authAttributes])),
				sign(createTurnStunMessage(TURN_STUN_TYPE.CONNECT_REQUEST, randomTurnTransactionId(), [peerAddress, ...authAttributes])),
			]);
			if (pipelined.length) await writeTurnBytes(controlWriter, 拼接字节数据(...pipelined), 'TURN pipelined request timed out');
		}

		if (message.type !== TURN_STUN_TYPE.ALLOCATE_SUCCESS) {
			const errorCode = parseTurnErrorCode(message.attributes[TURN_STUN_ATTR.ERROR_CODE]);
			throw new Error(errorCode ? `TURN Allocate failed with ${errorCode}` : 'TURN Allocate failed');
		}

		dataSocket = TCP连接({ hostname: turnHost, port: merged.port });
		turnResponse = await readTurnStunMessage(controlReader, bufferedData, 'TURN CreatePermission response timed out');
		message = turnResponse.message;
		bufferedData = turnResponse.extraData;
		if (message.type !== TURN_STUN_TYPE.CREATE_PERMISSION_SUCCESS) throw new Error('TURN CreatePermission failed');

		turnResponse = await readTurnStunMessage(controlReader, bufferedData, 'TURN CONNECT response timed out');
		message = turnResponse.message;
		bufferedData = turnResponse.extraData;
		if (message.type !== TURN_STUN_TYPE.CONNECT_SUCCESS || !message.attributes[TURN_STUN_ATTR.CONNECTION_ID]) throw new Error('TURN CONNECT failed');

		if (dataSocket.opened) await withTimeout(dataSocket.opened as Promise<unknown>, CONNECT_TIMEOUT_MS, 'TURN data connection timed out');
		dataWriter = dataSocket.writable.getWriter();
		dataReader = dataSocket.readable.getReader();
		await writeTurnBytes(
			dataWriter,
			await sign(
				createTurnStunMessage(TURN_STUN_TYPE.CONNECTION_BIND_REQUEST, randomTurnTransactionId(), [
					createTurnStunAttribute(TURN_STUN_ATTR.CONNECTION_ID, message.attributes[TURN_STUN_ATTR.CONNECTION_ID]),
					...authAttributes,
				])
			),
			'TURN ConnectionBind request timed out'
		);

		turnResponse = await readTurnStunMessage(dataReader, null, 'TURN ConnectionBind response timed out');
		message = turnResponse.message;
		const extraPayload = turnResponse.extraData;
		if (message.type !== TURN_STUN_TYPE.CONNECTION_BIND_SUCCESS) throw new Error('TURN ConnectionBind failed');

		controlWriter.releaseLock();
		controlWriter = null;
		controlReader.releaseLock();
		controlReader = null;
		dataWriter.releaseLock();
		dataWriter = null;

		const localDataSocket: TCPSocket = dataSocket;
		const localDataReader: ReadableStreamDefaultReader<Uint8Array> = dataReader;

		const readable = new ReadableStream<Uint8Array>({
			start(controller) {
				if (extraPayload?.byteLength) controller.enqueue(extraPayload);
			},
			pull(controller) {
				return localDataReader.read().then(({ done, value }) => {
					if (done) {
						releaseDataReader();
						controller.close();
					} else if (value?.byteLength) controller.enqueue(new Uint8Array(value));
				});
			},
			cancel() {
				try { localDataReader.cancel(); } catch { /* ignore */ }
				releaseDataReader();
				close();
			},
		});

		return { readable, writable: localDataSocket.writable, closed: localDataSocket.closed, close };
	} catch (error) {
		try { controlWriter?.releaseLock(); } catch { /* ignore */ }
		try { controlReader?.releaseLock(); } catch { /* ignore */ }
		try { dataWriter?.releaseLock(); } catch { /* ignore */ }
		releaseDataReader();
		close();
		throw error;
	}
}
