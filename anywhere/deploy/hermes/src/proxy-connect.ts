// SOCKS5 / HTTP / HTTPS CONNECT 三种代理客户端。

import { state, log } from './state';
import { 数据转Uint8Array, 拼接字节数据, 有效数据长度, isIPHostname, stripIPv6Brackets } from './utils';
import { TlsClient } from './tls-client';
import type { TCPConnector, TCPSocket } from './types';

export async function socks5Connect(targetHost: string, targetPort: number, initialData: Uint8Array | null, TCP连接: TCPConnector): Promise<TCPSocket> {
	const proxy = state.parsedSocks5Address as { username?: string; password?: string; hostname: string; port: number };
	const { username, password, hostname, port } = proxy;
	const socket = TCP连接({ hostname, port });
	const writer = socket.writable.getWriter();
	const reader = socket.readable.getReader();
	try {
		const authMethods = username && password ? new Uint8Array([0x05, 0x02, 0x00, 0x02]) : new Uint8Array([0x05, 0x01, 0x00]);
		await writer.write(authMethods);
		let response = await reader.read();
		if (response.done || response.value.byteLength < 2) throw new Error('S5 method selection failed');

		const selectedMethod = response.value[1];
		if (selectedMethod === 0x02) {
			if (!username || !password) throw new Error('S5 requires authentication');
			const userBytes = new TextEncoder().encode(username);
			const passBytes = new TextEncoder().encode(password);
			const authPacket = new Uint8Array([0x01, userBytes.length, ...userBytes, passBytes.length, ...passBytes]);
			await writer.write(authPacket);
			response = await reader.read();
			if (response.done || response.value[1] !== 0x00) throw new Error('S5 authentication failed');
		} else if (selectedMethod !== 0x00) throw new Error(`S5 unsupported auth method: ${selectedMethod}`);

		const hostBytes = new TextEncoder().encode(targetHost);
		const connectPacket = new Uint8Array([0x05, 0x01, 0x00, 0x03, hostBytes.length, ...hostBytes, targetPort >> 8, targetPort & 0xff]);
		await writer.write(connectPacket);
		response = await reader.read();
		if (response.done || response.value[1] !== 0x00) throw new Error('S5 connection failed');

		if (有效数据长度(initialData) > 0 && initialData) await writer.write(initialData);
		writer.releaseLock();
		reader.releaseLock();
		return socket;
	} catch (error) {
		try { writer.releaseLock(); } catch { /* ignore */ }
		try { reader.releaseLock(); } catch { /* ignore */ }
		try { socket.close(); } catch { /* ignore */ }
		throw error;
	}
}

export async function httpConnect(targetHost: string, targetPort: number, initialData: Uint8Array | null, HTTPS代理: boolean, TCP连接: TCPConnector): Promise<TCPSocket> {
	const proxy = state.parsedSocks5Address as { username?: string; password?: string; hostname: string; port: number };
	const { username, password, hostname, port } = proxy;
	const socket = HTTPS代理 ? TCP连接({ hostname, port }, { secureTransport: 'on', allowHalfOpen: false }) : TCP连接({ hostname, port });
	const writer = socket.writable.getWriter();
	const reader = socket.readable.getReader();
	const encoder = new TextEncoder();
	const decoder = new TextDecoder();
	try {
		if (HTTPS代理 && socket.opened) await socket.opened;

		const auth = username && password ? `Proxy-Authorization: Basic ${btoa(`${username}:${password}`)}\r\n` : '';
		const request = `CONNECT ${targetHost}:${targetPort} HTTP/1.1\r\nHost: ${targetHost}:${targetPort}\r\n${auth}User-Agent: Mozilla/5.0\r\nConnection: keep-alive\r\n\r\n`;
		await writer.write(encoder.encode(request));
		writer.releaseLock();

		let responseBuffer = new Uint8Array(0);
		let headerEndIndex = -1;
		let bytesRead = 0;
		while (headerEndIndex === -1 && bytesRead < 8192) {
			const { done, value } = await reader.read();
			if (done || !value) throw new Error(`${HTTPS代理 ? 'HTTPS' : 'HTTP'} 代理在返回 CONNECT 响应前关闭连接`);
			responseBuffer = new Uint8Array([...responseBuffer, ...value]);
			bytesRead = responseBuffer.length;
			const crlfcrlf = responseBuffer.findIndex((_, i) => i < responseBuffer.length - 3 && responseBuffer[i] === 0x0d && responseBuffer[i + 1] === 0x0a && responseBuffer[i + 2] === 0x0d && responseBuffer[i + 3] === 0x0a);
			if (crlfcrlf !== -1) headerEndIndex = crlfcrlf + 4;
		}

		if (headerEndIndex === -1) throw new Error('代理 CONNECT 响应头过长或无效');
		const statusMatch = decoder.decode(responseBuffer.slice(0, headerEndIndex)).split('\r\n')[0].match(/HTTP\/\d\.\d\s+(\d+)/);
		const statusCode = statusMatch ? parseInt(statusMatch[1], 10) : NaN;
		if (!Number.isFinite(statusCode) || statusCode < 200 || statusCode >= 300) throw new Error(`Connection failed: HTTP ${statusCode}`);

		reader.releaseLock();

		if (有效数据长度(initialData) > 0 && initialData) {
			const w = socket.writable.getWriter();
			await w.write(initialData);
			w.releaseLock();
		}

		// CONNECT 响应头后可能夹带隧道数据，先回灌到可读流，避免首包被吞。
		if (bytesRead > headerEndIndex) {
			const { readable, writable } = new TransformStream<Uint8Array, Uint8Array>();
			const transformWriter = writable.getWriter();
			await transformWriter.write(responseBuffer.subarray(headerEndIndex, bytesRead));
			transformWriter.releaseLock();
			socket.readable.pipeTo(writable).catch(() => { /* ignore */ });
			return { readable, writable: socket.writable, closed: socket.closed, close: () => socket.close() };
		}

		return socket;
	} catch (error) {
		try { writer.releaseLock(); } catch { /* ignore */ }
		try { reader.releaseLock(); } catch { /* ignore */ }
		try { socket.close(); } catch { /* ignore */ }
		throw error;
	}
}

export async function httpsConnect(targetHost: string, targetPort: number, initialData: Uint8Array | null, TCP连接: TCPConnector): Promise<TCPSocket> {
	const proxy = state.parsedSocks5Address as { username?: string; password?: string; hostname: string; port: number };
	const { username, password, hostname, port } = proxy;
	const encoder = new TextEncoder();
	const decoder = new TextDecoder();
	let tlsSocket: TlsClient | null = null;
	const tlsServerName = isIPHostname(hostname) ? '' : stripIPv6Brackets(hostname);
	const 打开HTTPS代理TLS = async (allowChacha = false): Promise<TlsClient> => {
		const proxySocket = TCP连接({ hostname, port });
		try {
			if (proxySocket.opened) await proxySocket.opened;
			const tls = new TlsClient(proxySocket, { serverName: tlsServerName, insecure: true, allowChacha });
			await tls.handshake();
			log(`[HTTPS代理] TLS版本: ${tls.isTls13 ? '1.3' : '1.2'} | Cipher: 0x${tls.cipherSuite?.toString(16)}${tls.cipherConfig?.chacha ? ' (ChaCha20)' : ' (AES-GCM)'}`);
			return tls;
		} catch (error) {
			try { proxySocket.close(); } catch { /* ignore */ }
			throw error;
		}
	};
	try {
		try {
			tlsSocket = await 打开HTTPS代理TLS(false);
		} catch (error) {
			const message = (error as { message?: string })?.message || `${error || ''}`;
			if (!/cipher|handshake|TLS Alert|ServerHello|Finished|Unsupported|Missing TLS/i.test(message)) throw error;
			log(`[HTTPS代理] AES-GCM TLS 握手失败，回退 ChaCha20 兼容模式: ${message}`);
			tlsSocket = await 打开HTTPS代理TLS(true);
		}

		const auth = username && password ? `Proxy-Authorization: Basic ${btoa(`${username}:${password}`)}\r\n` : '';
		const request = `CONNECT ${targetHost}:${targetPort} HTTP/1.1\r\nHost: ${targetHost}:${targetPort}\r\n${auth}User-Agent: Mozilla/5.0\r\nConnection: keep-alive\r\n\r\n`;
		await tlsSocket.write(encoder.encode(request));

		let responseBuffer = new Uint8Array(0);
		let headerEndIndex = -1;
		let bytesRead = 0;
		while (headerEndIndex === -1 && bytesRead < 8192) {
			const value = await tlsSocket.read();
			if (!value) throw new Error('HTTPS 代理在返回 CONNECT 响应前关闭连接');
			responseBuffer = 拼接字节数据(responseBuffer, value);
			bytesRead = responseBuffer.length;
			const crlfcrlf = responseBuffer.findIndex((_, i) => i < responseBuffer.length - 3 && responseBuffer[i] === 0x0d && responseBuffer[i + 1] === 0x0a && responseBuffer[i + 2] === 0x0d && responseBuffer[i + 3] === 0x0a);
			if (crlfcrlf !== -1) headerEndIndex = crlfcrlf + 4;
		}

		if (headerEndIndex === -1) throw new Error('HTTPS 代理 CONNECT 响应头过长或无效');
		const statusMatch = decoder.decode(responseBuffer.slice(0, headerEndIndex)).split('\r\n')[0].match(/HTTP\/\d\.\d\s+(\d+)/);
		const statusCode = statusMatch ? parseInt(statusMatch[1], 10) : NaN;
		if (!Number.isFinite(statusCode) || statusCode < 200 || statusCode >= 300) throw new Error(`Connection failed: HTTP ${statusCode}`);

		if (有效数据长度(initialData) > 0 && initialData) await tlsSocket.write(数据转Uint8Array(initialData));
		const bufferedData = bytesRead > headerEndIndex ? responseBuffer.subarray(headerEndIndex, bytesRead) : null;
		const tls = tlsSocket;
		let closedSettled = false;
		let resolveClosed: (() => void) | null = null;
		let rejectClosed: ((err: unknown) => void) | null = null;
		const closed = new Promise<void>((resolve, reject) => {
			resolveClosed = resolve;
			rejectClosed = reject;
		});
		const close = (): void => {
			try { tls.close(); } catch { /* ignore */ }
			if (!closedSettled) {
				closedSettled = true;
				resolveClosed?.();
			}
		};
		const readable = new ReadableStream<Uint8Array>({
			async start(controller) {
				try {
					if (有效数据长度(bufferedData) > 0 && bufferedData) controller.enqueue(bufferedData);
					for (;;) {
						const data = await tls.read();
						if (!data) break;
						if (data.byteLength > 0) controller.enqueue(data);
					}
					try { controller.close(); } catch { /* ignore */ }
					if (!closedSettled) {
						closedSettled = true;
						resolveClosed?.();
					}
				} catch (error) {
					try { controller.error(error); } catch { /* ignore */ }
					if (!closedSettled) {
						closedSettled = true;
						rejectClosed?.(error);
					}
				}
			},
			cancel() {
				close();
			},
		});
		const writable = new WritableStream<Uint8Array>({
			async write(chunk) {
				await tls.write(数据转Uint8Array(chunk));
			},
			close,
			abort(error) {
				close();
				if (error && !closedSettled) {
					closedSettled = true;
					rejectClosed?.(error);
				}
			},
		});
		return { readable, writable, closed, close };
	} catch (error) {
		try { tlsSocket?.close(); } catch { /* ignore */ }
		throw error;
	}
}
