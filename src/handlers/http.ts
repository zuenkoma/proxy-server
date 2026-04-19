import { isIPv4, isIPv6, type Socket } from 'net';
import { domainToUnicode } from 'url';
import type { Config } from '../config/index.ts';
import { connect } from '../connection.ts';
import type { DNS } from '../dns.ts';
import type { Host } from '../host.ts';
import { logInfo } from '../logger.ts';
import connectProxy from '../proxy/index.ts';
import { matchRule } from '../rule.ts';
import { findUser } from '../user.ts';
import { isValidDomain, isValidPort } from '../utils.ts';

interface HttpHeader {
    method: string;
    host: Host;
    port: number;
    headers: Record<string, string>;
}

function readHttpHeader(signal: AbortSignal, socket: Socket): Promise<HttpHeader> {
    if (signal.aborted) throw signal.reason;

    let buffer = Buffer.alloc(0);

    return new Promise((resolve, reject) => {
        function dataHandler(chunk: Buffer) {
            buffer = Buffer.concat([buffer, chunk]);
            const headerEnd = buffer.indexOf('\r\n\r\n');

            if (headerEnd !== -1) {
                socket.off('data', dataHandler);
                socket.off('error', errorHandler);
                socket.off('close', errorHandler);
                signal.removeEventListener('abort', abortHandler);

                const headerPart = buffer.subarray(0, headerEnd);
                const remaining = buffer.subarray(headerEnd + 4);
                if (remaining.length) socket.unshift(remaining);

                const lines = headerPart.toString().split('\r\n');
                const firstLine = lines[0];
                const parts = firstLine.split(' ');

                if (parts.length !== 3 || parts[0] !== 'CONNECT') {
                    reject(new Error('Invalid request: only CONNECT method supported'));
                    return;
                }

                const target = parts[1];
                const [hostStr, portStr] = target.split(':');

                let host: Host;
                if (isIPv4(hostStr)) host = { type: 'ipv4', host: hostStr };
                else if (isIPv6(hostStr)) host = { type: 'ipv6', host: hostStr };
                else if (isValidDomain(hostStr)) host = { type: 'domain', host: domainToUnicode(hostStr) };
                else {
                    reject(new Error('Invalid host'));
                    return;
                }

                const port = +portStr;
                if (!isValidPort(port)) {
                    reject(new Error('Invalid port'));
                    return;
                }

                const headers: Record<string, string> = {};
                for (let i = 1; i < lines.length; i++) {
                    const line = lines[i];
                    if (line === '') continue;

                    const colonIdx = line.indexOf(':');
                    if (colonIdx !== -1) {
                        const key = line.substring(0, colonIdx).trim().toLowerCase();
                        const value = line.substring(colonIdx + 1).trim();
                        headers[key] = value;
                    }
                }

                resolve({
                    method: parts[0],
                    host, port, headers
                });
            }
        }
        function errorHandler(error: Error) {
            socket.off('data', dataHandler);
            socket.off('close', errorHandler);
            signal.removeEventListener('abort', abortHandler);
            reject(error);
        }
        function abortHandler() {
            reject(signal.reason);
        }

        socket.on('data', dataHandler);
        socket.on('error', errorHandler);
        socket.on('close', errorHandler);
        signal.addEventListener('abort', abortHandler);
    });
}

export default async function handlerHttp(signal: AbortSignal, socket: Socket, dns: DNS, config: Config, connections: Map<Socket, string | null>): Promise<void> {
    if (signal.aborted) throw signal.reason;

    let host: Host, port: number, headers: Record<string, string>;
    try {
        ({ host, port, headers } = await readHttpHeader(signal, socket));
    }
    catch {
        socket.write('HTTP/1.1 400 Bad Request\r\n\r\n');
        socket.end();
        return;
    }

    if (config.users.length) {
        const authHeader = headers['proxy-authorization'];
        if (!authHeader) {
            socket.write('HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm="Proxy"\r\n\r\n');
            socket.end();
            return;
        }

        const [scheme, credentials] = authHeader.split(' ');
        if (scheme.toLowerCase() !== 'basic') {
            socket.write('HTTP/1.1 400 Bad Request\r\n\r\n');
            socket.end();
            return;
        }

        const decoded = atob(credentials);
        const [username, password] = decoded.split(':');

        const user = findUser(config.users, username, password);
        if (!user) {
            socket.write('HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm="Proxy"\r\n\r\n');
            socket.end();
            return;
        }

        if (user !== true && user.maxIps !== null) {
            connections.set(socket, username);

            const connectedIps = new Set<string>();
            for (const [socket, connUsername] of connections) {
                if (connUsername) connectedIps.add(socket.remoteAddress!);
            }

            if (connectedIps.size > user.maxIps) {
                socket.write('HTTP/1.1 429 Too Many Requests\r\n\r\n');
                socket.end();
                return;
            }
        }
    }

    const rule = await matchRule(config.rules, host, port, dns);
    if (config.debug) logInfo(`Connect to ${host.host}:${port} (${rule.type})`);

    let targetSocket: Socket;
    switch (rule.type) {
        case 'allow':
            try {
                targetSocket = await connect(signal, host, port, false, dns);
                break;
            }
            catch {
                socket.write('HTTP/1.1 502 Bad Gateway\r\n\r\n');
                socket.end();
                return;
            }

        case 'deny':
            socket.write('HTTP/1.1 403 Forbidden\r\n\r\n');
            socket.end();
            return;

        case 'proxy':
            try {
                targetSocket = await connectProxy(signal, rule.proxy, host.host, port, dns, config.debug);
                break;
            }
            catch {
                socket.write('HTTP/1.1 502 Bad Gateway\r\n\r\n');
                socket.end();
                return;
            }
    }

    socket.write('HTTP/1.1 200 Connection established\r\n\r\n');

    targetSocket.once('error', () => socket.destroy());
    targetSocket.once('end', () => socket.end());
    socket.once('error', () => targetSocket.destroy());
    socket.once('end', () => targetSocket.end());

    socket.pipe(targetSocket);
    targetSocket.pipe(socket);
}