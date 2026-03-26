import { createConnection, isIPv4, isIPv6, type Socket } from 'net';
import type { Config } from '../config.ts';
import { hasAccess } from '../users.ts';
import { isPrivateDomain, isPrivateIPv4, isPrivateIPv6 } from '../utils.ts';
import { matchRule } from '../rules.ts';
import connectProxy from '../proxy/index.ts';

interface HttpHeader {
    method: string;
    host: string;
    port: number;
    headers: Record<string, string>;

}

function readHttpHeader(socket: Socket): Promise<HttpHeader> {
    let buffer = Buffer.alloc(0);

    return new Promise((resolve, reject) => {
        function onData(chunk: Buffer) {
            buffer = Buffer.concat([buffer, chunk]);
            const headerEnd = buffer.indexOf('\r\n\r\n');

            if (headerEnd !== -1) {
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
                const [host, portStr] = target.split(':');
                const port = parseInt(portStr, 10);

                if (isNaN(port) || port < 1 || port > 65535) {
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

                socket.off('data', onData);
                socket.off('error', onError);
                socket.off('close', onClose);

                resolve({
                    method: parts[0],
                    host, port, headers
                });
            }
        }

        function onError(error: Error) {
            socket.off('data', onData);
            socket.off('error', onError);
            socket.off('close', onClose);
            reject(error);
        }

        function onClose() {
            socket.off('data', onData);
            socket.off('error', onError);
            socket.off('close', onClose);
            reject(new Error('Socket closed while reading header'));
        }

        socket.on('data', onData);
        socket.on('error', onError);
        socket.on('close', onClose);
    });
}

export default async function handlerHttp(socket: Socket, config: Config) {
    const { host, port, headers } = await readHttpHeader(socket);

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

        if (!hasAccess(config.users, username, password)) {
            socket.write('HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm="Proxy"\r\n\r\n');
            socket.end();
            return;
        }
    }

    if (isIPv4(host)) {
        if (isPrivateIPv4(host)) {
            socket.write('HTTP/1.1 403 Forbidden\r\n\r\n');
            socket.end();
            return;
        }
    }
    else if (isIPv6(host)) {
        if (isPrivateIPv6(host)) {
            socket.write('HTTP/1.1 403 Forbidden\r\n\r\n');
            socket.end();
            return;
        }
    }
    else {
        if (isPrivateDomain(host)) {
            socket.write('HTTP/1.1 403 Forbidden\r\n\r\n');
            socket.end();
            return;
        }
    }

    const rule = matchRule(config.rules, host, port);

    let targetSocket: Socket;
    switch (rule.type) {
        case 'allow':
            targetSocket = createConnection(port, host);
            break;

        case 'deny':
            socket.write('HTTP/1.1 403 Forbidden\r\n\r\n');
            socket.end();
            return;

        case 'proxy':
            try {
                targetSocket = await connectProxy(rule.proxy, host, port);
            }
            catch {
                socket.write('HTTP/1.1 502 Bad Gateway\r\n\r\n');
                socket.end();
                return;
            }
            break;
    }

    socket.write('HTTP/1.1 200 Connection established\r\n\r\n');

    targetSocket.once('error', () => socket.destroy());
    targetSocket.once('end', () => socket.end());
    socket.once('error', () => targetSocket.destroy());
    socket.once('end', () => targetSocket.end());

    socket.pipe(targetSocket);
    targetSocket.pipe(socket);
}