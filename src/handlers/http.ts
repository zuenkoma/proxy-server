import { createServer as createHttpServer, request as httpRequest } from 'node:http';
import { request as httpsRequest } from 'node:https';
import { isIPv4, isIPv6, type Socket } from 'node:net';
import { domainToUnicode } from 'node:url';
import type { Config } from '../config/index.ts';
import { connect } from '../connection.ts';
import type { DNS } from '../dns.ts';
import type { Host } from '../host.ts';
import { logInfo } from '../logger.ts';
import connectProxy from '../proxy/index.ts';
import { matchRule } from '../rule.ts';
import { findUser, handleUserLimit } from '../user.ts';
import { isValidDomain, isValidPort } from '../utils.ts';

const decoder = new TextDecoder('latin1');
export function checkHttp(buffer: Uint8Array): boolean | null {
    let line = decoder.decode(buffer.subarray(0, Math.min(buffer.length, 8192)));
    const method = line.match(/^[-a-z0-9!#$%&'*+.^_`|~]+/i);
    if (!method) return false;
    line = line.slice(method[0].length);
    if (line !== '' && line[0] !== ' ') return false;
    const url = line.slice(1).match(/[-a-z0-9._~!$&'()*+,;=:@/?%\[\]]*/i);
    if (!url) return false;
    line = line.slice(url[0].length + 1).toUpperCase();
    if (line !== '' && !line.startsWith(' HTTP/1.'.slice(0, line.length))) return false;
    line = line.slice(8);
    if (line !== '' && !['0', '1'].includes(line[0]!)) return false;
    line = line.slice(1);
    if (line !== '' && !line.startsWith('\r\n'.slice(0, line.length))) return false;
    return line === '' ? null : true;
}

export async function httpHandler(signal: AbortSignal, socket: Socket, dns: DNS, config: Config, connections: Map<Socket, string[]>): Promise<void> {
    if (signal.aborted) throw signal.reason;

    const server = createHttpServer(async (request, response) => {
        let url: URL;
        try {
            url = new URL(request.url!);
            if (!['http:', 'https:'].includes(url.protocol)) throw new Error();
        }
        catch {
            response.writeHead(400).end();
            return;
        }

        let username: string | null = null;
        if (config.users.length) {
            const authHeader = request.headers['proxy-authorization'];
            if (!authHeader) {
                response.writeHead(407, { 'proxy-authenticate': 'Basic realm="Proxy"' }).end();
                return;
            }

            const [scheme, encodedCredentials] = authHeader.split(' ');
            if (!scheme || !encodedCredentials || scheme.toLowerCase() !== 'basic') {
                response.writeHead(400).end();
                return;
            }

            let decoded;
            try {
                decoded = atob(encodedCredentials);
            }
            catch {
                response.writeHead(400).end();
                return;
            }

            const credentials = decoded.split(':');
            if (credentials.length !== 2) {
                response.writeHead(400).end();
                return;
            }

            let password;
            [username, password] = credentials as [string, string];
            const user = findUser(config.users, username, password);
            if (!user) {
                response.writeHead(407, { 'proxy-authenticate': 'Basic realm="Proxy"' }).end();
                return;
            }

            if (user !== true && handleUserLimit(user, socket, connections)) {
                response.writeHead(429).end();
                return;
            }
        }

        let host: Host;
        if (isIPv4(url.hostname)) host = { type: 'ipv4', host: url.hostname };
        else if (isIPv6(url.hostname)) host = { type: 'ipv6', host: url.hostname };
        else host = { type: 'domain', host: domainToUnicode(url.hostname) };

        const port = url.port === '' ? url.protocol === 'http:' ? 80 : 443 : +url.port;

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
                    response.writeHead(502).end();
                    return;
                }

            case 'deny':
                response.writeHead(403).end();
                return;

            case 'proxy':
                try {
                    targetSocket = await connectProxy(signal, rule.proxy, host.host, port, dns, config.debug);
                    break;
                }
                catch {
                    response.writeHead(502).end();
                    return;
                }
        }

        const headers: Record<string, string[] | undefined> = { ...request.headersDistinct };
        delete headers.host;
        delete headers['proxy-authorization'];
        delete headers['proxy-connection'];

        const targetRequest = (url.protocol === 'http:' ? httpRequest : httpsRequest)(url.href, {
            method: request.method,
            headers,
            createConnection: () => targetSocket
        }, targetResponse => {
            response.writeHead(targetResponse.statusCode!, targetResponse.headers);
            targetResponse.pipe(response);
        });

        if (username !== null) {
            targetSocket.once('end', () => {
                const usernames = connections.get(socket)!;
                usernames.splice(usernames.indexOf(username), 1);
            });
        }

        targetSocket.once('error', () => response.end());
        request.once('error', () => targetSocket.end());
        response.once('error', () => targetSocket.end());

        request.pipe(targetRequest);
    });

    server.on('connect', async (request, httpSocket, head) => {
        const [hostStr, portStr] = request.url!.split(':');

        let host: Host;
        if (isIPv4(hostStr!)) host = { type: 'ipv4', host: hostStr! };
        else if (isIPv6(hostStr!)) host = { type: 'ipv6', host: hostStr! };
        else if (isValidDomain(hostStr!)) host = { type: 'domain', host: domainToUnicode(hostStr!) };
        else {
            httpSocket.write('HTTP/1.1 400 Bad Request\r\n\r\n');
            httpSocket.end();
            return;
        }

        if (portStr === undefined || !isValidPort(+portStr)) {
            httpSocket.write('HTTP/1.1 400 Bad Request\r\n\r\n');
            httpSocket.end();
            return;
        }
        const port = +portStr;

        if (config.users.length) {
            const authHeader = request.headers['proxy-authorization'];
            if (!authHeader) {
                httpSocket.write('HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm="Proxy"\r\n\r\n');
                httpSocket.end();
                return;
            }

            const [scheme, encodedCredentials] = authHeader.split(' ');
            if (!scheme || !encodedCredentials || scheme.toLowerCase() !== 'basic') {
                httpSocket.write('HTTP/1.1 400 Bad Request\r\n\r\n');
                httpSocket.end();
                return;
            }

            let decoded;
            try {
                decoded = atob(encodedCredentials);
            }
            catch {
                httpSocket.write('HTTP/1.1 400 Bad Request\r\n\r\n');
                httpSocket.end();
                return;
            }

            const credentials = decoded.split(':');
            if (credentials.length !== 2) {
                httpSocket.write('HTTP/1.1 400 Bad Request\r\n\r\n');
                httpSocket.end();
                return;
            }

            const [username, password] = credentials as [string, string];
            const user = findUser(config.users, username, password);
            if (!user) {
                httpSocket.write('HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm="Proxy"\r\n\r\n');
                httpSocket.end();
                return;
            }

            if (user !== true && handleUserLimit(user, socket, connections)) {
                httpSocket.write('HTTP/1.1 429 Too Many Requests\r\n\r\n');
                httpSocket.end();
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
                    httpSocket.write('HTTP/1.1 502 Bad Gateway\r\n\r\n');
                    httpSocket.end();
                    return;
                }

            case 'deny':
                httpSocket.write('HTTP/1.1 403 Forbidden\r\n\r\n');
                httpSocket.end();
                return;

            case 'proxy':
                try {
                    targetSocket = await connectProxy(signal, rule.proxy, host.host, port, dns, config.debug);
                    break;
                }
                catch {
                    httpSocket.write('HTTP/1.1 502 Bad Gateway\r\n\r\n');
                    httpSocket.end();
                    return;
                }
        }

        targetSocket.once('error', () => httpSocket.destroy());
        httpSocket.once('error', () => targetSocket.destroy());

        httpSocket.write('HTTP/1.1 200 Connection established\r\n\r\n');
        httpSocket.write(head);

        httpSocket.pipe(targetSocket);
        targetSocket.pipe(httpSocket);

    });

    server.emit('connection', socket);
}