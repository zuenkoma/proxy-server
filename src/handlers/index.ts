import { Buffer } from 'node:buffer';
import type { Socket } from 'node:net';
import type { Config } from '../config/index.ts';
import type { DNS } from '../dns.ts';
import { rejectOnSocketError } from '../utils.ts';
import { checkHttp, httpHandler } from './http.ts';
import { checkSocks5, socks5Handler } from './socks5.ts';
import { checkTls, tlsHandler } from './tls.ts';

const protocols: [(buffer: Uint8Array) => boolean | null, typeof handleProtocol][] = [
    [checkTls, tlsHandler],
    [checkSocks5, socks5Handler],
    [checkHttp, httpHandler]
];

function detectProtocol(buffer: Uint8Array): typeof handleProtocol | false | null {
    let found = false;
    for (const [checkProtocol, handler] of protocols) {
        const result = checkProtocol(buffer);
        if (result) return handler;
        if (result === null) found = true;
    }
    return found ? null : false;
}

export default async function handleProtocol(signal: AbortSignal, socket: Socket, dns: DNS, config: Config, connections: Map<Socket, string[]>, inTls = false): Promise<void> {
    if (signal.aborted) throw signal.reason;
    return new Promise((resolve, reject) => {
        let buffer = Buffer.alloc(0);

        const cleanup = rejectOnSocketError(signal, socket, (error: Error) => {
            socket.off('data', dataHandler);
            reject(error);
        });
        socket.on('data', dataHandler);

        function dataHandler(data: Buffer) {
            buffer = Buffer.concat([buffer, data]);
            const handler = detectProtocol(buffer);
            if (handler !== null) {
                socket.off('data', dataHandler);
                cleanup();
                socket.unshift(buffer);
                if (handler) resolve(handler(signal, socket, dns, config, connections, inTls));
                else reject(new Error('Failed to detect protocol'));
            }
        }
    });
}