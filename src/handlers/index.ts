import { Buffer } from 'node:buffer';
import type { Socket } from 'node:net';
import type { Config } from '../config/index.ts';
import type { DNS } from '../dns.ts';
import { rejectOnSocketError } from '../utils.ts';
import { checkHttp, httpHandler } from './http.ts';
import { checkSocks5, socks5Handler } from './socks5.ts';
import { checkTls, tlsHandler } from './tls.ts';

export default async function handleProtocol(signal: AbortSignal, socket: Socket, dns: DNS, config: Config, connections: Map<Socket, string[]>, inTls = false): Promise<void> {
    if (signal.aborted) throw signal.reason;

    return new Promise((resolve, reject) => {
        let buffer = Buffer.alloc(0);

        const cleanup = rejectOnSocketError(signal, socket, (error: Error) => {
            socket.off('readable', dataHandler);
            reject(error);
        });
        socket.on('readable', dataHandler);

        const protocols: [(buffer: Uint8Array) => boolean | null, typeof handleProtocol][] = [];
        if (inTls) {
            if (config['socks5-tls']) protocols.push([checkSocks5, socks5Handler]);
            if (config['http-tls']) protocols.push([checkHttp, httpHandler]);
        }
        else {
            if (config['socks5-tls'] || config['http-tls']) protocols.push([checkTls, tlsHandler]);
            if (config.socks5) protocols.push([checkSocks5, socks5Handler]);
            if (config.http) protocols.push([checkHttp, httpHandler]);
        }

        function dataHandler() {
            const chunk: Buffer | null = socket.read();
            if (chunk === null) return reject(new Error('Failed to detect protocol'));
            buffer = Buffer.concat([buffer, chunk]);

            let resultHandler: typeof handleProtocol | null | false = false;
            for (const [checkProtocol, handler] of protocols) {
                const result = checkProtocol(buffer);
                if (result === null) resultHandler = null;
                else if (result) {
                    resultHandler = handler;
                    break;
                }
            }

            if (resultHandler !== null || buffer.length > 8192) {
                socket.off('readable', dataHandler);
                cleanup();
                socket.unshift(buffer);

                if (resultHandler) resolve(resultHandler(signal, socket, dns, config, connections, inTls));
                else reject(new Error('Failed to detect protocol'));
            }
        }
    });
}