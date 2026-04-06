import { readFile } from 'node:fs/promises';
import type { Socket } from 'node:net';
import { TLSSocket, createSecureContext, type SecureContext } from 'node:tls';
import { type Config } from '../config/index.ts';
import type { DNS } from '../dns.ts';
import { readBytes } from '../utils.ts';
import handlerHttp from './http.ts';
import handlerSocks5 from './socks5.ts';

const secureContexts = new WeakMap<Config, SecureContext>();
export default async function handlerTls(socket: Socket, dns: DNS, config: Config, connections: Map<Socket, string | null>): Promise<void> {
    if (!secureContexts.has(config)) {
        const [key, cert] = await Promise.all([
            readFile(config['tls-key']!),
            readFile(config['tls-cert']!)
        ]);
        secureContexts.set(config, createSecureContext({ key, cert }));
    }

    const tlsSocket = new TLSSocket(socket, {
        isServer: true,
        secureContext: secureContexts.get(config)!
    });

    const firstByte = (await readBytes(tlsSocket, 1)).readUint8();
    tlsSocket.unshift(new Uint8Array([firstByte]));

    switch (firstByte) {
        case 0x05:
            if (config['socks5-tls']) await handlerSocks5(tlsSocket, dns, config, connections);
            else tlsSocket.destroy();
            break;

        case 0x43:
            if (config['http-tls']) await handlerHttp(tlsSocket, dns, config, connections);
            else tlsSocket.destroy();
            break;

        default:
            tlsSocket.destroy();
            break;
    }
}