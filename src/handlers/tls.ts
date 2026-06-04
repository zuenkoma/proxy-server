import { readFile } from 'node:fs/promises';
import type { Socket } from 'node:net';
import { TLSSocket, createSecureContext, type SecureContext } from 'node:tls';
import { type Config } from '../config/index.ts';
import type { DNS } from '../dns.ts';
import handleProtocol from './index.ts';

export function checkTls(buffer: Uint8Array): boolean | null {
    return buffer[0] === 0x16;
}

const secureContexts = new WeakMap<Config, SecureContext>();
export async function tlsHandler(signal: AbortSignal, socket: Socket, dns: DNS, config: Config, connections: Map<Socket, string[]>): Promise<void> {
    if (signal.aborted) throw signal.reason;

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
    await handleProtocol(signal, tlsSocket, dns, config, connections, true);
}