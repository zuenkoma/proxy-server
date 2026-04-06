import { createConnection, isIPv4, isIPv6, type Socket } from 'node:net';
import { domainToUnicode } from 'node:url';
import type { DNS } from './dns.ts';
import type { Host } from './host.ts';
import { logError } from './logger.ts';

function tryConnectSocket(ip: string, port: number, debug: boolean): Promise<Socket> {
    return new Promise((resolve, reject) => {
        const socket = createConnection(port, ip, () => {
            socket.off('error', reject);
            if (debug) socket.on('error', logError);
            resolve(socket);
        });
        socket.once('error', reject);
    });
}

export async function connectSocket(host: Host, port: number, dns: DNS, debug: boolean): Promise<Socket> {
    if (isIPv4(host.host) || isIPv6(host.host)) {
        try {
            return await tryConnectSocket(host.host, port, debug);
        }
        catch {
            if (debug) logError(`Failed to connect to ${host.host}:${port}`);
            throw new Error(`Failed to connect to ${host.host}:${port}`);
        }

    }

    const domain = domainToUnicode(host.host);
    for (const ip of await dns.lookup(domain)) {
        try {
            return await tryConnectSocket(ip.address, port, debug);
        }
        catch { }
    }

    if (debug) logError(`Failed to connect to ${domain}:${port}`);
    throw new Error(`Failed to connect to ${domain}:${port}`);
}