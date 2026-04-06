import net, { isIPv4, isIPv6 } from 'node:net';
import tls from 'node:tls';
import type { DNS } from '../dns.ts';
import { logError } from '../logger.ts';
import type { Proxy } from '../rule.ts';
import connectHttpProxy from './http.ts';
import connectSocks5Proxy from './socks5.ts';

function tryConnectSocket(proxy: Proxy, ip: string, debug: boolean): Promise<net.Socket> {
    return new Promise<net.Socket>((resolve, reject) => {
        function connectHandler() {
            socket.off('error', reject);
            if (debug) socket.on('error', logError);
            resolve(socket);
        }
        const socket = proxy.tls ?
            tls.connect(proxy.port, ip, { servername: proxy.host }, connectHandler) :
            net.connect(proxy.port, ip, connectHandler);
        socket.once('error', reject);
    });
}

async function connectSocket(proxy: Proxy, dns: DNS, debug: boolean): Promise<net.Socket> {
    if (isIPv4(proxy.host) || isIPv6(proxy.host)) {
        try {
            return await tryConnectSocket(proxy, proxy.host, debug);
        }
        catch {
            if (debug) logError(`Failed to connect to proxy ${proxy.host}:${proxy.port}`);
            throw new Error(`Failed to connect to proxy ${proxy.host}:${proxy.port}`);
        }
    }

    for (const ip of await dns.lookup(proxy.host)) {
        try {
            return await tryConnectSocket(proxy, ip.address, debug);
        }
        catch { }
    }

    if (debug) logError(`Failed to connect to proxy ${proxy.host}:${proxy.port}`);
    throw new Error(`Failed to connect to proxy ${proxy.host}:${proxy.port}`);
}

export default async function connectProxy(proxy: Proxy, host: string, port: number, dns: DNS, debug: boolean): Promise<net.Socket> {
    const socket = await connectSocket(proxy, dns, debug);
    if (proxy.protocol === 'socks5') await connectSocks5Proxy(socket, host, port, proxy.auth);
    if (proxy.protocol === 'http') await connectHttpProxy(socket, host, port, proxy.auth);
    return socket;
}