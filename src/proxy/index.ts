import { type Socket } from 'node:net';
import { connect } from '../connection.ts';
import type { DNS } from '../dns.ts';
import { logError } from '../logger.ts';
import type { Proxy } from '../rule.ts';
import connectHttpProxy from './http.ts';
import connectSocks5Proxy from './socks5.ts';

export default async function connectProxy(signal: AbortSignal, proxy: Proxy, host: string, port: number, dns: DNS, debug: boolean): Promise<Socket> {
    let socket: Socket;
    try {
        socket = await connect(signal, proxy.host, proxy.port, proxy.tls, dns);
    }
    catch {
        if (debug) logError(`Failed to connect to proxy ${proxy.host}:${proxy.port}`);
        throw new Error(`Failed to connect to proxy ${proxy.host}:${proxy.port}`);
    }
    if (proxy.protocol === 'socks5') await connectSocks5Proxy(signal, socket, host, port, proxy.auth);
    if (proxy.protocol === 'http') await connectHttpProxy(signal, socket, host, port, proxy.auth);
    return socket;
}