import net from 'node:net';
import tls from 'node:tls';
import type { Proxy } from '../rules.ts';
import connectHttpProxy from './http.ts';
import connectSocks5Proxy from './socks5.ts';

function connectSocket(proxy: Proxy): Promise<net.Socket> {
    return new Promise((resolve, reject) => {
        function connectHandler() {
            socket.off('error', reject);
            resolve(socket);
        }
        const socket = proxy.tls ?
            tls.connect(proxy.port, proxy.host, {}, connectHandler) :
            net.connect(proxy.port, proxy.host, connectHandler);
        socket.once('error', reject);
    });
}

export default async function connectProxy(proxy: Proxy, host: string, port: number) {
    const socket = await connectSocket(proxy);
    if (proxy.proto === 'socks5') await connectSocks5Proxy(socket, host, port, proxy.auth);
    if (proxy.proto === 'http') await connectHttpProxy(socket, host, port, proxy.auth);
    return socket;
}