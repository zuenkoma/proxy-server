import { connect as connectTcp, type Socket } from 'node:net';
import { connect as connectTls } from 'node:tls';
import { domainToASCII } from 'node:url';
import type { DNS } from './dns.ts';
import type { Host } from './host.ts';

export class ConnectionError extends Error {
    readonly host: Host;
    readonly port: number;

    constructor(host: Host, port: number) {
        super(`Failed to connect to ${host.host}:${port}`);
        this.host = host;
        this.port = port;
    }
}

function connectIp(signal: AbortSignal, host: Host, ip: string, port: number, secure: boolean): Promise<Socket> {
    return new Promise((resolve, reject) => {
        function connectHandler() {
            socket.off('error', errorHandler);
            signal.removeEventListener('abort', abortHandler);
            resolve(socket);
        }
        function errorHandler() {
            signal.removeEventListener('abort', abortHandler);
            reject(new ConnectionError(host, port));
        }
        function abortHandler() {
            socket.destroy();
            reject(signal.reason);
        }

        const socket = secure
            ? connectTls(port, ip, { servername: host.type === 'domain' ? domainToASCII(host.host) : undefined }, connectHandler)
            : connectTcp(port, ip, connectHandler);
        socket.once('error', errorHandler);
        signal.addEventListener('abort', abortHandler);
    });
}

export async function connect(signal: AbortSignal, host: Host, port: number, secure: boolean, dns: DNS): Promise<Socket> {
    if (signal.aborted) throw signal.reason;

    if (host.type !== 'domain') {
        return await connectIp(signal, host, host.host, port, secure);
    }

    const ips = await dns.lookup(host.host);
    if (signal.aborted) throw signal.reason;

    const controllers: AbortController[] = [];
    function abortHandler() {
        for (const controller of controllers) {
            controller.abort(signal.reason);
        }
    }
    signal.addEventListener('abort', abortHandler);

    try {
        const [socket, winner] = await Promise.any(ips.map(async ip => {
            const controller = new AbortController();
            controllers.push(controller);
            return [
                await connectIp(controller.signal, host, ip.address, port, secure),
                controller
            ] as [Socket, AbortController];
        }));

        for (const controller of controllers) {
            if (controller !== winner) controller.abort();
        }
        return socket;
    }
    catch (error) {
        if (error instanceof AggregateError) throw new ConnectionError(host, port);
        throw error;
    }
    finally {
        signal.removeEventListener('abort', abortHandler);
    }
}