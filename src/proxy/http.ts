import { request as httpRequest } from 'node:http';
import type { Socket } from 'node:net';
import type { User } from '../user.ts';

export default function connectHttpProxy(signal: AbortSignal, socket: Socket, host: string, port: number, auth?: User): Promise<void> {
    if (signal.aborted) throw signal.reason;

    return new Promise((resolve, reject) => {
        const hostPort = `${host}:${port}`;
        const request = httpRequest({
            createConnection: () => socket,
            method: 'CONNECT',
            path: hostPort,
            headers: {
                Host: hostPort,
                ...auth && {
                    'Proxy-Authorization': 'Basic ' + btoa(`${auth.username}:${auth.password}`)
                }
            }
        }, response => {
            if (response.statusCode !== 200) {
                request.off('error', errorHandler);
                signal.removeEventListener('abort', abortHandler);
                reject(new Error(`Proxy connection failed with status ${response.statusCode}`));
            }
        });

        request.on('connect', (_response, socket, head) => {
            request.off('error', errorHandler);
            signal.removeEventListener('abort', abortHandler);
            socket.unshift(head);
            resolve();
        });

        function errorHandler(error: Error) {
            signal.removeEventListener('abort', abortHandler);
            reject(error);
        }
        function abortHandler() {
            socket.destroy();
            reject(signal.reason);
        }

        request.once('error', errorHandler);
        signal.addEventListener('abort', abortHandler);

        request.end();
    });
}