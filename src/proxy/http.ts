import type { Socket } from 'node:net';
import type { User } from '../user.ts';

export default function connectHttpProxy(signal: AbortSignal, socket: Socket, host: string, port: number, auth?: User): Promise<void> {
    if (signal.aborted) throw signal.reason;
    return new Promise((resolve, reject) => {
        let response = Buffer.alloc(0);
        function dataHandler(chunk: Buffer) {
            response = Buffer.concat([response, chunk]);

            const headerEnd = response.indexOf('\r\n\r\n');
            if (headerEnd > -1) {
                const remaining = response.subarray(headerEnd + 4);
                if (remaining.length) socket.unshift(remaining);

                socket.off('data', dataHandler);
                socket.off('error', errorHandler);
                signal.removeEventListener('abort', abortHandler);

                const statusLine = response.toString().split('\r\n')[0];
                const statusMatch = statusLine.match(/HTTP\/\d\.\d\s+(\d+)/);
                const statusCode = statusMatch ? +statusMatch[1] : 0;

                if (statusCode === 200) resolve();
                else reject(new Error(`Proxy connection failed with status ${statusCode}`));
            }
        }
        function errorHandler(error: Error) {
            socket.off('data', dataHandler);
            signal.removeEventListener('abort', abortHandler);
            reject(error);
        }
        function abortHandler() {
            socket.destroy();
            reject(signal.reason);
        }

        socket.on('data', dataHandler);
        socket.once('error', errorHandler);
        signal.addEventListener('abort', abortHandler);

        socket.write(`CONNECT ${host}:${port} HTTP/1.1\r\nHost: ${host}:${port}${auth ? `\r\nProxy-Authorization: Basic ${btoa(`${auth.username}:${auth.password}`)}` : ''}\r\n\r\n`);
    });
}