import { BinaryReader } from 'binary-rw';
import { type Socket } from 'net';

export function rejectOnSocketError(signal: AbortSignal, socket: Socket, reject: (error: Error) => void): () => void {
    let rejected = false;

    function cleanup(): void {
        socket.off('error', errorHandler);
        socket.off('close', closeHandler);
        signal.removeEventListener('abort', abortHandler);
    }

    function errorHandler(error: Error): void {
        if (rejected) return;
        rejected = true;
        cleanup();
        reject(error);
    }
    function closeHandler(): void {
        errorHandler(new Error('Socket closed'));
    }
    function abortHandler(): void {
        socket.destroy();
        errorHandler(signal.reason);
    }

    socket.on('error', errorHandler);
    socket.on('close', closeHandler);
    signal.addEventListener('abort', abortHandler);

    return cleanup;
}

export async function readBytes(signal: AbortSignal, socket: Socket, length: number): Promise<BinaryReader> {
    if (signal.aborted) throw signal.reason;
    return new Promise((resolve, reject) => {
        const buffer = Buffer.allocUnsafe(length);
        let bytesRead = 0;

        const cleanup = rejectOnSocketError(signal, socket, (error: Error) => {
            socket.off('readable', dataHandler);
            reject(error);
        });
        socket.on('readable', dataHandler);

        function dataHandler(): void {
            const chunk: Buffer | null = socket.read(length - bytesRead);
            if (!chunk) return;

            chunk.copy(buffer, bytesRead);
            bytesRead += chunk.length;

            if (bytesRead === length) {
                socket.off('readable', dataHandler);
                cleanup();
                resolve(new BinaryReader(buffer.buffer, buffer.byteOffset));
            }
        }
    });
}

export function isObject(value: unknown): boolean {
    return typeof value === 'object' && value !== null && !Array.isArray(value);
}

export function isValidDomain(domain: string): boolean {
    return /^[\p{L}\p{N}](?:[\p{L}\p{N}-]{0,61}[\p{L}\p{N}])?(?:\.[\p{L}\p{N}](?:[\p{L}\p{N}-]{0,61}[\p{L}\p{N}])?)*$/u.test(domain);
}

export function isValidPort(port: number): boolean {
    return Number.isInteger(port) && port >= 1 && port <= 65535;
}