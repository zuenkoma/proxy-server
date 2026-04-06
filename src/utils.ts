import { BinaryReader } from 'binary-rw';
import { type Socket } from 'net';

export async function readBytes(socket: Socket, length: number): Promise<BinaryReader> {
    return new Promise((resolve, reject) => {
        const buffer = Buffer.allocUnsafe(length);
        let bytesRead = 0;

        function dataHandler() {
            const chunk: Buffer | null = socket.read(length - bytesRead);
            if (!chunk) return;

            chunk.copy(buffer, bytesRead);
            bytesRead += chunk.length;

            if (bytesRead === length) {
                socket.off('readable', dataHandler);
                socket.off('error', reject);
                socket.off('close', reject);
                resolve(new BinaryReader(buffer.buffer, buffer.byteOffset));
            }
        }

        socket.on('readable', dataHandler);
        socket.once('error', reject);
        socket.once('close', reject);
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