import type { Socket } from 'node:net';
import type { User } from '../users.ts';

export default function connectSocks5Proxy(socket: Socket, host: string, port: number, user?: User) {
    return Promise.reject(new Error('Not implemented'));
}