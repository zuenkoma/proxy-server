import { BinaryReader } from 'binary-rw';
import { type Socket } from 'net';
import { type Config } from '../config/index.ts';
import { connectSocket } from '../connection.ts';
import type { DNS } from '../dns.ts';
import type { Host } from '../host.ts';
import { logInfo } from '../logger.ts';
import connectProxy from '../proxy/index.ts';
import { matchRule } from '../rule.ts';
import { hasAccess } from '../user.ts';
import { readBytes } from '../utils.ts';

function createConnectReply(status: number) {
    return new Uint8Array([
        0x05, // Version
        status,
        0x00, // Reserved
        0x01, // Address type: IPv4
        0x00, 0x00, 0x00, 0x00, // Address
        0x00, 0x00 // Port
    ]);
}

export default async function handlerSocks5(socket: Socket, dns: DNS, config: Config): Promise<void> {
    // Handshake
    {
        const reader1 = await readBytes(socket, 2);
        reader1.skip(1); // Version

        const methodCount = reader1.readUint8();
        const reader2 = await readBytes(socket, methodCount);

        let loginMethod = 0xFF;
        for (let i = 0; i < methodCount; ++i) {
            const method = reader2.readUint8();
            if (
                method === 0x00 && !config.users.length ||
                method === 0x02 && config.users.length
            ) {
                loginMethod = method;
                break;
            }
        }

        socket.write(new Uint8Array([
            0x05, // Version
            loginMethod // Method
        ]));
        if (loginMethod === 0xFF) {
            socket.end();
            return;
        }
    }

    // Auth
    if (config.users.length) {
        const reader1 = await readBytes(socket, 2);

        const authVersion = reader1.readUint8();
        if (authVersion !== 0x01) throw new Error('Auth: invalid auth version');

        const usernameLen = reader1.readUint8();
        const reader2 = await readBytes(socket, usernameLen + 1);
        const username = reader2.readString(usernameLen);

        const passwordLen = reader2.readUint8();
        const reader3 = await readBytes(socket, passwordLen);
        const password = reader3.readString(passwordLen);

        if (!hasAccess(config.users, username, password)) {
            socket.end(new Uint8Array([
                0x01, // Auth version
                0x01 // Failure
            ]));
            return;
        }

        socket.write(new Uint8Array([
            0x01, // Auth version
            0x00 // Success
        ]));
    }

    // Request
    {
        const reader1 = await readBytes(socket, 4);

        const version = reader1.readUint8();
        if (version !== 0x05) {
            socket.destroy();
            return;
        }

        const command = reader1.readUint8();
        if (command < 0x01 || command > 0x03) throw new Error('Request: unsupported command');

        const reserved = reader1.readUint8();
        if (reserved !== 0x00) throw new Error('Request: invalid reserved field');

        const addressType = reader1.readUint8();
        let host: Host, reader2: BinaryReader;
        switch (addressType) {
            case 0x01: { // IPv4
                reader2 = await readBytes(socket, 6);
                host = {
                    type: 'ipv4',
                    host: Array.from({ length: 4 }, () => reader2.readUint8()).join('.')
                };
                break;
            }
            case 0x03: { // Domain
                const reader1 = await readBytes(socket, 1);
                const domainLen = reader1.readUint8();
                reader2 = await readBytes(socket, domainLen + 2);
                host = {
                    type: 'domain',
                    host: reader2.readString(domainLen)
                };
                break;
            }
            case 0x04: { // IPv6
                reader2 = await readBytes(socket, 18);
                host = {
                    type: 'ipv6',
                    host: Array.from({ length: 8 }, () => reader2.readUint16().toString(16).padStart(4, '0')).join(':')
                };
                break;
            }
            default:
                throw new Error('Request: unsupported address type');
        }

        const port = reader2.readUint16();

        // Support TCP connection only (0x01)
        if (command !== 0x01) {
            socket.end(createConnectReply(0x07));
            return;
        }

        const rule = await matchRule(config.rules, host, port, dns);
        if (config.debug) logInfo(`Connect to ${host.host}:${port} (${rule.type})`);

        let targetSocket: Socket;
        switch (rule.type) {
            case 'allow': {
                try {
                    targetSocket = await connectSocket(host, port, dns, config.debug);
                    break;
                }
                catch {
                    socket.end(createConnectReply(0x04)); // Host unreachable
                    return;
                }
            }

            case 'deny':
                socket.end(createConnectReply(0x02)); // Connection forbidden
                return;

            case 'proxy': {
                try {
                    targetSocket = await connectProxy(rule.proxy, host.host, port, dns, config.debug);
                    break;
                }
                catch {
                    socket.end(createConnectReply(0x04)); // Host unreachable
                    return;
                }
            }
        }

        socket.write(createConnectReply(0x00));

        targetSocket.once('error', () => socket.destroy());
        targetSocket.once('end', () => socket.end());
        socket.once('error', () => targetSocket.destroy());
        socket.once('end', () => targetSocket.end());

        socket.pipe(targetSocket);
        targetSocket.pipe(socket);
    }
}