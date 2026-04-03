import { BinaryReader } from 'binary-rw';
import { createConnection, type Socket } from 'net';
import { type Config } from '../config.ts';
import { logInfo } from '../logger.ts';
import connectProxy from '../proxy/index.ts';
import { matchRule } from '../rules.ts';
import { hasAccess } from '../users.ts';
import { isPrivateDomain, isPrivateIPv4, isPrivateIPv6, readBytes } from '../utils.ts';

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

export default async function handlerSocks5(socket: Socket, config: Config) {
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
        if (loginMethod === 0xFF) return socket.end();
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
            return socket.end(new Uint8Array([
                0x01, // Auth version
                0x01 // Failure
            ]));
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
        if (version !== 0x05) return socket.destroy();

        const command = reader1.readUint8();
        if (command < 0x01 || command > 0x03) throw new Error('Request: unsupported command');

        const reserved = reader1.readUint8();
        if (reserved !== 0x00) throw new Error('Request: invalid reserved field');

        const addressType = reader1.readUint8();
        let address: string, reader2: BinaryReader;
        switch (addressType) {
            case 0x01: { // IPv4
                reader2 = await readBytes(socket, 6);
                const parts: number[] = [];
                for (let i = 0; i < 4; ++i) {
                    parts.push(reader2.readUint8());
                }
                address = parts.join('.');
                if (isPrivateIPv4(address)) {
                    return socket.end(createConnectReply(0x02));
                }
                break;
            }
            case 0x03: { // Domain
                const reader1 = await readBytes(socket, 1);
                const domainLen = reader1.readUint8();
                reader2 = await readBytes(socket, domainLen + 2);
                address = reader2.readString(domainLen);
                if (isPrivateDomain(address)) {
                    return socket.end(createConnectReply(0x02));
                }
                break;
            }
            case 0x04: { // IPv6
                reader2 = await readBytes(socket, 18);
                const parts = [];
                for (let i = 0; i < 8; ++i) {
                    const part = reader2.readUint16();
                    parts.push(part.toString(16));
                }
                address = parts.join(':');
                if (isPrivateIPv6(address)) {
                    return socket.end(createConnectReply(0x02));
                }
                break;
            }
            default:
                throw new Error('Request: unsupported address type');
        }

        const port = reader2.readUint16();

        // Support TCP connection only (0x01)
        if (command !== 0x01) {
            return socket.end(createConnectReply(0x07));
        }

        const rule = matchRule(config.rules, address, port);
        if (config.debug) logInfo(`Connect to ${address}:${port} (${rule.type})`);

        switch (rule.type) {
            case 'allow': {
                let sendReply = false;
                const targetSocket = createConnection(port, address, () => {
                    socket.write(createConnectReply(0x00));
                    sendReply = true;
                    socket.pipe(targetSocket);
                    targetSocket.pipe(socket);
                });

                targetSocket.once('error', () => {
                    if (sendReply) socket.destroy();
                    else socket.end(createConnectReply(0x04)); // Host unreachable
                });
                targetSocket.once('end', () => socket.end());

                socket.once('error', () => targetSocket.destroy());
                socket.once('end', () => targetSocket.end());

                break;
            }

            case 'deny':
                socket.end(createConnectReply(0x02)); // Connection forbidden
                break;

            case 'proxy': {
                try {
                    const proxySocket = await connectProxy(rule.proxy, address, port, config.debug);
                    socket.write(createConnectReply(0x00));

                    proxySocket.once('error', () => socket.destroy());
                    proxySocket.once('end', () => socket.end());

                    socket.once('error', () => proxySocket.destroy());
                    socket.once('end', () => proxySocket.end());

                    socket.pipe(proxySocket);
                    proxySocket.pipe(socket);
                }
                catch {
                    socket.end(createConnectReply(0x04)); // Host unreachable
                }

                break;
            }
        }
    }
}