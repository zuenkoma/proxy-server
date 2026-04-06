import { BinaryWriter } from 'binary-rw';
import { isIPv4, isIPv6, type Socket } from 'node:net';
import type { User } from '../user.ts';
import { readBytes } from '../utils.ts';

export default async function connectSocks5Proxy(socket: Socket, host: string, port: number, auth?: User): Promise<void> {
    const method = auth ? 0x02 : 0x00;

    // Handshake
    {
        socket.write(new Uint8Array([0x05, 0x01, method]));

        const reader = await readBytes(socket, 2);
        const version = reader.readUint8();
        const chosenMethod = reader.readUint8();

        if (version !== 0x05 || chosenMethod !== method) {
            throw new Error('SOCKS5 handshake failed');
        }
    }

    // Auth
    if (method === 0x02) {
        const usernameBuf = new TextEncoder().encode(auth!.username).buffer;
        const passwordBuf = new TextEncoder().encode(auth!.password).buffer;

        const writer = new BinaryWriter();
        writer.writeUint8(0x01); // Version
        writer.writeUint8(usernameBuf.byteLength);
        writer.writeBuffer(usernameBuf);
        writer.writeUint8(passwordBuf.byteLength);
        writer.writeBuffer(passwordBuf);
        socket.write(new Uint8Array(writer.toBuffer()));

        const reader = await readBytes(socket, 2);
        const authVersion = reader.readUint8();
        const authStatus = reader.readUint8();

        if (authVersion !== 0x01 || authStatus !== 0x00) {
            throw new Error('SOCKS5 authentication failed');
        }
    }

    // Request
    {
        let addressBuf: ArrayBuffer;
        if (isIPv4(host)) {
            addressBuf = new Uint8Array([
                0x01, // Type
                ...host.split('.').map(Number)
            ]).buffer;
        }
        else if (isIPv6(host)) {
            const numGroups = host.match(/[0-9a-z]+/g)!.length;
            const groups = host.replace('::', (host.startsWith(':') ? '' : ':') + Array.from({ length: 8 - numGroups }, () => '0').join(':') + (host.endsWith(':') ? '' : ':')).split(':');

            const ipWriter = new BinaryWriter();
            ipWriter.writeUint8(0x04); // Type
            for (const group of groups) {
                ipWriter.writeUint16(parseInt(group, 16));
            }
            addressBuf = ipWriter.toBuffer() as ArrayBuffer;
        }
        else {
            const domainBuf = new TextEncoder().encode(host).buffer;

            const domainWriter = new BinaryWriter();
            domainWriter.writeUint8(0x03); // Type
            domainWriter.writeUint8(domainBuf.byteLength);
            domainWriter.writeBuffer(domainBuf);
            addressBuf = domainWriter.toBuffer() as ArrayBuffer;
        }

        const writer = new BinaryWriter();
        writer.writeUint8(0x05); // Version
        writer.writeUint8(0x01); // Command
        writer.writeUint8(0x00); // Reserved
        writer.writeBuffer(addressBuf);
        writer.writeUint16(port);
        socket.write(new Uint8Array(writer.toBuffer()));

        const reader = await readBytes(socket, 4);
        const requestVersion = reader.readUint8();
        const requestCommand = reader.readUint8();
        reader.skip(1); // Reserved
        const requestAddressType = reader.readUint8();

        if (requestVersion !== 0x05 || requestCommand !== 0x00 || ![0x01, 0x03, 0x04].includes(requestAddressType)) {
            throw new Error('SOCKS5 connection failed');
        }

        if (requestAddressType === 0x01) await readBytes(socket, 6);
        else if (requestAddressType === 0x04) await readBytes(socket, 18);
        else {
            const requestDomainLen = (await readBytes(socket, 1)).readUint8();
            await readBytes(socket, requestDomainLen + 2);
        }
    }
}