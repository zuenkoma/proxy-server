import { createServer, type Socket } from 'node:net';
import process from 'node:process';
import { readConfig } from './config.ts';
import handlerHttp from './handlers/http.ts';
import handlerSocks5 from './handlers/socks5.ts';
import handlerTls from './handlers/tls.ts';
import { logError, logInfo } from './logger.ts';
import { readBytes } from './utils.ts';

const config = await readConfig();

const connections = new Set<Socket>();
const server = createServer(async socket => {
    connections.add(socket);
    socket.once('close', () => connections.delete(socket));
    socket.once('error', error => {
        if (config.debug) logError('Connection error: ' + error.message);
    });

    if (config.debug) logInfo(`Connection from ${socket.remoteAddress}:${socket.remotePort}`);

    try {
        const firstByte = (await readBytes(socket, 1)).readUint8();
        socket.unshift(new Uint8Array([firstByte]));

        switch (firstByte) {
            case 0x05:
                if (config.socks5) handlerSocks5(socket, config);
                else socket.destroy();
                break;

            case 0x43:
                if (config.http) handlerHttp(socket, config);
                else socket.destroy();
                break;

            case 0x16:
                if (config['http-tls'] || config['socks5-tls']) handlerTls(socket, config);
                else socket.destroy();
                break;

            default:
                socket.destroy();
                break;
        }
    }
    catch (error) {
        if (config.debug) console.error(error);
        socket.destroy();
    }
});
server.listen(config.port, config.host);

function shutdown() {
    for (const socket of connections) socket.end();
    server.close();
}
process.on('SIGINT', shutdown);
process.on('SIGINT', shutdown);