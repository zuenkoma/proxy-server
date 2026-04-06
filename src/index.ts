import { createServer, type Socket } from 'node:net';
import process from 'node:process';
import { CliError, ConfigError } from './config/errors.ts';
import { readConfig, type Config } from './config/index.ts';
import { DNS } from './dns.ts';
import handlerHttp from './handlers/http.ts';
import handlerSocks5 from './handlers/socks5.ts';
import handlerTls from './handlers/tls.ts';
import { logError, logInfo } from './logger.ts';
import { readBytes } from './utils.ts';

let config: Config;
try {
    config = await readConfig();
}
catch (error) {
    if (error instanceof ConfigError || error instanceof CliError) {
        console.error(error.message + '.');
    }
    else throw error;
    process.exit(1);
}

const dns = new DNS(60_000);

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
                if (config.socks5) await handlerSocks5(socket, dns, config);
                else socket.destroy();
                break;

            case 0x43:
                if (config.http) await handlerHttp(socket, dns, config);
                else socket.destroy();
                break;

            case 0x16:
                if (config['http-tls'] || config['socks5-tls']) await handlerTls(socket, dns, config);
                else socket.destroy();
                break;

            default:
                socket.destroy();
                break;
        }
    }
    catch { }
});
server.listen(config.port, config.host);

let isShuttingDown = false;
function shutdown() {
    if (isShuttingDown) return;
    isShuttingDown = true;

    logInfo('Shutting down...');

    server.close();
    for (const socket of connections) socket.end();
}
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);