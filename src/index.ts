import { createServer, type Socket } from 'node:net';
import process from 'node:process';
import { CliError, ConfigError } from './config/errors.ts';
import { readConfig, type Config } from './config/index.ts';
import { DNS } from './dns.ts';
import handleProtocol from './handlers/index.ts';
import { logError, logInfo } from './logger.ts';

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

const connections = new Map<Socket, string[]>();
const server = createServer(async socket => {
    connections.set(socket, []);

    const controller = new AbortController();
    socket.once('close', () => {
        controller.abort();
        connections.delete(socket);
    });
    socket.once('error', error => {
        if (config.debug) logError('Connection error: ' + error.message);
    });

    if (config.debug) logInfo(`Connection from ${socket.remoteAddress}:${socket.remotePort}`);

    try {
        await handleProtocol(controller.signal, socket, dns, config, connections);
    }
    catch (error) {
        if (!(error instanceof DOMException) || error.name !== 'AbortError') {
            socket.destroy();
        }
    }
});
server.listen(config.port, config.host);

let isShuttingDown = false;
function shutdown() {
    if (isShuttingDown) return;
    isShuttingDown = true;

    logInfo('Shutting down...');

    server.close();
    for (const [socket] of connections) socket.end();
    process.exit(0);
}
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);