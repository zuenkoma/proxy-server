import { createServer } from 'node:net';
import { readConfig } from './config.ts';
import handlerHttp from './handlers/http.ts';
import handlerSocks5 from './handlers/socks5.ts';
import handlerTls from './handlers/tls.ts';
import { readBytes } from './utils.ts';

const config = await readConfig();

const server = createServer(async socket => {
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
});
server.listen(config.port, config.host);

process.on('SIGINT', () => server.close());