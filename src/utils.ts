import { BinaryReader } from 'binary-rw';
import { isIPv4, isIPv6, type Socket } from 'net';

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

export function isPrivateIPv4(ip: string) {
    const parts = ip.split('.').map(Number);

    // 10.0.0.0/8
    if (parts[0] === 10) return true;

    // 172.16.0.0/12
    if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;

    // 192.168.0.0/16
    if (parts[0] === 192 && parts[1] === 168) return true;

    // 127.0.0.0/8 (localhost)
    if (parts[0] === 127) return true;

    // 169.254.0.0/16 (link-local)
    if (parts[0] === 169 && parts[1] === 254) return true;

    // 0.0.0.0/8
    if (parts[0] === 0) return true;

    // 224.0.0.0/4 (multicast)
    if (parts[0] >= 224 && parts[0] <= 239) return true;

    return false;
}

export function isPrivateIPv6(ip: string) {
    // fc00::/7 (unique local)
    if (ip.toLowerCase().startsWith('fc') || ip.toLowerCase().startsWith('fd')) return true;

    // fe80::/10 (link-local)
    if (ip.toLowerCase().startsWith('fe80')) return true;

    // ::1/128 (localhost)
    if (ip === '::1') return true;

    // ::/128 (unspecified)
    if (ip === '::') return true;

    // ff00::/8 (multicast)
    if (ip.toLowerCase().startsWith('ff')) return true;

    return false;
}

export function isPrivateDomain(domain: string) {
    if (isIPv4(domain)) return isPrivateIPv4(domain);
    if (isIPv6(domain)) return isPrivateIPv6(domain);

    const privateDomains = [
        'localhost',
        'local',
        'internal',
        'intranet',
        '.local',
        '.internal',
        '.intranet',
        '.home.arpa',
        '.in-addr.arpa',
        '.ip6.arpa'
    ];

    const lowerDomain = domain.toLowerCase();

    for (const privateDomain of privateDomains) {
        if (lowerDomain === privateDomain || lowerDomain.endsWith(privateDomain)) {
            return true;
        }
    }

    return false;
}