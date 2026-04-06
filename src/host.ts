export type HostType = 'ipv4' | 'ipv6' | 'domain';

export interface Host {
    type: HostType;
    host: string;
}

export function ipv4ToNumber(ip: string): number {
    const octets = ip.split('.').map(Number);
    return (octets[0] << 24 | octets[1] << 16 | octets[2] << 8 | octets[3]) >>> 0;
}

export function ipv6ToBigint(ip: string): bigint {
    ip = ip.replace(/\d+\.\d+\.\d+\.\d+/, ipv4 => {
        const octets = ipv4.split('.').map(Number);
        return `${(octets[0] << 8 | octets[1]).toString(16)}:${(octets[2] << 8 | octets[3]).toString(16)}`;
    });
    return BigInt(
        '0x' + ip
            .replace('::', ':'.repeat(10 - ip.split(':').length))
            .split(':').map(p => p.padStart(4, '0')).join('')
    );
}