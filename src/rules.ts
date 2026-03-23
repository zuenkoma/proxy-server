import { isIPv4 } from 'node:net';
import type { User } from './users.ts';

export interface Proxy {
    proto: 'socks5' | 'http';
    host: string;
    port: number;
    tls?: boolean; // default: false
}

export interface BaseRule {
    address: string;     // 192.168.0.1/24, *.example.com
    port: string | number; // 80, '80-88', '80,8080,3000'
}
export interface AllowRule extends BaseRule {
    type: 'allow';
}
export interface DenyRule extends BaseRule {
    type: 'deny';
}
export interface ProxyRule extends BaseRule {
    type: 'proxy';
    proxy: Proxy;
}
export type Rule = AllowRule | DenyRule | ProxyRule;

function matchAddress(address: string, pattern: string): boolean {
    if (pattern.includes('/')) {
        const [ip, mask] = pattern.split('/');
        const maskNum = parseInt(mask, 10);

        if (isIPv4(address) && isIPv4(ip)) {
            const addrParts = address.split('.').map(Number);
            const patternParts = ip.split('.').map(Number);

            let maskBits = maskNum;
            for (let i = 0; i < 4; i++) {
                const bits = Math.min(8, maskBits);
                const maskByte = bits === 8 ? 255 : (256 - Math.pow(2, 8 - bits));
                if ((addrParts[i] & maskByte) !== (patternParts[i] & maskByte)) {
                    return false;
                }
                maskBits -= bits;
                if (maskBits <= 0) break;
            }
            return true;
        }
        return false;
    }

    if (pattern.includes('*')) {
        const domainPattern = pattern.slice(2);
        return address === domainPattern || address.endsWith('.' + domainPattern);
    }

    return address === pattern;
}

function matchPort(port: number, pattern: string | number): boolean {
    if (typeof pattern === 'number') {
        return port === pattern;
    }

    if (pattern.includes('-')) {
        const [start, end] = pattern.split('-').map(Number);
        return port >= start && port <= end;
    }

    if (pattern.includes(',')) {
        const ports = pattern.split(',').map(Number);
        return ports.includes(port);
    }

    return port === +pattern;
}

export function matchRule(rules: Rule[], address: string, port: number): Rule {
    for (const rule of rules) {
        if (matchAddress(address, rule.address) && matchPort(port, rule.port)) {
            return rule;
        }
    }
    return {
        type: 'allow',
        address, port
    };
}