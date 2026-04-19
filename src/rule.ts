import type { DNS } from './dns.ts';
import { ipv4ToNumber, ipv6ToBigint, type Host } from './host.ts';
import type { User } from './user.ts';

export interface CIDRPattern {
    host: number | bigint;
    mask: number;
}
export type HostPattern = number | bigint | CIDRPattern | RegExp;
export type PortPattern = number | [number, number];

export interface Proxy {
    protocol: 'socks5' | 'http';
    host: Host;
    port: number;
    tls: boolean;
    auth?: User;
}

export interface BaseRule {
    hosts: HostPattern[] | null;
    ports: PortPattern[] | null;
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

function matchHost(host: number | bigint | string, pattern: HostPattern): boolean {
    if (pattern instanceof RegExp) {
        return typeof host === 'string' && pattern.test(host);
    }

    if (typeof pattern === 'object') {
        return typeof host === typeof pattern.host && pattern.host === (
            typeof pattern.host === 'number' ?
                ((host as number) & pattern.mask) >>> 0 :
                (host as bigint) & BigInt(pattern.mask)
        );
    }

    return host === pattern;
}

function matchPort(port: number, pattern: PortPattern): boolean {
    if (typeof pattern === 'number') {
        return port === pattern;
    }
    else {
        const [start, end] = pattern;
        return port >= start && port <= end;
    }
}

export async function matchRule(rules: Rule[], host: Host, port: number, dns: DNS): Promise<Rule> {
    let matchedRule: Rule = {
        type: 'allow',
        hosts: null,
        ports: null
    };

    let hostValue: number | bigint | string = host.host;
    if (host.type === 'ipv4') hostValue = ipv4ToNumber(host.host);
    if (host.type === 'ipv6') hostValue = ipv6ToBigint(host.host);

    const domainIps = host.type === 'domain' ? (await dns.lookup(host.host)).map(
        address => (address.family === 4 ? ipv4ToNumber : ipv6ToBigint)(address.address)
    ) : [];

    for (const rule of rules) {
        const isAddressMatched = !rule.hosts || rule.hosts.some(pattern => [hostValue, ...domainIps].some(h => matchHost(h, pattern)));
        const isPortMatched = !rule.ports || rule.ports.some(pattern => matchPort(port, pattern));
        if (isAddressMatched && isPortMatched) matchedRule = rule;
    }

    return matchedRule;
}