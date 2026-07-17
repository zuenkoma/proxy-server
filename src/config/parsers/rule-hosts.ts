import { isIPv4, isIPv6 } from 'node:net';
import { domainToUnicode } from 'node:url';
import { ipv4ToNumber, ipv6ToBigint } from '../../host.ts';
import type { HostPattern } from '../../rule.ts';
import { isValidDomain } from '../../utils.ts';
import { ConfigError } from '../errors.ts';

function isIPv4CIDR(cidr: string): boolean {
    const parts = cidr.split('/');
    if (parts.length !== 2) return false;
    const [ip, mask] = parts as [string, string];
    return isIPv4(ip) && Number.isInteger(+mask) && +mask >= 0 && +mask <= 32;
}

function isIPv6CIDR(cidr: string): boolean {
    const parts = cidr.split('/');
    if (parts.length !== 2) return false;
    const [ip, mask] = parts as [string, string];
    return isIPv6(ip) && Number.isInteger(+mask) && +mask >= 0 && +mask <= 128;
}

export function parseRuleHosts(hosts: unknown, ruleIndex: number): HostPattern[] | null {
    if (hosts === undefined) return null;

    if (!Array.isArray(hosts)) {
        throw new ConfigError(`proxy[${ruleIndex}].hosts`, 'must be an array');
    }

    return hosts.map((host, index) => {
        if (typeof host !== 'string') {
            throw new ConfigError(`proxy[${ruleIndex}].hosts[${index}]`, 'must be a string');
        }

        if (isIPv4(host)) return ipv4ToNumber(host);
        if (isIPv4CIDR(host)) {
            const [ip, maskBits] = host.split('/') as [string, string];
            return {
                host: ipv4ToNumber(ip),
                mask: ((0xFFFFFFFF << (32 - +maskBits)) >>> 0)
            };
        }

        if (isIPv6(host)) return ipv6ToBigint(host);
        if (isIPv6CIDR(host)) {
            const [ip, maskBits] = host.split('/') as [string, string];
            return {
                host: ipv6ToBigint(ip),
                mask: ((0xFFFFFFFF << (32 - +maskBits)) >>> 0)
            };
        }

        if (host.startsWith('.')) {
            if (isValidDomain(host.slice(1))) {
                return new RegExp(`^([^.]+\\.)+${RegExp.escape(domainToUnicode(host.slice(1)))}$`, 'i');
            }
        }
        else if (host.startsWith('*.')) {
            if (isValidDomain(host.slice(2))) {
                return new RegExp(`^([^.]+\\.)*${RegExp.escape(domainToUnicode(host.slice(2)))}$`, 'i');
            }
        }
        else if (isValidDomain(host)) {
            return new RegExp(`^${RegExp.escape(domainToUnicode(host))}$`, 'i');
        }

        throw new ConfigError(`proxy[${ruleIndex}].hosts[${index}]`, 'is not a valid host');
    });
}