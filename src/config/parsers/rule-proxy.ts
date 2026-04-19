import { isIPv4, isIPv6 } from 'node:net';
import { domainToUnicode } from 'node:url';
import type { Host } from '../../host.ts';
import type { Proxy } from '../../rule.ts';
import { isObject, isValidDomain, isValidPort } from '../../utils.ts';
import { ConfigError } from '../errors.ts';

export function parseRuleProxy(proxy: any, ruleIndex: number): Proxy {
    if (!isObject(proxy)) {
        throw new ConfigError(`rules[${ruleIndex}].proxy`, 'must be an object');
    }

    if (proxy.protocol !== 'socks5' && proxy.protocol !== 'http') {
        throw new ConfigError(`rules[${ruleIndex}].proxy.protocol`, "must be 'socks5' or 'http'");
    }

    let host: Host;
    if (typeof proxy.host === 'string') {
        if (isIPv4(proxy.host)) host = { type: 'ipv4', host: proxy.host };
        else if (isIPv6(proxy.host)) host = { type: 'ipv6', host: proxy.host };
        else if (isValidDomain(proxy.host)) host = { type: 'domain', host: domainToUnicode(proxy.host) };
        else throw new ConfigError(`rules[${ruleIndex}].proxy.host`, 'is not a valid host');
    }
    else {
        throw new ConfigError(`rules[${ruleIndex}].proxy.host`, 'must be a string');
    }

    if (typeof proxy.port !== 'number' || !isValidPort(proxy.port)) {
        throw new ConfigError(`rules[${ruleIndex}].proxy.port`, 'must be a number between 1 and 65535');
    }

    const parsed: Proxy = {
        protocol: proxy.protocol,
        host,
        port: proxy.port,
        tls: false
    };

    if ('tls' in proxy) {
        if (typeof proxy.tls !== 'boolean') {
            throw new ConfigError(`rules[${ruleIndex}].proxy.tls`, 'must be a boolean');
        }

        parsed.tls = proxy.tls;
    }

    if ('auth' in proxy) {
        if (!isObject(proxy.auth)) {
            throw new ConfigError(`rules[${ruleIndex}].proxy.auth`, 'must be an object');
        }
        if (typeof proxy.auth.username !== 'string' || proxy.auth.username.length === 0) {
            throw new ConfigError(`rules[${ruleIndex}].proxy.auth.username`, 'must be a non-empty string');
        }
        if (typeof proxy.auth.password !== 'string' || proxy.auth.password.length === 0) {
            throw new ConfigError(`rules[${ruleIndex}].proxy.auth.password`, 'must be a non-empty string');
        }

        parsed.auth = proxy.auth;
    }

    return parsed;
}