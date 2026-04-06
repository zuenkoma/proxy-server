import { isIPv4, isIPv6 } from 'node:net';
import { ConfigError } from '../errors.ts';

export function parseHost(host: unknown): string {
    if (typeof host !== 'string') {
        throw new ConfigError('host', 'must be a string');
    }

    if (!isIPv4(host) && !isIPv6(host)) {
        throw new ConfigError('host', 'is not a valid host');
    }

    return host;
}