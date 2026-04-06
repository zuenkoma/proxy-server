import { isValidPort } from '../../utils.ts';
import { ConfigError } from '../errors.ts';

export function parsePort(port: unknown): number {
    if (typeof port !== 'number' || !isValidPort(port)) {
        throw new ConfigError('port', 'must be a number between 1 and 65535');
    }
    return port;
}