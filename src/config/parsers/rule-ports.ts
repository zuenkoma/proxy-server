import type { PortPattern } from '../../rule.ts';
import { isValidPort } from '../../utils.ts';
import { ConfigError } from '../errors.ts';

export function parseRulePorts(ports: unknown, ruleIndex: number): PortPattern[] | null {
    if (ports === undefined) return null;

    if (!Array.isArray(ports)) {
        throw new ConfigError(`rules[${ruleIndex}].ports`, 'must be an array');
    }

    return ports.map((port, index) => {
        switch (typeof port) {
            case 'number':
                if (!isValidPort(port)) {
                    throw new ConfigError(`rules[${ruleIndex}].ports[${index}]`, 'must be a number between 1 and 65535');
                }
                return port;

            case 'string':
                if (/^\d+-\d+$/.test(port)) {
                    const [start, end] = port.split('-').map(Number) as [number, number];
                    if (!isValidPort(start) || !isValidPort(end)) {
                        throw new ConfigError(`rules[${ruleIndex}].ports[${index}]`, 'must be a number between 1 and 65535');
                    }
                    if (start < end) return [start, end];
                }
                throw new ConfigError(`rules[${ruleIndex}].ports[${index}]`, 'is not a valid port range');

            default:
                throw new ConfigError(`rules[${ruleIndex}].ports[${index}]`, 'must be a number or a string');
        }
    });
}