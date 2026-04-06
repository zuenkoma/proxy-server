import type { Rule } from '../../rule.ts';
import { isObject } from '../../utils.ts';
import { ConfigError } from '../errors.ts';
import { parseRuleHosts } from './rule-hosts.ts';
import { parseRulePorts } from './rule-ports.ts';
import { parseRuleProxy } from './rule-proxy.ts';

const defaultRules: unknown[] = [{
    type: 'deny',
    hosts: [
        '0.0.0.0/8',
        '10.0.0.0/8',
        '100.64.0.0/10',
        '127.0.0.0/8',
        '169.254.0.0/16',
        '172.16.0.0/12',
        '192.0.2.0/24',
        '192.168.0.0/16',
        '198.18.0.0/15',
        '198.51.100.0/24',
        '203.0.113.0/24',
        '224.0.0.0/4',
        '240.0.0.0/4',
        '255.255.255.255/32',
        '::1',
        'fc00::/7',
        'fe80::/10'
    ]
}];

export function parseRules(rules: any): Rule[] {
    if (!Array.isArray(rules)) {
        throw new ConfigError('rules', 'must be an array');
    }

    return [...defaultRules, ...rules].map((rule, index) => {
        if (!isObject(rule)) {
            throw new ConfigError(`rules[${index - defaultRules.length}]`, 'must be an object');
        }

        if (rule.type !== 'allow' && rule.type !== 'deny' && rule.type !== 'proxy') {
            throw new ConfigError(`proxy[${index - defaultRules.length}].type`, "must be 'allow', 'deny', or 'proxy'");
        }

        const hosts = parseRuleHosts(rule.hosts, index - defaultRules.length);
        const ports = parseRulePorts(rule.ports, index - defaultRules.length);

        if (rule.type === 'proxy') {
            return {
                type: rule.type,
                hosts, ports,
                proxy: parseRuleProxy(rule.proxy, index - defaultRules.length)
            };
        }
        else {
            return {
                type: rule.type,
                hosts, ports
            };
        }
    });
}