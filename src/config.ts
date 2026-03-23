import { readFile } from 'node:fs/promises';
import { isIPv4 } from 'node:net';
import { parseArgs } from 'node:util';
import type { Proxy, Rule } from './rules.ts';
import type { User } from './users.ts';

export interface Config {
    host: string;
    port: number;
    'tls-key': string | null;
    'tls-cert': string | null;
    http: boolean;
    'http-tls': boolean;
    socks5: boolean;
    'socks5-tls': boolean;
    users: User[];
    rules: Rule[];
}

function checkHost(host: string) {
    if (!isIPv4(host)) {
        console.error('Host must be a valid IPv4 address.');
        process.exit(1);
    }
}
function checkPort(port: number) {
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
        console.error('Port must be a number between 1 and 65535.');
        process.exit(1);
    }
}

function checkUsers(users: any): users is User[] {
    if (!Array.isArray(users)) {
        console.error('Users must be an array.');
        return false;
    }

    for (const user of users) {
        if (typeof user !== 'object' || user === null) {
            console.error('Each user must be an object.');
            return false;
        }

        if (typeof user.username !== 'string' || user.username.length === 0) {
            console.error('Each user must have a non-empty username string.');
            return false;
        }

        if (typeof user.password !== 'string' || user.password.length === 0) {
            console.error('Each user must have a non-empty password string.');
            return false;
        }
    }

    return true;
}

function checkProxy(proxy: any): proxy is Proxy {
    if (typeof proxy !== 'object' || proxy === null) {
        console.error('Proxy must be an object.');
        return false;
    }

    if (proxy.proto !== 'socks5' && proxy.proto !== 'http') {
        console.error('Proxy proto must be "socks5" or "http".');
        return false;
    }

    if (typeof proxy.host !== 'string' || proxy.host.length === 0) {
        console.error('Proxy host must be a non-empty string.');
        return false;
    }

    if (typeof proxy.port !== 'number' || proxy.port < 1 || proxy.port > 65535) {
        console.error('Proxy port must be a number between 1 and 65535.');
        return false;
    }

    if (proxy.tls !== undefined && typeof proxy.tls !== 'boolean') {
        console.error('Proxy tls must be a boolean.');
        return false;
    }

    if (proxy.auth !== undefined) {
        if (typeof proxy.auth !== 'object' || proxy.auth === null) {
            console.error('Proxy auth must be an object.');
            return false;
        }
        if (typeof proxy.auth.username !== 'string' || proxy.auth.username.length === 0) {
            console.error('Proxy auth username must be a non-empty string.');
            return false;
        }
        if (typeof proxy.auth.password !== 'string' || proxy.auth.password.length === 0) {
            console.error('Proxy auth password must be a non-empty string.');
            return false;
        }
    }

    return true;
}

function checkAddressPattern(address: string): boolean {
    if (address.includes('/')) {
        const [ip, mask] = address.split('/');
        if (!isIPv4(ip)) {
            console.error(`Invalid IP address in pattern: ${address}`);
            return false;
        }
        const maskNum = parseInt(mask, 10);
        if (isNaN(maskNum) || maskNum < 0 || maskNum > 32) {
            console.error(`Invalid mask in pattern: ${address}`);
            return false;
        }
        return true;
    }

    if (address.includes('*')) {
        if (address.indexOf('*') !== 0 || address.indexOf('*.') !== 0) {
            console.error(`Wildcard must be at the beginning: ${address}`);
            return false;
        }
        const domain = address.slice(2);
        if (domain.length === 0) {
            console.error(`Invalid domain pattern: ${address}`);
            return false;
        }
        return true;
    }

    if (isIPv4(address)) {
        return true;
    }

    const domainRegex = /^[a-zA-Z0-9][a-zA-Z0-9.-]*[a-zA-Z0-9]$/;
    if (domainRegex.test(address)) {
        return true;
    }

    console.error(`Invalid address pattern: ${address}`);
    return false;
}

function checkPortRange(port: any): boolean {
    if (typeof port === 'number') {
        return port >= 1 && port <= 65535;
    }

    if (typeof port !== 'string') {
        console.error('Port must be a number or string.');
        return false;
    }

    if (port.includes('-')) {
        const [start, end] = port.split('-').map(p => parseInt(p, 10));
        if (isNaN(start) || isNaN(end) || start < 1 || end > 65535 || start > end) {
            console.error(`Invalid port range: ${port}`);
            return false;
        }
        return true;
    }

    if (port.includes(',')) {
        const ports = port.split(',').map(p => parseInt(p, 10));
        for (const p of ports) {
            if (isNaN(p) || p < 1 || p > 65535) {
                console.error(`Invalid port in list: ${port}`);
                return false;
            }
        }
        return true;
    }

    const singlePort = +port;
    if (isNaN(singlePort) || singlePort < 1 || singlePort > 65535) {
        console.error(`Invalid port: ${port}`);
        return false;
    }

    return true;
}

function checkRule(rule: any): rule is Rule {
    if (typeof rule !== 'object' || rule === null) {
        console.error('Rule must be an object.');
        return false;
    }

    if (rule.type !== 'allow' && rule.type !== 'deny' && rule.type !== 'proxy') {
        console.error('Rule type must be "allow", "deny", or "proxy".');
        return false;
    }

    if (typeof rule.address !== 'string') {
        console.error('Rule address must be a string.');
        return false;
    }
    if (!checkAddressPattern(rule.address)) {
        return false;
    }
    if (!checkPortRange(rule.port)) {
        return false;
    }

    if (rule.type === 'proxy') {
        if (!rule.proxy) {
            console.error('Proxy rule must have a proxy field.');
            return false;
        }
        if (!checkProxy(rule.proxy)) {
            return false;
        }
    }

    return true;
}

function checkRules(rules: any): rules is Rule[] {
    if (!Array.isArray(rules)) {
        console.error('Rules must be an array.');
        return false;
    }

    for (const rule of rules) {
        if (!checkRule(rule)) {
            return false;
        }
    }

    return true;
}

export async function readConfig() {
    const config = {
        host: '0.0.0.0',
        port: null as number | null,
        'tls-key': null as string | null,
        'tls-cert': null as string | null,
        http: false,
        'http-tls': false,
        socks5: false,
        'socks5-tls': false,
        users: [] as User[],
        rules: [] as Rule[]
    };

    const { values: cliConfig } = parseArgs({
        options: {
            host: { type: 'string', short: 'h' },
            port: { type: 'string', short: 'p' },
            config: { type: 'string', short: 'c' },
            'tls-key': { type: 'string' },
            'tls-cert': { type: 'string' },
            'http': { type: 'boolean' },
            'http-tls': { type: 'boolean' },
            'socks5': { type: 'boolean' },
            'socks5-tls': { type: 'boolean' },
            'user': { type: 'string', multiple: true }
        },
        strict: true
    });

    if (cliConfig.config) {
        let configFile;

        try {
            configFile = await readFile(cliConfig.config, 'utf8');
        }
        catch {
            console.error(`Failed to read config file "${cliConfig.config}".`);
            process.exit(1);
        }

        try {
            configFile = JSON.parse(configFile);
        }
        catch {
            console.error(`Failed to parse config file "${cliConfig.config}".`);
            process.exit(1);
        }

        for (const key in configFile) {
            switch (key) {
                case 'host':
                    checkHost(configFile[key]);
                    config.host = configFile[key];
                    break;
                case 'port':
                    checkPort(+configFile[key]);
                    config.port = +configFile[key];
                    break;

                case 'tls-key':
                case 'tls-cert':
                    if (typeof configFile[key] !== 'string') {
                        console.error(`Config key "${key}" must be a string.`);
                        process.exit(1);
                    }
                    config[key] = configFile[key];
                    break;

                case 'http':
                case 'http-tls':
                case 'socks5':
                case 'socks5-tls':
                    if (typeof configFile[key] !== 'boolean') {
                        console.error(`Config key "${key}" must be a boolean.`);
                        process.exit(1);
                    }
                    config[key] = configFile[key];
                    break;

                case 'users':
                    if (configFile[key] !== undefined) {
                        if (!checkUsers(configFile[key])) {
                            process.exit(1);
                        }
                        config.users = configFile[key];
                    }
                    break;

                case 'rules':
                    if (configFile[key] !== undefined) {
                        if (!checkRules(configFile[key])) {
                            process.exit(1);
                        }
                        config.rules = configFile[key];
                    }
                    break;

                default:
                    console.error(`Unknown config key: "${key}".`);
                    process.exit(1);
            }
        }
    }

    if (cliConfig.host !== undefined) {
        checkHost(cliConfig.host);
        config.host = cliConfig.host;
    }
    if (cliConfig.port !== undefined) {
        checkPort(+cliConfig.port);
        config.port = +cliConfig.port;
    }

    if (cliConfig['tls-key'] !== undefined) {
        config['tls-key'] = cliConfig['tls-key'];
    }
    if (cliConfig['tls-cert'] !== undefined) {
        config['tls-cert'] = cliConfig['tls-cert'];
    }

    for (const key of ['http', 'http-tls', 'socks5', 'socks5-tls'] as const) {
        if (cliConfig[key] !== undefined) {
            config[key] = cliConfig[key];
        }
    }

    if (cliConfig.user && cliConfig.user.length) {
        for (const userStr of cliConfig.user) {
            const parts = userStr.split(':');
            if (parts.length !== 2) {
                console.error(`Invalid user format: "${userStr}". Expected "username:password".`);
                process.exit(1);
            }
            if (!parts[0].length || !parts[1].length) {
                console.error(`Username and password cannot be empty: "${userStr}".`);
                process.exit(1);
            }
            config.users.push({
                username: parts[0],
                password: parts[1]
            });
        }
    }

    if (config.port === null) {
        console.error('Port is required.');
        process.exit(1);
    }
    if (!config.http && !config['http-tls'] && !config.socks5 && !config['socks5-tls']) {
        console.error('At least one protocol must be enabled.');
        process.exit(1);
    }
    if ((config['http-tls'] || config['socks5-tls']) && (!config['tls-key'] || !config['tls-cert'])) {
        console.error('TLS key and certificate are required.');
        process.exit(1);
    }

    return config as Config;
}