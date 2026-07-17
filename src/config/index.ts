import { readFile } from 'node:fs/promises';
import { isIPv4, isIPv6 } from 'node:net';
import { parseArgs } from 'node:util';
import type { Rule } from '../rule.ts';
import type { User } from '../user.ts';
import { isObject, isValidPort } from '../utils.ts';
import { CliError, ConfigError } from './errors.ts';
import { parseHost } from './parsers/host.ts';
import { parsePort } from './parsers/port.ts';
import { parseRules } from './parsers/rules.ts';
import { parseUsers } from './parsers/users.ts';

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
    debug: boolean;
}

export async function readConfig(): Promise<Config> {
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
        rules: [] as Rule[],
        debug: false
    };

    let cliConfig;
    try {
        const parsed = parseArgs({
            options: {
                host: { type: 'string', short: 'h' },
                port: { type: 'string', short: 'p' },
                config: { type: 'string', short: 'c' },
                'tls-key': { type: 'string' },
                'tls-cert': { type: 'string' },
                http: { type: 'boolean' },
                'http-tls': { type: 'boolean' },
                socks5: { type: 'boolean' },
                'socks5-tls': { type: 'boolean' },
                user: { type: 'string', multiple: true, short: 'u' },
                debug: { type: 'boolean' }
            },
            strict: true
        });
        cliConfig = parsed.values;
    }
    catch (error) {
        if (error instanceof Error) {
            throw new CliError(error.message);
        }
        else throw error;
    }

    if (cliConfig.config) {
        let configFile;

        try {
            configFile = await readFile(cliConfig.config, 'utf8');
        }
        catch {
            throw new CliError(`Failed to read config file '${cliConfig.config}'`);
        }

        try {
            configFile = JSON.parse(configFile);
        }
        catch {
            throw new CliError(`Failed to parse config file '${cliConfig.config}'`);
        }

        if (!isObject(configFile)) {
            throw new CliError(`Config file '${cliConfig.config}' must contain a JSON object`);
        }

        for (const key in configFile) {
            switch (key) {
                case 'host':
                    config.host = parseHost(configFile[key]);
                    break;
                case 'port':
                    config.port = parsePort(configFile[key]);
                    break;

                case 'tls-key':
                case 'tls-cert':
                    if (typeof configFile[key] !== 'string') {
                        throw new ConfigError(key, 'must be a string');
                    }
                    config[key] = configFile[key];
                    break;

                case 'http':
                case 'http-tls':
                case 'socks5':
                case 'socks5-tls':
                    if (typeof configFile[key] !== 'boolean') {
                        throw new ConfigError(key, 'must be a boolean');
                    }
                    config[key] = configFile[key];
                    break;

                case 'users':
                    config.users = parseUsers(configFile[key]);
                    break;

                case 'rules':
                    config.rules = parseRules(configFile[key]);
                    break;

                case 'debug':
                    if (typeof configFile[key] !== 'boolean') {
                        throw new ConfigError('debug', 'must be a boolean');
                    }
                    config.debug = configFile[key];
                    break;

                default:
                    throw new ConfigError(key, 'is unknown');
            }
        }
    }

    if (cliConfig.host) {
        if (typeof cliConfig.host !== 'string') {
            throw new CliError("Option '--host -h' must be a string");
        }
        if (!isIPv4(cliConfig.host) && !isIPv6(cliConfig.host)) {
            throw new CliError("Option '--host, -h' is not a valid host");
        }
        config.host = cliConfig.host;
    }
    if (cliConfig.port) {
        if (!isValidPort(+cliConfig.port)) {
            throw new CliError("Option '--port, -p' must be a number between 1 and 65535");
        }
        config.port = +cliConfig.port;
    }

    if (cliConfig['tls-key']) {
        config['tls-key'] = cliConfig['tls-key'];
    }
    if (cliConfig['tls-cert']) {
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
                throw new CliError(`Option '--user, -u' must be 'username:password'`);
            }
            if (!parts[0]!.length || !parts[1]!.length) {
                throw new CliError(`Option '--user, -u' is invalid. Username and password cannot be empty`);
            }
            config.users.push({
                username: parts[0]!,
                password: parts[1]!,
                maxIps: null
            });
        }
    }

    if (cliConfig.debug !== undefined) {
        config.debug = cliConfig.debug;
    }

    if (config.port === null) {
        throw new CliError('Port is required');
    }
    if (!config.http && !config['http-tls'] && !config.socks5 && !config['socks5-tls']) {
        throw new CliError('At least one protocol must be enabled');
    }
    if ((config['http-tls'] || config['socks5-tls']) && (!config['tls-key'] || !config['tls-cert'])) {
        throw new CliError('TLS key and certificate are required');
    }

    return config as Config;
}