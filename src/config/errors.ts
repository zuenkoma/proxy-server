export class ConfigError extends Error {
    constructor(property: string, message: string) {
        super(`Config property '${property}' ${message}`);
    }
}

export class CliError extends Error { }