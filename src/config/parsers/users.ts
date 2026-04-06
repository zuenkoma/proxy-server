import type { User } from '../../user.ts';
import { isObject } from '../../utils.ts';
import { ConfigError } from '../errors.ts';

export function parseUsers(users: unknown): User[] {
    if (!Array.isArray(users)) {
        throw new ConfigError('users', 'must be an array');
    }

    return users.map((user, index) => {
        if (!isObject(user)) {
            throw new ConfigError(`users[${index}]`, 'must be an object');
        }

        if (typeof user.username !== 'string' || user.username.length === 0) {
            throw new ConfigError(`users[${index}].username`, 'must be a non-empty string');
        }

        if (typeof user.password !== 'string' || user.password.length === 0) {
            throw new ConfigError(`users[${index}].password`, 'must be a non-empty string');
        }

        return user;
    });
}