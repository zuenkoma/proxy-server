import type { Socket } from 'node:net';

export interface User {
    username: string;
    password: string;
    maxIps: number | null;
}

export function findUser(users: User[], username: string, password: string): User | true | null {
    if (users.length === 0) return true;
    const user = users.find(user => user.username === username && user.password === password);
    return user ?? null;
}

export function handleUserLimit(user: User, socket: Socket, connections: Map<Socket, string[]>): boolean {
    if (user.maxIps === null) return false;

    const connectedIps = new Set<string>();
    for (const [socket, usernames] of connections) {
        if (usernames.includes(user.username)) connectedIps.add(socket.remoteAddress!);
    }
    if (connectedIps.size >= user.maxIps) return true;

    connections.get(socket)!.push(user.username);
    return false;
}