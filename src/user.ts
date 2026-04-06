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