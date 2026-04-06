export interface User {
    username: string;
    password: string;
}

export function hasAccess(users: User[], username: string, password: string): boolean {
    return users.length === 0 || users.some(user => user.username === username && user.password === password);
}