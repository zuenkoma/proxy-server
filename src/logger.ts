function getTime(): string {
    const date = new Date();
    return `[${date.getHours().toString().padStart(2, '0')}:${date.getMinutes().toString().padStart(2, '0')}:${date.getSeconds().toString().padStart(2, '0')}]`;
}

export function logInfo(message: string): void {
    console.log(getTime(), message);
}
export function logError(message: string): void {
    console.error(getTime(), message);
}