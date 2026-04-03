function getTime() {
    const date = new Date();
    return `[${date.getHours().toString().padStart(2, '0')}:${date.getMinutes().toString().padStart(2, '0')}:${date.getSeconds().toString().padStart(2, '0')}]`;
}

export function logInfo(message: string) {
    console.log(getTime(), message);
}
export function logError(message: string) {
    console.error(getTime(), message);
}