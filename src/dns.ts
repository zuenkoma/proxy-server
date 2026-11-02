import { lookup } from 'node:dns/promises';

export interface LookupAddress {
    address: string;
    family: 4 | 6;
}

interface CacheRecord {
    addresses: LookupAddress[];
    expires: number;
}

export class DNS {
    private cache = new Map<string, CacheRecord>();
    private ttl: number;
    private cleanupTimer: ReturnType<typeof setTimeout> | null = null;

    constructor(ttl: number) {
        this.ttl = ttl;
    }

    private cleanup(): void {
        const now = Date.now();
        let nextTime = Infinity;
        for (const [hostname, record] of this.cache) {
            if (record.expires <= now) this.cache.delete(hostname);
            else if (record.expires < now + nextTime) {
                nextTime = record.expires - now;
            }
        }
        if (nextTime < Infinity) {
            this.cleanupTimer = setTimeout(() => this.cleanup(), nextTime);
        }
        else this.cleanupTimer = null;
    }

    async lookup(hostname: string): Promise<LookupAddress[]> {
        const now = Date.now();

        const cached = this.cache.get(hostname);
        if (cached && cached.expires > now) return cached.addresses;

        try {
            const lookupAddresses = await lookup(hostname, { all: true });
            const addresses = lookupAddresses.filter(address => address.family === 4 || address.family === 6) as LookupAddress[];
            this.cache.set(hostname, { addresses, expires: now + this.ttl });
            if (this.cleanupTimer === null) {
                this.cleanupTimer = setTimeout(() => this.cleanup(), this.ttl);
            }
            return addresses;
        }
        catch {
            if (cached) return cached.addresses;
            return [];
        }
    }

    destroy() {
        if (this.cleanupTimer !== null) {
            clearTimeout(this.cleanupTimer);
            this.cleanupTimer = null;
        }
        this.cache.clear();
    }
}