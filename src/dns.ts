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

    constructor(ttl: number) {
        this.ttl = ttl;
    }

    async lookup(hostname: string): Promise<LookupAddress[]> {
        const now = Date.now();

        const cached = this.cache.get(hostname);
        if (cached && cached.expires > now) return cached.addresses;

        try {
            const lookupAddresses = await lookup(hostname, { all: true });
            const addresses = lookupAddresses.filter(address => address.family === 4 || address.family === 6) as LookupAddress[];
            this.cache.set(hostname, { addresses, expires: now + this.ttl });
            return addresses;
        }
        catch {
            if (cached) return cached.addresses;
            return [];
        }
    }
}