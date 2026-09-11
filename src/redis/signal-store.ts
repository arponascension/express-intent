import type { RedisClientAdapter } from './client.js';
import { buildRedisKey } from './keys.js';
import type { SignalStore, StoreEntry } from '../domain/providers.js';

export interface RedisSignalStoreOptions {
  readonly client: RedisClientAdapter;
  readonly keyPrefix?: string;
}

export class RedisSignalStore implements SignalStore {
  private readonly client: RedisClientAdapter;
  private readonly keyPrefix: string;

  constructor(options: RedisSignalStoreOptions) {
    this.client = options.client;
    this.keyPrefix = options.keyPrefix ?? 'default';
  }

  private redisKey(signalKey: string): string {
    return buildRedisKey('sig', [this.keyPrefix, signalKey]);
  }

  async increment(signalKey: string, ttlMs: number, delta = 1): Promise<number> {
    if (!Number.isFinite(ttlMs) || ttlMs <= 0) {
      throw new Error('ttlMs must be a positive finite number');
    }
    const key = this.redisKey(signalKey);
    let n = 0;
    for (let i = 0; i < delta; i++) n = await this.client.incr(key);
    await this.client.expire(key, ttlMs);
    return n;
  }

  async count(signalKey: string): Promise<number> {
    const v = await this.client.get(this.redisKey(signalKey));
    if (v === null) return 0;
    return Number.parseInt(v, 10);
  }

  async reset(signalKey: string): Promise<void> {
    await this.client.del(this.redisKey(signalKey));
  }

  async shutdown(): Promise<void> {
    /* adapter-owned */
  }

  async getEntry(signalKey: string): Promise<StoreEntry | null> {
    const v = await this.client.get(this.redisKey(signalKey));
    if (v === null) return null;
    return { count: Number.parseInt(v, 10), expiresAt: Date.now() };
  }
}
