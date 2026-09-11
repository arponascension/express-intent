import type { RedisClientAdapter } from './client.js';

interface Entry {
  value: string;
  expiresAt: number;
}

type ZEntry = { member: string; score: number };
interface ZSet {
  entries: ZEntry[];
  expiresAt: number;
}

export class InMemoryRedisAdapter implements RedisClientAdapter {
  readonly kind = 'in-memory-shim';
  private readonly kv = new Map<string, Entry>();
  private readonly zs = new Map<string, ZSet>();
  private readonly subs = new Map<string, Array<(m: string) => void>>();

  private now(): number {
    return Date.now();
  }
  private purgeKv(now: number): void {
    for (const [k, e] of this.kv) {
      if (e.expiresAt <= now) this.kv.delete(k);
    }
  }
  private purgeZ(now: number): void {
    for (const [k, z] of this.zs) {
      if (z.expiresAt <= now) this.zs.delete(k);
    }
  }

  async get(key: string): Promise<string | null> {
    const now = this.now();
    this.purgeKv(now);
    const e = this.kv.get(key);
    if (e === undefined) return null;
    if (e.expiresAt <= now) {
      this.kv.delete(key);
      return null;
    }
    return e.value;
  }

  async set(
    key: string,
    value: string,
    opts: { ttlMs?: number; ifNotExists?: boolean } = {},
  ): Promise<boolean> {
    const now = this.now();
    this.purgeKv(now);
    if (opts.ifNotExists && this.kv.has(key)) return false;
    const ttl = opts.ttlMs ?? 0;
    this.kv.set(key, { value, expiresAt: ttl > 0 ? now + ttl : Number.POSITIVE_INFINITY });
    return true;
  }

  async del(key: string): Promise<number> {
    let n = 0;
    if (this.kv.delete(key)) n++;
    if (this.zs.delete(key)) n++;
    return n;
  }

  async expire(key: string, ttlMs: number): Promise<boolean> {
    const e = this.kv.get(key);
    if (e !== undefined) {
      e.expiresAt = this.now() + ttlMs;
      return true;
    }
    const z = this.zs.get(key);
    if (z !== undefined) {
      z.expiresAt = this.now() + ttlMs;
      return true;
    }
    return false;
  }

  async incr(key: string): Promise<number> {
    const cur = await this.get(key);
    const next = (cur === null ? 0 : Number.parseInt(cur, 10)) + 1;
    this.kv.set(key, {
      value: String(next),
      expiresAt: this.kv.get(key)?.expiresAt ?? Number.POSITIVE_INFINITY,
    });
    return next;
  }

  async decr(key: string): Promise<number> {
    const cur = await this.get(key);
    const next = (cur === null ? 0 : Number.parseInt(cur, 10)) - 1;
    this.kv.set(key, {
      value: String(next),
      expiresAt: this.kv.get(key)?.expiresAt ?? Number.POSITIVE_INFINITY,
    });
    return next;
  }

  async zadd(
    key: string,
    score: number,
    member: string,
    opts: { ttlMs?: number } = {},
  ): Promise<number> {
    const now = this.now();
    this.purgeZ(now);
    const ttl = opts.ttlMs ?? 0;
    const z = this.zs.get(key) ?? {
      entries: [],
      expiresAt: ttl > 0 ? now + ttl : Number.POSITIVE_INFINITY,
    };
    if (ttl > 0) z.expiresAt = now + ttl;
    const idx = z.entries.findIndex((e) => e.member === member);
    if (idx >= 0) {
      z.entries[idx] = { member, score };
      this.zs.set(key, z);
      return 0;
    }
    z.entries.push({ member, score });
    this.zs.set(key, z);
    return 1;
  }

  async zremRangeByScore(key: string, min: number, max: number): Promise<number> {
    const z = this.zs.get(key);
    if (z === undefined) return 0;
    const before = z.entries.length;
    z.entries = z.entries.filter((e) => !(e.score >= min && e.score <= max));
    return before - z.entries.length;
  }

  async zcard(key: string): Promise<number> {
    const z = this.zs.get(key);
    return z === undefined ? 0 : z.entries.length;
  }

  async zrangeByScoreWithScores(
    key: string,
    min: number,
    max: number,
    limit?: number,
  ): Promise<ReadonlyArray<{ member: string; score: number }>> {
    const z = this.zs.get(key);
    if (z === undefined) return [];
    const filtered = z.entries
      .filter((e) => e.score >= min && e.score <= max)
      .sort((a, b) => a.score - b.score);
    return limit === undefined ? filtered : filtered.slice(0, limit);
  }

  async publish(channel: string, message: string): Promise<number> {
    const subs = this.subs.get(channel) ?? [];
    queueMicrotask(() => {
      for (const h of subs) h(message);
    });
    return subs.length;
  }

  async subscribe(
    channel: string,
    handler: (message: string) => void,
  ): Promise<() => Promise<void>> {
    const arr = this.subs.get(channel) ?? [];
    arr.push(handler);
    this.subs.set(channel, arr);
    return async () => {
      const list = this.subs.get(channel) ?? [];
      const idx = list.indexOf(handler);
      if (idx >= 0) list.splice(idx, 1);
    };
  }

  async quit(): Promise<void> {
    this.kv.clear();
    this.zs.clear();
    this.subs.clear();
  }
}
