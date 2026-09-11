import type { RedisClientAdapter } from './client.js';
import { buildRedisKey, hashActor, hashIp } from './keys.js';
import type { Observation } from '../anomaly-defs.js';
import type { ObservationStore } from '../anomaly-store.js';

export interface RedisObservationStoreOptions {
  readonly client: RedisClientAdapter;
  readonly keyPrefix?: string;
  readonly ttlMs?: number;
  readonly maxEntriesPerKey?: number;
}

const DEFAULT_TTL = 5 * 60_000;
const DEFAULT_MAX = 10_000;

interface ScopedResult {
  readonly observation: Observation;
  readonly matchedAt: number;
}

function encode(obs: Observation): string {
  return JSON.stringify(obs);
}

function decode(s: string): ScopedResult | null {
  try {
    const o = JSON.parse(s) as Observation;
    if (typeof o.now !== 'number') return null;
    return { observation: o, matchedAt: o.now };
  } catch {
    return null;
  }
}

export class RedisObservationStore implements ObservationStore {
  private readonly client: RedisClientAdapter;
  private readonly keyPrefix: string;
  private readonly ttlMs: number;
  private readonly maxEntriesPerKey: number;

  constructor(options: RedisObservationStoreOptions) {
    this.client = options.client;
    this.keyPrefix = options.keyPrefix ?? 'default';
    this.ttlMs = options.ttlMs ?? DEFAULT_TTL;
    this.maxEntriesPerKey = options.maxEntriesPerKey ?? DEFAULT_MAX;
  }

  private actorKey(actorSubject: string | null | undefined): string {
    return buildRedisKey('obs', [this.keyPrefix, 'a', hashActor(actorSubject)]);
  }
  private ipKey(ip: string | null | undefined): string {
    return buildRedisKey('obs', [this.keyPrefix, 'i', hashIp(ip)]);
  }

  async record(observation: Observation): Promise<void> {
    const ttl = this.ttlMs;
    const member = encode(observation);
    if (observation.actorSubject !== null && observation.actorSubject !== undefined) {
      const k = this.actorKey(observation.actorSubject);
      await this.client.zadd(k, observation.now, member, { ttlMs: ttl });
      await this.client.zremRangeByScore(k, 0, observation.now - ttl);
      const size = await this.client.zcard(k);
      if (size > this.maxEntriesPerKey) {
        const all = await this.client.zrangeByScoreWithScores(k, 0, Number.POSITIVE_INFINITY);
        const excess = all.length - this.maxEntriesPerKey;
        for (let i = 0; i < excess; i++) {
          const entry = all[i]!;
          await this.client.zremRangeByScore(k, entry.score, entry.score);
        }
      }
    }
    if (observation.ip !== null && observation.ip !== undefined) {
      const k = this.ipKey(observation.ip);
      await this.client.zadd(k, observation.now, member, { ttlMs: ttl });
      await this.client.zremRangeByScore(k, 0, observation.now - ttl);
    }
  }

  async recent(opts: {
    actorSubject?: string | null;
    ip?: string | null;
    now: number;
    windowMs: number;
  }): Promise<ReadonlyArray<Observation>> {
    const min = opts.now - opts.windowMs;
    const out: Observation[] = [];
    const seen = new Set<string>();
    if (opts.actorSubject !== null && opts.actorSubject !== undefined) {
      const items = await this.client.zrangeByScoreWithScores(
        this.actorKey(opts.actorSubject),
        min,
        opts.now,
      );
      for (const it of items) {
        const dec = decode(it.member);
        if (dec === null) continue;
        const k = dec.observation.method + ':' + dec.observation.path + ':' + dec.observation.now;
        if (!seen.has(k)) {
          seen.add(k);
          out.push(dec.observation);
        }
      }
    }
    if (opts.ip !== null && opts.ip !== undefined) {
      const items = await this.client.zrangeByScoreWithScores(this.ipKey(opts.ip), min, opts.now);
      for (const it of items) {
        const dec = decode(it.member);
        if (dec === null) continue;
        const k = dec.observation.method + ':' + dec.observation.path + ':' + dec.observation.now;
        if (!seen.has(k)) {
          seen.add(k);
          out.push(dec.observation);
        }
      }
    }
    out.sort((a, b) => a.now - b.now);
    return out;
  }

  async clear(): Promise<void> {
    /* no-op for shared Redis; intended for local test usage */
  }
}
