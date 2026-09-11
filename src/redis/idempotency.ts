import type { RedisClientAdapter } from './client.js';
import { buildRedisKey, buildRedisChannel, hashString } from './keys.js';
import type {
  AcquireResult,
  IdempotencyProvider,
  IdempotencySnapshot,
  IdempotencyState,
  StoredResponse,
} from '../idempotency-defs.js';

export interface RedisIdempotencyProviderOptions {
  readonly client: RedisClientAdapter;
  readonly keyPrefix?: string;
}

const SCHEMA_VERSION = 1;

function encode(snap: object): string {
  return JSON.stringify({ v: SCHEMA_VERSION, ...snap });
}

interface EncodedSnapshot {
  v: number;
  key: string;
  state: IdempotencyState;
  fingerprint: string;
  inFlightSince: number | null;
  completedAt: number | null;
  expiresAt: number;
  version: number;
  response: StoredResponse | null;
  error: string | null;
}

function decode(raw: string): EncodedSnapshot | null {
  try {
    const o = JSON.parse(raw) as EncodedSnapshot;
    if (o.v !== SCHEMA_VERSION) return null;
    return o;
  } catch {
    return null;
  }
}

function toSnapshot(enc: EncodedSnapshot): IdempotencySnapshot {
  return Object.freeze({
    key: enc.key,
    state: enc.state,
    fingerprint: enc.fingerprint,
    response: enc.response,
    error: enc.error,
    inFlightSince: enc.inFlightSince,
    completedAt: enc.completedAt,
    expiresAt: enc.expiresAt,
    version: enc.version,
  }) as IdempotencySnapshot;
}

export class RedisIdempotencyProvider implements IdempotencyProvider {
  readonly name = 'redis';
  readonly version = SCHEMA_VERSION;
  private readonly client: RedisClientAdapter;
  private readonly keyPrefix: string;

  constructor(options: RedisIdempotencyProviderOptions) {
    this.client = options.client;
    this.keyPrefix = options.keyPrefix ?? 'default';
  }

  private redisKey(key: string): string {
    return buildRedisKey('idem', [this.keyPrefix, key]);
  }
  private channel(key: string): string {
    return buildRedisChannel('notify', ['idem', this.keyPrefix, hashString(key)]);
  }

  async lookup(key: string, _now?: number): Promise<IdempotencySnapshot | null> {
    void _now;
    const raw = await this.client.get(this.redisKey(key));
    if (raw === null) return null;
    const dec = decode(raw);
    if (dec === null) return null;
    return toSnapshot(dec);
  }

  async acquire(
    key: string,
    fingerprint: string,
    ttlMs: number,
    _now?: number,
  ): Promise<AcquireResult> {
    void _now;
    if (!Number.isFinite(ttlMs) || ttlMs <= 0) {
      throw new Error('ttlMs must be positive finite');
    }
    const now = Date.now();
    const proposed: EncodedSnapshot = {
      v: SCHEMA_VERSION,
      key,
      state: 'in-flight',
      fingerprint,
      inFlightSince: now,
      completedAt: null,
      expiresAt: now + ttlMs,
      version: 1,
      response: null,
      error: null,
    };
    const set = await this.client.set(this.redisKey(key), encode(proposed), {
      ttlMs,
      ifNotExists: true,
    });
    if (set) return { acquired: true, current: toSnapshot(proposed) };
    const existing = await this.lookup(key);
    if (existing === null) {
      const set2 = await this.client.set(this.redisKey(key), encode(proposed), {
        ttlMs,
        ifNotExists: true,
      });
      if (set2) return { acquired: true, current: toSnapshot(proposed) };
      const existing2 = await this.lookup(key);
      if (existing2 === null) throw new Error('idempotency acquire: race after retry');
      if (existing2.fingerprint !== fingerprint) {
        throw new Error(`Idempotency-Key "${key}" was used with a different request fingerprint`);
      }
      return { acquired: false, current: existing2 };
    }
    if (existing.fingerprint !== fingerprint) {
      throw new Error(`Idempotency-Key "${key}" was used with a different request fingerprint`);
    }
    return { acquired: false, current: existing };
  }

  async complete(
    key: string,
    response: StoredResponse,
    ttlMs: number,
    _now?: number,
  ): Promise<void> {
    void _now;
    const existing = await this.lookup(key);
    if (existing === null) return;
    if (existing.state !== 'in-flight') {
      throw new Error(`Cannot complete key "${key}" in state "${existing.state}"`);
    }
    const frozenResp: StoredResponse = Object.freeze({
      status: response.status,
      headers: Object.freeze({ ...response.headers }) as Readonly<Record<string, string>>,
      body: response.body,
    }) as StoredResponse;
    const updated: EncodedSnapshot = {
      v: SCHEMA_VERSION,
      key,
      state: 'done',
      fingerprint: existing.fingerprint,
      inFlightSince: existing.inFlightSince,
      completedAt: Date.now(),
      expiresAt: existing.expiresAt,
      version: existing.version + 1,
      response: frozenResp,
      error: null,
    };
    const newTtl = Math.max(1, updated.expiresAt - Date.now());
    await this.client.set(this.redisKey(key), encode(updated), { ttlMs: newTtl });
    await this.client.publish(this.channel(key), JSON.stringify({ key, version: updated.version }));
  }

  async release(key: string, _now?: number): Promise<void> {
    void _now;
    const existing = await this.lookup(key);
    if (existing === null) return;
    if (existing.state !== 'in-flight') return;
    await this.client.del(this.redisKey(key));
    await this.client.publish(this.channel(key), JSON.stringify({ key, released: true }));
  }

  async waitForCompletion(
    key: string,
    deadlineMs: number,
    _now?: number,
  ): Promise<IdempotencySnapshot | null> {
    void _now;
    const current = await this.lookup(key);
    if (current === null) return null;
    if (current.state === 'done') return current;
    return new Promise<IdempotencySnapshot | null>((resolve, reject) => {
      const timer = setTimeout(
        () => {
          void unsubscribe();
          void this.lookup(key).then((s) => {
            if (s !== null && s.state === 'done') resolve(s);
            else if (s === null) resolve(null);
            else reject(new Error(`Timed out waiting for idempotency key "${key}" to complete`));
          });
        },
        Math.max(0, deadlineMs),
      );
      if (typeof timer.unref === 'function') timer.unref();
      let unsubscribe: () => Promise<void> = async () => undefined;
      this.client
        .subscribe(this.channel(key), () => {
          void this.lookup(key)
            .then((s) => {
              if (s === null) {
                void unsubscribe();
                resolve(null);
                return;
              }
              if (s.state === 'done') {
                void unsubscribe();
                resolve(s);
              }
            })
            .catch((err) => {
              void unsubscribe();
              reject(err);
            });
        })
        .then((u) => {
          unsubscribe = u;
        })
        .catch((err) => {
          clearTimeout(timer);
          reject(err);
        });
    });
  }

  async shutdown(): Promise<void> {
    /* adapter-owned */
  }
}
