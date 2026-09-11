import type {
  AcquireResult,
  IdempotencyProvider,
  IdempotencySnapshot,
  IdempotencyState,
  StoredResponse,
} from './idempotency-defs.js';

interface Entry {
  readonly key: string;
  readonly fingerprint: string;
  state: IdempotencyState;
  readonly inFlightSince: number | null;
  completedAt: number | null;
  readonly expiresAt: number;
  response: StoredResponse | null;
  error: string | null;
  version: number;
  waiters: Array<{
    resolve: (s: IdempotencySnapshot | null) => void;
    reject: (e: Error) => void;
    deadline: number;
  }>;
}

export interface InMemoryIdempotencyProviderOptions {
  readonly maxEntries?: number;
  readonly clock?: () => number;
}

function snapshot(e: Entry): IdempotencySnapshot {
  return Object.freeze({
    key: e.key,
    state: e.state,
    fingerprint: e.fingerprint,
    response: e.response,
    error: e.error,
    inFlightSince: e.inFlightSince,
    completedAt: e.completedAt,
    expiresAt: e.expiresAt,
    version: e.version,
  }) as IdempotencySnapshot;
}

export class InMemoryIdempotencyProvider implements IdempotencyProvider {
  readonly name = 'in-memory';
  readonly version = 1;
  private readonly entries = new Map<string, Entry>();
  private readonly maxEntries: number;
  private readonly clock: () => number;

  constructor(options: InMemoryIdempotencyProviderOptions = {}) {
    this.maxEntries = options.maxEntries ?? 10_000;
    this.clock = options.clock ?? (() => Date.now());
  }

  async lookup(key: string, now: number = this.clock()): Promise<IdempotencySnapshot | null> {
    const e = this.entries.get(key);
    if (e === undefined) return null;
    if (e.expiresAt <= now) {
      this.entries.delete(key);
      this.rejectWaiters(e, new Error('idempotency key expired'));
      return null;
    }
    return snapshot(e);
  }

  async acquire(
    key: string,
    fingerprint: string,
    ttlMs: number,
    now: number = this.clock(),
  ): Promise<AcquireResult> {
    if (!Number.isFinite(ttlMs) || ttlMs <= 0) {
      throw new Error(`ttlMs must be a positive finite number, got ${ttlMs}`);
    }
    const existing = this.entries.get(key);
    if (existing !== undefined) {
      if (existing.expiresAt <= now) {
        this.entries.delete(key);
        this.rejectWaiters(existing, new Error('idempotency key expired'));
      } else {
        if (existing.fingerprint !== fingerprint) {
          throw new Error(`Idempotency-Key "${key}" was used with a different request fingerprint`);
        }
        return { acquired: false, current: snapshot(existing) };
      }
    }

    if (this.entries.size >= this.maxEntries) this.evictOne();

    const entry: Entry = {
      key,
      fingerprint,
      state: 'in-flight',
      inFlightSince: now,
      completedAt: null,
      expiresAt: now + ttlMs,
      response: null,
      error: null,
      version: 1,
      waiters: [],
    };
    this.entries.set(key, entry);
    return { acquired: true, current: snapshot(entry) };
  }

  async complete(
    key: string,
    response: StoredResponse,
    ttlMs: number,
    now: number = this.clock(),
  ): Promise<void> {
    const e = this.entries.get(key);
    if (e === undefined) return;
    if (e.state !== 'in-flight') {
      throw new Error(`Cannot complete key "${key}" in state "${e.state}"`);
    }
    const freshExpiresAt = now + ttlMs;
    if (e.expiresAt > freshExpiresAt) {
      this.entries.set(key, {
        ...e,
        state: 'done',
        completedAt: now,
        expiresAt: e.expiresAt,
        response: Object.freeze({
          status: response.status,
          headers: Object.freeze({ ...response.headers }) as Readonly<Record<string, string>>,
          body: response.body,
        }) as StoredResponse,
        version: e.version + 1,
      });
    } else {
      this.entries.set(key, {
        ...e,
        state: 'done',
        completedAt: now,
        expiresAt: freshExpiresAt,
        response: Object.freeze({
          status: response.status,
          headers: Object.freeze({ ...response.headers }) as Readonly<Record<string, string>>,
          body: response.body,
        }) as StoredResponse,
        version: e.version + 1,
      });
    }
    const finished = this.entries.get(key)!;
    this.notifyWaiters(finished);
  }

  async release(key: string, now: number = this.clock()): Promise<void> {
    const e = this.entries.get(key);
    if (e === undefined) return;
    if (e.state !== 'in-flight') return;
    this.entries.delete(key);
    this.rejectWaiters(e, new Error('idempotency key released'));
    void now;
  }

  async waitForCompletion(
    key: string,
    deadlineMs: number,
    now: number = this.clock(),
  ): Promise<IdempotencySnapshot | null> {
    const e = this.entries.get(key);
    if (e === undefined) return null;
    if (e.state === 'done') return snapshot(e);
    if (e.expiresAt <= now) {
      this.entries.delete(key);
      return null;
    }
    return new Promise<IdempotencySnapshot | null>((resolve, reject) => {
      const waiter = { resolve, reject, deadline: now + deadlineMs };
      e.waiters.push(waiter);
      const timer = setTimeout(
        () => {
          const idx = e.waiters.indexOf(waiter);
          if (idx >= 0) e.waiters.splice(idx, 1);
          const cur = this.entries.get(key);
          if (cur !== undefined && cur.state !== 'done') {
            reject(new Error(`Timed out waiting for idempotency key "${key}" to complete`));
          } else {
            resolve(cur ? snapshot(cur) : null);
          }
        },
        Math.max(0, deadlineMs),
      );
      if (typeof timer.unref === 'function') timer.unref();
    });
  }

  async shutdown(): Promise<void> {
    for (const e of this.entries.values()) {
      this.rejectWaiters(e, new Error('provider shutdown'));
    }
    this.entries.clear();
  }

  size(): number {
    return this.entries.size;
  }

  private notifyWaiters(e: Entry): void {
    const snap = snapshot(e);
    for (const w of e.waiters) w.resolve(snap);
    e.waiters.length = 0;
  }

  private rejectWaiters(e: Entry, err: Error): void {
    for (const w of e.waiters) w.reject(err);
    e.waiters.length = 0;
  }

  private evictOne(): void {
    let oldestKey: string | undefined;
    let oldestExpiry = Number.POSITIVE_INFINITY;
    for (const [k, e] of this.entries) {
      if (e.expiresAt < oldestExpiry) {
        oldestExpiry = e.expiresAt;
        oldestKey = k;
      }
    }
    if (oldestKey !== undefined) this.entries.delete(oldestKey);
  }
}
