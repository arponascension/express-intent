import type { Observation } from './anomaly-defs.js';

export interface ObservationStore {
  record(observation: Observation): void | Promise<void>;
  recent(query: {
    actorSubject?: string | null;
    ip?: string | null;
    now: number;
    windowMs: number;
  }): ReadonlyArray<Observation> | Promise<ReadonlyArray<Observation>>;
  clear(): void | Promise<void>;
}

export interface InMemoryObservationStoreOptions {
  readonly maxEntries?: number;
  readonly ttlMs?: number;
  readonly clock?: () => number;
  /**
   * Run the TTL purge at most once every N records. Set to 0 to purge on
   * every write (default behaviour, useful only for tests). Higher values
   * trade memory boundedness for throughput. Default 1024.
   */
  readonly purgeEvery?: number;
}

interface Entry {
  readonly observation: Observation;
}

export class InMemoryObservationStore implements ObservationStore {
  private readonly entries: Entry[] = [];
  private readonly maxEntries: number;
  private readonly ttlMs: number;
  private readonly clock: () => number;
  private readonly purgeEvery: number;
  private writesSincePurge = 0;
  private maxObservedNow = 0;

  constructor(options: InMemoryObservationStoreOptions = {}) {
    this.maxEntries = options.maxEntries ?? 10_000;
    this.ttlMs = options.ttlMs ?? 5 * 60_000;
    this.clock = options.clock ?? (() => Date.now());
    this.purgeEvery = options.purgeEvery ?? 1024;
  }

  record(observation: Observation): void {
    if (observation.now > this.maxObservedNow) this.maxObservedNow = observation.now;
    this.entries.push({ observation });
    if (++this.writesSincePurge >= this.purgeEvery) {
      this.purge();
      this.writesSincePurge = 0;
      while (this.entries.length > this.maxEntries) this.entries.shift();
    } else if (this.entries.length > this.maxEntries) {
      // Single shift to enforce cap; full purge happens periodically.
      this.entries.shift();
    }
  }

  recent(query: {
    actorSubject?: string | null;
    ip?: string | null;
    now: number;
    windowMs: number;
  }): ReadonlyArray<Observation> {
    const cutoff = query.now - query.windowMs;
    const ttlCutoff = query.now - this.ttlMs;
    const out: Observation[] = [];
    for (let i = 0; i < this.entries.length; i++) {
      const o = this.entries[i]!.observation;
      if (o.now < cutoff) continue;
      if (o.now < ttlCutoff) continue;
      if (query.actorSubject !== undefined && o.actorSubject !== query.actorSubject) continue;
      if (query.ip !== undefined && o.ip !== query.ip) continue;
      out.push(o);
    }
    return Object.freeze(out) as ReadonlyArray<Observation>;
  }

  clear(): void {
    this.entries.length = 0;
    this.writesSincePurge = 0;
    this.maxObservedNow = 0;
  }

  size(): number {
    return this.entries.length;
  }

  purge(): number {
    const now = this.maxObservedNow;
    // Two-pointer compaction: O(n) instead of O(n^2) splice loop.
    let writeIdx = 0;
    let removed = 0;
    for (let readIdx = 0; readIdx < this.entries.length; readIdx++) {
      const o = this.entries[readIdx]!.observation;
      if (o.now + this.ttlMs < now) {
        removed++;
        continue;
      }
      if (writeIdx !== readIdx) this.entries[writeIdx] = this.entries[readIdx]!;
      writeIdx++;
    }
    this.entries.length = writeIdx;
    return removed;
  }
}
