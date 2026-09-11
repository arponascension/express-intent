import { createHash } from 'node:crypto';
import type { Actor } from './types.js';
import type { RateLimitScope, RateLimitSpec, RateLimitResult } from './rate-limit-defs.js';

const MAX_SUBJECT_LENGTH = 256;
const MAX_IP_LENGTH = 64;

function hashKey(s: string): string {
  return createHash('sha256').update(s).digest('hex').slice(0, 16);
}

function normalize(value: string): string {
  const t = value.toLowerCase().trim();
  if (t.length <= MAX_SUBJECT_LENGTH) return t;
  return t.slice(0, MAX_SUBJECT_LENGTH);
}

function normalizeIp(value: string): string {
  const t = value.trim();
  if (t.length === 0) return 'unknown';
  if (t.length <= MAX_IP_LENGTH && looksLikeIp(t)) return t;
  if (t.length <= MAX_IP_LENGTH) return t;
  return hashKey(t);
}

function looksLikeIp(s: string): boolean {
  if (s.length > 64) return false;
  return /^[0-9a-fA-F:.]+$/.test(s);
}

export function buildRateLimitKey(
  scope: RateLimitScope,
  namespace: string,
  actor: Actor | null,
  ip: string | null,
  action: string,
  custom?: string,
): string {
  switch (scope) {
    case 'actor': {
      const subject = actor?.subject ?? 'anonymous';
      const normalized = normalize(subject);
      const hashed = normalized.length > 32 ? hashKey(normalized) : normalized;
      return `rl:${namespace}:actor:${hashed}`;
    }
    case 'ip': {
      const value = ip ?? 'unknown';
      const normalized = normalizeIp(value);
      return `rl:${namespace}:ip:${normalized}`;
    }
    case 'action': {
      const normalized = normalize(action);
      const hashed = normalized.length > 32 ? hashKey(normalized) : normalized;
      return `rl:${namespace}:action:${hashed}`;
    }
    case 'custom': {
      if (!custom) {
        throw new Error('buildRateLimitKey with scope "custom" requires a custom key');
      }
      const normalized = normalize(custom);
      const hashed = normalized.length > 0 ? hashKey(normalized) : hashKey('empty');
      return `rl:${namespace}:custom:${hashed}`;
    }
  }
}

export interface InMemoryRateLimiterOptions {
  readonly sweepIntervalMs?: number;
  readonly clock?: () => number;
  readonly maxKeys?: number;
}

interface Bucket {
  count: number;
  expiresAt: number;
}

export class InMemoryRateLimiter {
  private readonly buckets = new Map<string, Bucket>();
  private readonly clock: () => number;
  private readonly maxKeys: number;
  private sweeper: ReturnType<typeof setInterval> | undefined;

  constructor(options: InMemoryRateLimiterOptions = {}) {
    this.clock = options.clock ?? (() => Date.now());
    this.maxKeys = options.maxKeys ?? 100_000;
    const sweepIntervalMs = options.sweepIntervalMs ?? 60_000;
    if (sweepIntervalMs > 0) {
      this.sweeper = setInterval(() => this.sweep(), sweepIntervalMs);
      if (typeof this.sweeper.unref === 'function') this.sweeper.unref();
    }
  }

  async consume(spec: RateLimitSpec): Promise<RateLimitResult> {
    const now = spec.now ?? this.clock();
    if (!Number.isFinite(spec.max) || spec.max < 0) {
      throw new Error(`RateLimitSpec.max must be a non-negative finite number, got ${spec.max}`);
    }
    if (!Number.isFinite(spec.windowMs) || spec.windowMs <= 0) {
      throw new Error(
        `RateLimitSpec.windowMs must be a positive finite number, got ${spec.windowMs}`,
      );
    }
    if (spec.scope === 'custom' && !spec.key) {
      throw new Error('RateLimitSpec with scope "custom" requires a `key`');
    }

    const actor = spec.actor ?? null;
    const ip = spec.ip ?? null;
    const key = buildRateLimitKey(spec.scope, spec.namespace, actor, ip, spec.action, spec.key);

    const expiresAt = now + spec.windowMs;
    const existing = this.buckets.get(key);
    if (existing === undefined || existing.expiresAt <= now) {
      if (this.buckets.size >= this.maxKeys && existing === undefined) {
        this.evictOne();
      }
      const fresh: Bucket = { count: 1, expiresAt };
      this.buckets.set(key, fresh);
      return {
        allowed: 1 <= spec.max,
        limit: spec.max,
        remaining: Math.max(0, spec.max - 1),
        count: 1,
        retryAfterMs: 0,
        resetAt: expiresAt,
        namespace: spec.namespace,
        scope: spec.scope,
        key,
      };
    }

    existing.count += 1;
    const allowed = existing.count <= spec.max;
    const remaining = Math.max(0, spec.max - existing.count);
    const retryAfterMs = allowed ? 0 : Math.max(0, existing.expiresAt - now);
    return {
      allowed,
      limit: spec.max,
      remaining,
      count: existing.count,
      retryAfterMs,
      resetAt: existing.expiresAt,
      namespace: spec.namespace,
      scope: spec.scope,
      key,
    };
  }

  async reset(key: string): Promise<void> {
    this.buckets.delete(key);
  }

  async shutdown(): Promise<void> {
    if (this.sweeper !== undefined) {
      clearInterval(this.sweeper);
      this.sweeper = undefined;
    }
    this.buckets.clear();
  }

  sweep(now: number = this.clock()): number {
    let removed = 0;
    for (const [k, b] of this.buckets) {
      if (b.expiresAt <= now) {
        this.buckets.delete(k);
        removed++;
      }
    }
    return removed;
  }

  size(): number {
    return this.buckets.size;
  }

  private evictOne(): void {
    let oldestKey: string | undefined;
    let oldestExpiry = Number.POSITIVE_INFINITY;
    for (const [k, b] of this.buckets) {
      if (b.expiresAt < oldestExpiry) {
        oldestExpiry = b.expiresAt;
        oldestKey = k;
      }
    }
    if (oldestKey !== undefined) this.buckets.delete(oldestKey);
  }
}
