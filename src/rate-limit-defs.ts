import type { Actor } from './types.js';

export type RateLimitScope = 'actor' | 'ip' | 'action' | 'custom';

export interface RateLimitSpec {
  readonly namespace: string;
  readonly max: number;
  readonly windowMs: number;
  readonly scope: RateLimitScope;
  readonly actor?: Actor | null;
  readonly ip?: string | null;
  readonly action: string;
  readonly key?: string;
  readonly now?: number;
}

export interface RateLimitResult {
  readonly allowed: boolean;
  readonly limit: number;
  readonly remaining: number;
  readonly count: number;
  readonly retryAfterMs: number;
  readonly resetAt: number;
  readonly namespace: string;
  readonly scope: RateLimitScope;
  readonly key: string;
}

export interface RateLimiter {
  consume(spec: RateLimitSpec): Promise<RateLimitResult>;
  reset(key: string): Promise<void>;
  shutdown?(): Promise<void>;
}
