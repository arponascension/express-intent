import type { RedisClientAdapter } from './client.js';
import { buildRedisKey, hashString } from './keys.js';
import type { RateLimitResult, RateLimitSpec, RateLimiter } from '../rate-limit-defs.js';

export interface RedisRateLimiterOptions {
  readonly client: RedisClientAdapter;
  readonly keyPrefix?: string;
}

function scopeKey(spec: RateLimitSpec): string {
  switch (spec.scope) {
    case 'actor': {
      const subject = spec.actor?.subject ?? 'anonymous';
      return `actor:${hashString(subject)}`;
    }
    case 'ip': {
      const ip = spec.ip ?? 'unknown';
      return `ip:${hashString(ip)}`;
    }
    case 'action':
      return `action:${hashString(spec.action)}`;
    case 'custom': {
      if (!spec.key) {
        throw new Error('RateLimitSpec with scope "custom" requires spec.key');
      }
      return `custom:${hashString(spec.key)}`;
    }
  }
}

export class RedisRateLimiter implements RateLimiter {
  private readonly client: RedisClientAdapter;
  private readonly keyPrefix: string;

  constructor(options: RedisRateLimiterOptions) {
    this.client = options.client;
    this.keyPrefix = options.keyPrefix ?? 'default';
  }

  private redisKey(spec: RateLimitSpec): string {
    return buildRedisKey('rl', [this.keyPrefix, scopeKey(spec)]);
  }

  async consume(spec: RateLimitSpec): Promise<RateLimitResult> {
    if (spec.max < 0 || !Number.isFinite(spec.windowMs) || spec.windowMs <= 0) {
      throw new Error('Invalid rate limit spec: max>=0 and windowMs>0 required');
    }
    const key = this.redisKey(spec);
    const now = spec.now ?? Date.now();
    const windowMs = spec.windowMs;
    const bucketWindow = Math.floor(now / windowMs) * windowMs;
    const resetAt = bucketWindow + windowMs;
    const expiresAt = resetAt - now;

    const count = await this.client.incr(key);
    await this.client.expire(key, expiresAt);
    const remaining = Math.max(0, spec.max - count);
    const retryAfterMs = count > spec.max ? expiresAt : 0;
    const allowed = count <= spec.max;

    return Object.freeze({
      allowed,
      limit: spec.max,
      remaining,
      count,
      retryAfterMs,
      resetAt,
      namespace: spec.namespace,
      scope: spec.scope,
      key,
    }) as RateLimitResult;
  }

  async reset(key: string): Promise<void> {
    if (key.startsWith('ei:v1:')) {
      await this.client.del(key);
    } else {
      await this.client.del(buildRedisKey('rl', [this.keyPrefix, key]));
    }
  }

  async shutdown(): Promise<void> {
    /* adapter-owned */
  }
}
