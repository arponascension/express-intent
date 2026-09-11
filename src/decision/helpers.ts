import type {
  AllowDecision,
  ChallengeDecision,
  ChallengeKind,
  DenyDecision,
  MonitorDecision,
  RateLimitDecision,
} from '../types.js';

export function allow(): AllowDecision {
  return { kind: 'allow' };
}

export function monitor(reason: string): MonitorDecision {
  return { kind: 'monitor', reason };
}

export function challenge(
  reason: string,
  kind: ChallengeKind = 'mfa',
  ttlMs: number | null = null,
): ChallengeDecision {
  return { kind: 'challenge', reason, challenge: kind, ttlMs };
}

export function deny(reason: string, status = 403): DenyDecision {
  return { kind: 'deny', reason, status };
}

export interface RateLimitInit {
  readonly reason: string;
  readonly limit: number;
  readonly remaining: number;
  readonly retryAfterMs: number;
  readonly scope?: RateLimitDecision['scope'];
}

export function rateLimit(
  initOrReason: RateLimitInit | string,
  limit = 100,
  retryAfterMs = 60_000,
  scope: RateLimitDecision['scope'] = 'subject',
): RateLimitDecision {
  if (typeof initOrReason === 'string') {
    return {
      kind: 'rate_limit',
      reason: initOrReason,
      limit,
      remaining: 0,
      retryAfterMs,
      scope,
    };
  }
  return {
    kind: 'rate_limit',
    reason: initOrReason.reason,
    limit: initOrReason.limit,
    remaining: initOrReason.remaining,
    retryAfterMs: initOrReason.retryAfterMs,
    scope: initOrReason.scope ?? 'subject',
  };
}
