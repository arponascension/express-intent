import type { ChallengeKind } from './intent.js';

export type DecisionKind = 'allow' | 'monitor' | 'rate_limit' | 'challenge' | 'deny';

export interface AllowDecision {
  readonly kind: 'allow';
}

export interface MonitorDecision {
  readonly kind: 'monitor';
  readonly reason: string;
}

export interface RateLimitDecision {
  readonly kind: 'rate_limit';
  readonly reason: string;
  readonly limit: number;
  readonly remaining: number;
  readonly retryAfterMs: number;
  readonly scope: 'subject' | 'ip' | 'pair' | 'global' | 'actor' | 'action' | 'custom';
}

export interface ChallengeDecision {
  readonly kind: 'challenge';
  readonly reason: string;
  readonly challenge: ChallengeKind;
  readonly ttlMs: number | null;
}

export interface DenyDecision {
  readonly kind: 'deny';
  readonly reason: string;
  readonly status: number;
}

export type Decision =
  AllowDecision | MonitorDecision | RateLimitDecision | ChallengeDecision | DenyDecision;

export function compareDecisions(a: DecisionKind, b: DecisionKind): number {
  const order: Record<DecisionKind, number> = {
    deny: 0,
    challenge: 1,
    rate_limit: 2,
    monitor: 3,
    allow: 4,
  };
  return order[a] - order[b];
}
