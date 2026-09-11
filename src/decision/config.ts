import type { ChallengeKind, Severity } from '../types.js';

export interface DecisionThresholds {
  readonly rateLimitAt: number;
  readonly challengeAt: number;
  readonly denyAt: number;
}

export interface DecisionConfig {
  readonly thresholds: DecisionThresholds;
  readonly challengeKind: ChallengeKind;
  readonly challengeTtlMs: number | null;
  readonly denyStatus: number;
  readonly defaultLimit: number;
}

export const DEFAULT_CHALLENGE: ChallengeKind = 'mfa';
export const DEFAULT_DENY_STATUS = 403;
export const DEFAULT_CHALLENGE_TTL_MS: number | null = 60_000;
export const DEFAULT_LIMIT = 100;

export const DEFAULT_THRESHOLDS: DecisionThresholds = {
  rateLimitAt: 25,
  challengeAt: 50,
  denyAt: 75,
};

export const DEFAULT_DECISION_CONFIG: DecisionConfig = {
  thresholds: DEFAULT_THRESHOLDS,
  challengeKind: DEFAULT_CHALLENGE,
  challengeTtlMs: DEFAULT_CHALLENGE_TTL_MS,
  denyStatus: DEFAULT_DENY_STATUS,
  defaultLimit: DEFAULT_LIMIT,
};

export const SEVERITY_TO_KIND: Readonly<
  Record<Severity, 'allow' | 'monitor' | 'rate_limit' | 'challenge' | 'deny'>
> = {
  low: 'allow',
  medium: 'monitor',
  high: 'challenge',
  critical: 'deny',
};
