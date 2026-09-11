import type { Actor, Decision, Intent, Risk, Severity } from '../types.js';
import type { DecisionConfig, DecisionThresholds } from './config.js';
import { DEFAULT_DECISION_CONFIG } from './config.js';

export interface DecisionInput {
  readonly intent: Intent;
  readonly actor: Actor;
  readonly risk?: Risk;
  readonly score?: number;
  readonly requiredSignals?: ReadonlyArray<string>;
  readonly missingSignals?: ReadonlyArray<string>;
}

export interface DecisionEvaluation {
  readonly decision: Decision;
  readonly severity: Severity;
  readonly score: number;
  readonly rule: 'hard-rule' | 'missing-required-signal' | 'severity-threshold' | 'allow';
}

function mergeThresholds(
  base: DecisionThresholds,
  overrides: Intent['decisionOverrides'],
): DecisionThresholds {
  return {
    rateLimitAt: overrides.rateLimitAt ?? base.rateLimitAt,
    challengeAt: overrides.challengeAt ?? base.challengeAt,
    denyAt: overrides.denyAt ?? base.denyAt,
  };
}

function mergeConfig(base: DecisionConfig, intent: Intent): DecisionConfig {
  const o = intent.decisionOverrides;
  return {
    thresholds: mergeThresholds(base.thresholds, o),
    challengeKind: o.challengeKind ?? base.challengeKind,
    challengeTtlMs: o.challengeTtlMs === undefined ? base.challengeTtlMs : o.challengeTtlMs,
    denyStatus: o.denyStatus ?? base.denyStatus,
    defaultLimit: o.limit ?? base.defaultLimit,
  };
}

function severityFromRiskScore(
  score: number,
  thresholds: DecisionThresholds,
): 'allow' | 'monitor' | 'rate_limit' | 'challenge' | 'deny' {
  if (score >= thresholds.denyAt) return 'deny';
  if (score >= thresholds.challengeAt) return 'challenge';
  if (score >= thresholds.rateLimitAt) return 'rate_limit';
  if (score >= thresholds.rateLimitAt / 2) return 'monitor';
  return 'allow';
}

function severityLabel(score: number, thresholds: DecisionThresholds): Severity {
  if (score >= thresholds.denyAt) return 'critical';
  if (score >= thresholds.challengeAt) return 'high';
  if (score >= thresholds.rateLimitAt) return 'medium';
  return 'low';
}

function buildDecision(
  kind: 'allow' | 'monitor' | 'rate_limit' | 'challenge' | 'deny',
  cfg: DecisionConfig,
  ctx: { reason: string; limit: number; retryAfterMs: number; score: number },
): Decision {
  switch (kind) {
    case 'allow':
      return { kind: 'allow' };
    case 'monitor':
      return { kind: 'monitor', reason: ctx.reason };
    case 'rate_limit':
      return {
        kind: 'rate_limit',
        reason: ctx.reason,
        limit: cfg.defaultLimit,
        remaining: 0,
        retryAfterMs: ctx.retryAfterMs,
        scope: 'subject',
      };
    case 'challenge':
      return {
        kind: 'challenge',
        reason: ctx.reason,
        challenge: cfg.challengeKind,
        ttlMs: cfg.challengeTtlMs,
      };
    case 'deny':
      return { kind: 'deny', reason: ctx.reason, status: cfg.denyStatus };
  }
}

export function evaluateDecision(
  input: DecisionInput,
  baseConfig: DecisionConfig = DEFAULT_DECISION_CONFIG,
): DecisionEvaluation {
  const cfg = mergeConfig(baseConfig, input.intent);
  const score = clamp100(input.score ?? 0);
  const required = new Set(input.requiredSignals ?? []);
  const missing = new Set(input.missingSignals ?? input.risk?.missing ?? []);

  // Hard rule: mfa-required intent + anonymous actor → challenge mfa
  if (input.intent.auth === 'mfa-required' && !input.actor.authenticated) {
    return {
      decision: {
        kind: 'challenge',
        reason: 'mfa-required but actor not authenticated',
        challenge: cfg.challengeKind,
        ttlMs: cfg.challengeTtlMs,
      },
      severity: 'high',
      score,
      rule: 'hard-rule',
    };
  }

  // Hard rule: destructive mutation + not authenticated → deny
  if (input.intent.mutation === 'destructive' && !input.actor.authenticated) {
    return {
      decision: {
        kind: 'deny',
        reason: 'destructive mutation requires authentication',
        status: cfg.denyStatus,
      },
      severity: 'critical',
      score,
      rule: 'hard-rule',
    };
  }

  // Hard rule: required-but-missing signal → deny (fail-closed)
  const requiredMissing = [...required].filter((n) => missing.has(n));
  if (requiredMissing.length > 0) {
    return {
      decision: {
        kind: 'deny',
        reason: `required signals missing: ${requiredMissing.sort().join(',')}`,
        status: cfg.denyStatus,
      },
      severity: 'critical',
      score,
      rule: 'missing-required-signal',
    };
  }

  const kind = severityFromRiskScore(score, cfg.thresholds);
  const severity = severityLabel(score, cfg.thresholds);

  const retryAfterMs = computeRetryAfter(score, cfg);
  const reason =
    kind === 'allow'
      ? 'within thresholds'
      : `risk score ${score.toFixed(1)} crossed ${kind} threshold`;

  const decision =
    kind === 'allow'
      ? { kind: 'allow' as const }
      : buildDecision(kind, cfg, { reason, limit: cfg.defaultLimit, retryAfterMs, score });

  return {
    decision,
    severity,
    score,
    rule: kind === 'allow' ? 'allow' : 'severity-threshold',
  };
}

function clamp100(n: number): number {
  if (Number.isNaN(n)) return 0;
  if (n < 0) return 0;
  if (n > 100) return 100;
  return n;
}

function computeRetryAfter(score: number, cfg: DecisionConfig): number {
  const ratio =
    (score - cfg.thresholds.rateLimitAt) / Math.max(1, 100 - cfg.thresholds.rateLimitAt);
  const clamped = ratio < 0 ? 0 : ratio > 1 ? 1 : ratio;
  return Math.round(1_000 + clamped * 59_000);
}
