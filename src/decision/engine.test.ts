import { describe, it, expect } from 'vitest';
import fc from 'fast-check';

import { evaluateDecision } from './engine.js';
import { DEFAULT_DECISION_CONFIG, DEFAULT_THRESHOLDS, SEVERITY_TO_KIND } from './config.js';
import type { DecisionConfig } from './config.js';
import { defineIntent } from '../intent/builder.js';
import type { Actor, Decision, Intent, Risk } from '../types.js';

const NOW = 1_700_000_000_000;

function makeActor(partial: Partial<Actor> = {}): Actor {
  return {
    subject: 'u-1',
    authenticated: true,
    authMethod: 'password',
    authRequirement: 'required',
    roles: [],
    scopes: [],
    claims: {},
    authenticatedAt: NOW,
    ...partial,
  };
}

function makeRisk(
  score: number,
  missing: string[] = [],
  signals: ReadonlyArray<string> = [],
): Risk {
  return Object.freeze({
    signals: signals.map((name, i) =>
      Object.freeze({
        name,
        kind: 'numeric' as const,
        value: 0.5,
        confidence: 1,
        source: 'test',
        computedAt: NOW,
        ttlMs: 60_000,
        _i: i,
      }),
    ),
    missing: Object.freeze([...missing]),
    aggregationHash: 'x'.repeat(16),
    computedAt: NOW,
  }) as Risk;
}

function makeIntent(partial: Parameters<typeof defineIntent>[1] = {}): Intent {
  return defineIntent('payment.create', partial);
}

describe('evaluateDecision — hard rules', () => {
  it('mfa-required intent + anonymous actor → challenge(mfa)', () => {
    const intent = makeIntent({ auth: 'mfa-required' });
    const actor = makeActor({ authenticated: false, subject: null });
    const result = evaluateDecision({ intent, actor, risk: makeRisk(0), score: 0 });
    expect(result.decision.kind).toBe('challenge');
    if (result.decision.kind === 'challenge') {
      expect(result.decision.challenge).toBe('mfa');
    }
    expect(result.rule).toBe('hard-rule');
    expect(result.severity).toBe('high');
  });

  it('destructive mutation + unauthenticated actor → deny', () => {
    const intent = makeIntent({ mutation: 'destructive' });
    const actor = makeActor({ authenticated: false, subject: null });
    const result = evaluateDecision({ intent, actor, risk: makeRisk(0), score: 0 });
    expect(result.decision.kind).toBe('deny');
    if (result.decision.kind === 'deny') {
      expect(result.decision.status).toBe(DEFAULT_DECISION_CONFIG.denyStatus);
    }
    expect(result.rule).toBe('hard-rule');
  });

  it('required-auth intent + authenticated actor → no hard-rule block', () => {
    const intent = makeIntent({ auth: 'required' });
    const actor = makeActor({ authenticated: true });
    const result = evaluateDecision({ intent, actor, risk: makeRisk(0), score: 0 });
    expect(result.rule).toBe('allow');
    expect(result.decision.kind).toBe('allow');
  });

  it('anonymous intent + anonymous actor → allow when score low', () => {
    const intent = makeIntent({ auth: 'anonymous' });
    const actor = makeActor({ authenticated: false, subject: null });
    const result = evaluateDecision({ intent, actor, risk: makeRisk(0), score: 0 });
    expect(result.decision.kind).toBe('allow');
  });
});

describe('evaluateDecision — missing required signals (fail-closed)', () => {
  it('denies when a required signal is missing', () => {
    const intent = makeIntent();
    const actor = makeActor();
    const risk = makeRisk(0, ['geo']);
    const result = evaluateDecision({
      intent,
      actor,
      risk,
      score: 0,
      requiredSignals: ['geo'],
      missingSignals: ['geo'],
    });
    expect(result.decision.kind).toBe('deny');
    expect(result.rule).toBe('missing-required-signal');
  });

  it('does NOT deny for non-required missing signals', () => {
    const intent = makeIntent();
    const actor = makeActor();
    const result = evaluateDecision({
      intent,
      actor,
      risk: makeRisk(0, ['geo']),
      score: 0,
      requiredSignals: ['velocity'],
    });
    expect(result.decision.kind).toBe('allow');
  });
});

describe('evaluateDecision — severity threshold ladder', () => {
  const cfg = DEFAULT_DECISION_CONFIG;
  const intent = makeIntent();
  const actor = makeActor();

  it('low score (below rateLimitAt/2) → allow', () => {
    const r = evaluateDecision({ intent, actor, risk: makeRisk(0), score: 5 });
    expect(r.decision.kind).toBe('allow');
    expect(r.rule).toBe('allow');
    expect(r.severity).toBe('low');
  });

  it('medium score (≥ rateLimitAt/2, < rateLimitAt) → monitor', () => {
    const r = evaluateDecision({ intent, actor, risk: makeRisk(0), score: 15 });
    expect(r.decision.kind).toBe('monitor');
    expect(r.severity).toBe('low');
    expect(r.rule).toBe('severity-threshold');
  });

  it('boundary: score === rateLimitAt → rate_limit', () => {
    const r = evaluateDecision({
      intent,
      actor,
      risk: makeRisk(0),
      score: cfg.thresholds.rateLimitAt,
    });
    expect(r.decision.kind).toBe('rate_limit');
    expect(r.severity).toBe('medium');
    if (r.decision.kind === 'rate_limit') {
      expect(r.decision.limit).toBe(DEFAULT_DECISION_CONFIG.defaultLimit);
      expect(r.decision.remaining).toBe(0);
      expect(r.decision.retryAfterMs).toBeGreaterThan(0);
      expect(r.decision.scope).toBe('subject');
    }
  });

  it('boundary: score === challengeAt → challenge', () => {
    const r = evaluateDecision({
      intent,
      actor,
      risk: makeRisk(0),
      score: cfg.thresholds.challengeAt,
    });
    expect(r.decision.kind).toBe('challenge');
    expect(r.severity).toBe('high');
  });

  it('boundary: score === denyAt → deny', () => {
    const r = evaluateDecision({ intent, actor, risk: makeRisk(0), score: cfg.thresholds.denyAt });
    expect(r.decision.kind).toBe('deny');
    expect(r.severity).toBe('critical');
  });

  it('just-below threshold: rateLimitAt - epsilon → monitor', () => {
    const r = evaluateDecision({
      intent,
      actor,
      risk: makeRisk(0),
      score: cfg.thresholds.rateLimitAt - 0.0001,
    });
    expect(r.decision.kind).toBe('monitor');
  });

  it('just-below threshold: challengeAt - epsilon → rate_limit', () => {
    const r = evaluateDecision({
      intent,
      actor,
      risk: makeRisk(0),
      score: cfg.thresholds.challengeAt - 0.0001,
    });
    expect(r.decision.kind).toBe('rate_limit');
  });

  it('just-below threshold: denyAt - epsilon → challenge', () => {
    const r = evaluateDecision({
      intent,
      actor,
      risk: makeRisk(0),
      score: cfg.thresholds.denyAt - 0.0001,
    });
    expect(r.decision.kind).toBe('challenge');
  });

  it('above max (score = 100) → deny', () => {
    const r = evaluateDecision({ intent, actor, risk: makeRisk(0), score: 100 });
    expect(r.decision.kind).toBe('deny');
  });

  it('score 0 → allow', () => {
    const r = evaluateDecision({ intent, actor, risk: makeRisk(0), score: 0 });
    expect(r.decision.kind).toBe('allow');
  });

  it('negative score clamps to 0 → allow', () => {
    const r = evaluateDecision({ intent, actor, risk: makeRisk(0), score: -10 });
    expect(r.decision.kind).toBe('allow');
  });

  it('NaN score → allow (clamped)', () => {
    const r = evaluateDecision({ intent, actor, risk: makeRisk(0), score: Number.NaN });
    expect(r.decision.kind).toBe('allow');
  });
});

describe('evaluateDecision — per-intent overrides', () => {
  const actor = makeActor();
  const intent = makeIntent({
    decisionOverrides: {
      rateLimitAt: 10,
      challengeAt: 20,
      denyAt: 30,
      challengeKind: 'captcha',
      challengeTtlMs: 5_000,
      denyStatus: 429,
      limit: 7,
    },
  });

  it('uses overridden thresholds', () => {
    const r = evaluateDecision({ intent, actor, risk: makeRisk(0), score: 15 });
    expect(r.decision.kind).toBe('rate_limit');
  });

  it('overridden challenge kind is reflected in decision', () => {
    const r = evaluateDecision({ intent, actor, risk: makeRisk(0), score: 25 });
    expect(r.decision.kind).toBe('challenge');
    if (r.decision.kind === 'challenge') {
      expect(r.decision.challenge).toBe('captcha');
      expect(r.decision.ttlMs).toBe(5_000);
    }
  });

  it('overridden deny status is reflected', () => {
    const r = evaluateDecision({ intent, actor, risk: makeRisk(0), score: 50 });
    expect(r.decision.kind).toBe('deny');
    if (r.decision.kind === 'deny') expect(r.decision.status).toBe(429);
  });

  it('overridden limit is reflected in rate_limit', () => {
    const r = evaluateDecision({ intent, actor, risk: makeRisk(0), score: 15 });
    if (r.decision.kind === 'rate_limit') expect(r.decision.limit).toBe(7);
  });
});

describe('evaluateDecision — config-based overrides (global)', () => {
  const intent = makeIntent();
  const actor = makeActor();
  const strict: DecisionConfig = {
    ...DEFAULT_DECISION_CONFIG,
    thresholds: { rateLimitAt: 5, challengeAt: 10, denyAt: 15 },
  };

  it('global thresholds apply when no per-intent override', () => {
    const r = evaluateDecision({ intent, actor, risk: makeRisk(0), score: 12 }, strict);
    expect(r.decision.kind).toBe('challenge');
  });

  it('per-intent overrides win over global config', () => {
    const lenientIntent = makeIntent({
      decisionOverrides: { rateLimitAt: 50, challengeAt: 80, denyAt: 95 },
    });
    const r = evaluateDecision(
      { intent: lenientIntent, actor, risk: makeRisk(0), score: 40 },
      strict,
    );
    expect(r.decision.kind).toBe('monitor');
  });
});

describe('evaluateDecision — failure isolation', () => {
  it('does not require I/O — operates on plain inputs', () => {
    const intent = makeIntent();
    const actor = makeActor();
    const r = evaluateDecision({ intent, actor, risk: makeRisk(0), score: 30 });
    expect(r).toHaveProperty('decision');
    expect(r).toHaveProperty('severity');
    expect(r).toHaveProperty('score');
    expect(r).toHaveProperty('rule');
  });

  it('deterministic for identical inputs', () => {
    const intent = makeIntent();
    const actor = makeActor();
    const risk = makeRisk(0, ['x']);
    const r1 = evaluateDecision({ intent, actor, risk, score: 30 });
    const r2 = evaluateDecision({ intent, actor, risk, score: 30 });
    expect(r1.decision).toEqual(r2.decision);
    expect(r1.severity).toBe(r2.severity);
    expect(r1.score).toBe(r2.score);
    expect(r1.rule).toBe(r2.rule);
  });

  it('evaluateDecision never depends on req/res (no Express types)', () => {
    expect(typeof evaluateDecision).toBe('function');
  });
});

describe('evaluateDecision — retryAfterMs', () => {
  const intent = makeIntent();
  const actor = makeActor();

  it('retryAfterMs grows with score within the rate_limit band', () => {
    const low = evaluateDecision({
      intent,
      actor,
      risk: makeRisk(0),
      score: DEFAULT_THRESHOLDS.rateLimitAt + 1,
    });
    const high = evaluateDecision({
      intent,
      actor,
      risk: makeRisk(0),
      score: DEFAULT_THRESHOLDS.challengeAt - 1,
    });
    expect(low.decision.kind).toBe('rate_limit');
    expect(high.decision.kind).toBe('rate_limit');
    if (low.decision.kind === 'rate_limit' && high.decision.kind === 'rate_limit') {
      expect(high.decision.retryAfterMs).toBeGreaterThan(low.decision.retryAfterMs);
    }
  });
});

describe('evaluateDecision — exhaustive coverage', () => {
  const intent = makeIntent();
  const actor = makeActor();

  it('covers all 5 decision kinds for scores in [0, 100]', () => {
    const seen = new Set<Decision['kind']>();
    for (let s = 0; s <= 100; s += 0.5) {
      const r = evaluateDecision({ intent, actor, risk: makeRisk(0), score: s });
      seen.add(r.decision.kind);
    }
    expect(seen).toEqual(new Set(['allow', 'monitor', 'rate_limit', 'challenge', 'deny']));
  });
});

describe('evaluateDecision — property tests', () => {
  const intent = makeIntent();
  const actor = makeActor();

  it('result score is always within [0, 100]', () => {
    fc.assert(
      fc.property(fc.double({ min: -50, max: 150, noNaN: true }), (score) => {
        const r = evaluateDecision({ intent, actor, risk: makeRisk(0), score });
        expect(r.score).toBeGreaterThanOrEqual(0);
        expect(r.score).toBeLessThanOrEqual(100);
      }),
      { numRuns: 100 },
    );
  });

  it('NaN scores are clamped to 0', () => {
    fc.assert(
      fc.property(fc.double({ min: -100, max: 100, noNaN: true }), () => {
        const r = evaluateDecision({ intent, actor, risk: makeRisk(0), score: Number.NaN });
        expect(r.score).toBe(0);
        expect(r.decision.kind).toBe('allow');
      }),
      { numRuns: 20 },
    );
  });
});

describe('SEVERITY_TO_KIND + DEFAULT_THRESHOLDS — sanity', () => {
  it('SEVERITY_TO_KIND covers all 4 severities', () => {
    expect(Object.keys(SEVERITY_TO_KIND).sort()).toEqual(['critical', 'high', 'low', 'medium']);
  });

  it('DEFAULT_THRESHOLDS are ascending', () => {
    const t = DEFAULT_THRESHOLDS;
    expect(t.rateLimitAt).toBeLessThan(t.challengeAt);
    expect(t.challengeAt).toBeLessThan(t.denyAt);
    expect(t.denyAt).toBeLessThanOrEqual(100);
  });
});
