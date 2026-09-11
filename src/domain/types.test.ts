import { describe, it, expect, expectTypeOf } from 'vitest';

import type {
  AllowDecision,
  ChallengeDecision,
  ContextEnricher,
  Decision,
  DecisionKind,
  DenyDecision,
  Intent,
  IntentContext,
  IntentOptions,
  MonitorDecision,
  Policy,
  PolicyAdapter,
  PolicyResult,
  RequestSnapshot,
  Risk,
  RiskSignal,
  SignalProvider,
} from './types.js';
import { compareDecisions, isDecision } from './index.js';
import { allow, deny, challenge, monitor } from '../decision/helpers.js';

describe('Decision — type-level invariants', () => {
  it('discriminates by `kind`', () => {
    const a: AllowDecision = { kind: 'allow' };
    const m: MonitorDecision = { kind: 'monitor', reason: 'new-device' };
    const c: ChallengeDecision = {
      kind: 'challenge',
      reason: 'reauth',
      challenge: 'mfa',
      ttlMs: null,
    };
    const d: DenyDecision = { kind: 'deny', reason: 'blocked', status: 403 };

    function describe(d: Decision): string {
      switch (d.kind) {
        case 'allow':
          return 'a';
        case 'monitor':
          return `m:${d.reason}`;
        case 'challenge':
          return `c:${d.challenge}:${d.ttlMs ?? 'none'}`;
        case 'deny':
          return `d:${d.status}`;
      }
    }

    expect(describe(a)).toBe('a');
    expect(describe(m)).toBe('m:new-device');
    expect(describe(c)).toBe('c:mfa:none');
    expect(describe(d)).toBe('d:403');
  });

  it('compareDecisions orders deny > challenge > monitor > allow', () => {
    expect(compareDecisions('deny', 'allow')).toBeLessThan(0);
    expect(compareDecisions('challenge', 'deny')).toBeGreaterThan(0);
    expect(compareDecisions('monitor', 'challenge')).toBeGreaterThan(0);
    expect(compareDecisions('allow', 'monitor')).toBeGreaterThan(0);
  });

  it('compareDecisions accepts DecisionKind', () => {
    expectTypeOf(compareDecisions).parameter(0).toEqualTypeOf<DecisionKind>();
    expectTypeOf(compareDecisions).parameter(1).toEqualTypeOf<DecisionKind>();
    expectTypeOf(compareDecisions).returns.toEqualTypeOf<number>();
  });

  it('DecisionKind is the union of literal kinds', () => {
    expectTypeOf<DecisionKind>().toEqualTypeOf<
      'allow' | 'monitor' | 'rate_limit' | 'challenge' | 'deny'
    >();
  });

  it('helpers return narrow types', () => {
    expectTypeOf(allow()).toEqualTypeOf<Decision>();
    expectTypeOf(deny('x')).toEqualTypeOf<Decision>();
    expectTypeOf(challenge('x', 'mfa')).toEqualTypeOf<Decision>();
    expectTypeOf(monitor('x')).toEqualTypeOf<Decision>();
  });

  it('isDecision narrows PolicyResult', () => {
    const r1: PolicyResult = { kind: 'allow' };
    const r2: PolicyResult = { kind: 'noop' };
    if (isDecision(r1)) {
      expectTypeOf(r1).toMatchTypeOf<Decision>();
    } else {
      throw new Error('r1 should be a decision');
    }
    if (!isDecision(r2)) {
      expectTypeOf(r2).toEqualTypeOf<{ readonly kind: 'noop' }>();
    } else {
      throw new Error('r2 should be noop');
    }
  });
});

describe('Intent — type-level invariants', () => {
  it('IntentOptions defaults are partial', () => {
    const empty: IntentOptions = {};
    expectTypeOf(empty).toMatchTypeOf<IntentOptions>();
  });

  it('Intent is the normalized form (every field required)', () => {
    expectTypeOf<Intent>().toHaveProperty('key');
    expectTypeOf<Intent>().toHaveProperty('auth');
    expectTypeOf<Intent>().toHaveProperty('sensitivity');
    expectTypeOf<Intent>().toHaveProperty('mutation');
    expectTypeOf<Intent>().toHaveProperty('velocity');
    expectTypeOf<Intent>().toHaveProperty('anomaly');
    expectTypeOf<Intent>().toHaveProperty('authFreshness');
    expectTypeOf<Intent>().toHaveProperty('quotas');
    expectTypeOf<Intent>().toHaveProperty('tags');
  });

  it('Intent exposes no redundant `action` or self-referencing `intent` fields', () => {
    expectTypeOf<Intent>().not.toHaveProperty('action');
    expectTypeOf<Intent>().not.toHaveProperty('intent');
  });

  it('ContextEnricher / SignalProvider / Policy adapter contracts are framework-agnostic', () => {
    // Compile-only: enforce that all providers take only domain types
    const _e: ContextEnricher = {} as ContextEnricher;
    const _s: SignalProvider = {} as SignalProvider;
    const _p: Policy = {} as Policy;
    const _a: PolicyAdapter = {} as PolicyAdapter;
    expectTypeOf(_e.name).toEqualTypeOf<string>();
    expectTypeOf(_s.name).toEqualTypeOf<string>();
    expectTypeOf(_p.name).toEqualTypeOf<string>();
    expectTypeOf(_a.name).toEqualTypeOf<string>();
  });
});

describe('Context — immutability contracts', () => {
  it('IntentContext is Readonly at every level', () => {
    expectTypeOf<IntentContext['requestId']>().toEqualTypeOf<string>();
    expectTypeOf<IntentContext['method']>().toEqualTypeOf<string>();
    expectTypeOf<IntentContext['headers']>().toMatchTypeOf<Readonly<Record<string, string>>>();
    expectTypeOf<IntentContext['params']>().toMatchTypeOf<Readonly<Record<string, string>>>();
    expectTypeOf<IntentContext['extras']>().toMatchTypeOf<Readonly<Record<string, unknown>>>();
  });

  it('RequestSnapshot has no redundant `intentKey` field', () => {
    expectTypeOf<RequestSnapshot>().toHaveProperty('requestId');
    expectTypeOf<RequestSnapshot>().toHaveProperty('action');
    expectTypeOf<RequestSnapshot>().toHaveProperty('actorSubject');
    expectTypeOf<RequestSnapshot>().toHaveProperty('startedAt');
    expectTypeOf<RequestSnapshot>().not.toHaveProperty('intentKey');
  });
});

describe('Risk — signal shape', () => {
  it('RiskSignal kind discriminates value type', () => {
    const n: RiskSignal<'numeric', number> = {
      name: 'velocity.ip',
      kind: 'numeric',
      value: 0.42,
      confidence: 0.9,
      source: 'velocity',
      computedAt: 0,
      ttlMs: 60_000,
    };
    const c: RiskSignal<'categorical', string> = {
      name: 'device.trust',
      kind: 'categorical',
      value: 'trusted',
      confidence: 0.95,
      source: 'device',
      computedAt: 0,
      ttlMs: 0,
    };
    expectTypeOf(n.value).toEqualTypeOf<number>();
    expectTypeOf(c.value).toEqualTypeOf<string>();
  });

  it('Risk.aggregationHash is a string', () => {
    expectTypeOf<Risk['aggregationHash']>().toEqualTypeOf<string>();
  });
});
