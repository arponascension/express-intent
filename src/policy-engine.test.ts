import { describe, it, expect } from 'vitest';
import fc from 'fast-check';

import {
  definePolicy,
  validatePolicyDefinition,
  compilePolicy,
  toBuiltPolicy,
  evaluatePolicies,
  sortPoliciesById,
  PolicyValidationError,
  pAllow,
  pDeny,
  pMonitor,
  pChallenge,
  pRateLimit,
  NOOP,
} from './policy-engine.js';
import type { Condition, EngineInput, PolicyDefinition } from './policy-engine.js';
import { defineIntent } from './intent/builder.js';
import { freezeContext } from './domain/context.js';
import type { Actor, IntentContext } from './types.js';

const NOW = 1_700_000_000_000;

function makeActor(partial: Partial<Actor> = {}): Actor {
  return {
    subject: 'u-1',
    authenticated: true,
    authMethod: 'oauth2',
    authRequirement: 'required',
    roles: ['user'],
    scopes: ['read'],
    claims: {},
    authenticatedAt: NOW,
    ...partial,
  };
}

function makeContext(partial: Partial<IntentContext> = {}): IntentContext {
  return freezeContext(
    {
      requestId: 'req-1',
      intent: defineIntent('payment.create', {}),
      actor: makeActor(),
      method: 'POST',
      path: '/payments',
      ip: '10.0.0.1',
      headers: { 'x-tenant': 'acme' },
      params: {},
      query: {},
      bodyShapeHash: null,
      receivedAt: NOW,
      extras: {},
      ...partial,
    },
    undefined,
  );
}

function makeEngineInput(partial: Partial<EngineInput> = {}): EngineInput {
  return {
    intent: defineIntent('payment.create', { tags: ['pii'] }),
    context: makeContext(),
    actor: makeActor(),
    score: 30,
    severity: 'medium',
    signals: new Map([['geo.country', 'US']]),
    missingSignals: new Set<string>(),
    ...partial,
  };
}

const def = (overrides: Partial<PolicyDefinition> = {}): PolicyDefinition =>
  definePolicy({
    id: 'p-default',
    version: 1,
    when: { kind: 'action', pattern: 'payment.*' },
    then: { decision: { kind: 'allow' } },
    ...overrides,
  });

describe('validatePolicyDefinition — happy path', () => {
  it('accepts a minimal definition', () => {
    const d = definePolicy({
      id: 'min',
      version: 1,
      when: { kind: 'authenticated', value: true },
      then: { decision: { kind: 'allow' } },
    });
    expect(d.id).toBe('min');
    expect(d.version).toBe(1);
    expect(Object.isFrozen(d)).toBe(true);
  });

  it('accepts a definition with a description', () => {
    const d = definePolicy({
      id: 'described',
      version: 2,
      description: 'blocks pii exports from anonymous',
      when: { kind: 'tagged', tag: 'pii' },
      then: { decision: { kind: 'deny', reason: 'no', status: 403 } },
    });
    expect(d.description).toBe('blocks pii exports from anonymous');
  });
});

describe('validatePolicyDefinition — error reporting', () => {
  it('throws on non-object input', () => {
    expect(() => validatePolicyDefinition(null)).toThrow(PolicyValidationError);
    expect(() => validatePolicyDefinition('x')).toThrow(PolicyValidationError);
  });

  it('rejects empty/missing id', () => {
    expect(() =>
      definePolicy({
        id: '',
        version: 1,
        when: { kind: 'action', pattern: 'x' },
        then: { decision: { kind: 'allow' } },
      }),
    ).toThrow(PolicyValidationError);
    expect(() =>
      definePolicy({
        version: 1,
        when: { kind: 'action', pattern: 'x' },
        then: { decision: { kind: 'allow' } },
      } as never),
    ).toThrow(PolicyValidationError);
  });

  it('rejects negative or non-integer version', () => {
    expect(() =>
      definePolicy({
        id: 'x',
        version: -1,
        when: { kind: 'action', pattern: 'x' },
        then: { decision: { kind: 'allow' } },
      }),
    ).toThrow(PolicyValidationError);
    expect(() =>
      definePolicy({
        id: 'x',
        version: 1.5,
        when: { kind: 'action', pattern: 'x' },
        then: { decision: { kind: 'allow' } },
      }),
    ).toThrow(PolicyValidationError);
  });

  it('rejects unknown condition kind', () => {
    expect(() =>
      definePolicy({
        id: 'x',
        version: 1,
        when: { kind: 'whatever' as never, foo: 1 },
        then: { decision: { kind: 'allow' } },
      }),
    ).toThrow(/unknown condition kind/);
  });

  it('rejects invalid glob / regex / pattern', () => {
    expect(() =>
      definePolicy({
        id: 'x',
        version: 1,
        when: { kind: 'action', pattern: '' },
        then: { decision: { kind: 'allow' } },
      }),
    ).toThrow(/non-empty string/);
    expect(() =>
      definePolicy({
        id: 'x',
        version: 1,
        when: { kind: 'pathMatches', pattern: '[unclosed' },
        then: { decision: { kind: 'allow' } },
      }),
    ).toThrow(/invalid regex/);
  });

  it('rejects out-of-range risk thresholds', () => {
    expect(() =>
      definePolicy({
        id: 'x',
        version: 1,
        when: { kind: 'riskScoreAtLeast', value: 200 },
        then: { decision: { kind: 'allow' } },
      }),
    ).toThrow(/\[0, 100\]/);
    expect(() =>
      definePolicy({
        id: 'x',
        version: 1,
        when: { kind: 'riskScoreBelow', value: -1 },
        then: { decision: { kind: 'allow' } },
      }),
    ).toThrow(/\[0, 100\]/);
  });

  it('rejects unknown / out-of-range severity', () => {
    expect(() =>
      definePolicy({
        id: 'x',
        version: 1,
        when: { kind: 'riskAtLeast', severity: 'catastrophic' as never },
        then: { decision: { kind: 'allow' } },
      }),
    ).toThrow(/severity/);
  });

  it('rejects empty and/or arrays', () => {
    expect(() =>
      definePolicy({
        id: 'x',
        version: 1,
        when: { kind: 'and', all: [] },
        then: { decision: { kind: 'allow' } },
      }),
    ).toThrow(/non-empty/);
    expect(() =>
      definePolicy({
        id: 'x',
        version: 1,
        when: { kind: 'or', any: [] },
        then: { decision: { kind: 'allow' } },
      }),
    ).toThrow(/non-empty/);
  });

  it('rejects malformed decision effect', () => {
    expect(() =>
      definePolicy({
        id: 'x',
        version: 1,
        when: { kind: 'action', pattern: 'x' },
        then: { decision: { kind: 'deny', reason: 'r' } },
      }),
    ).toThrow(/status/);
    expect(() =>
      definePolicy({
        id: 'x',
        version: 1,
        when: { kind: 'action', pattern: 'x' },
        then: { decision: { kind: 'deny', reason: 5 as never, status: 403 } },
      }),
    ).toThrow(/reason/);
  });

  it('rejects non-string description', () => {
    expect(() =>
      definePolicy({
        id: 'x',
        version: 1,
        description: 42 as never,
        when: { kind: 'action', pattern: 'x' },
        then: { decision: { kind: 'allow' } },
      }),
    ).toThrow(/description/);
  });

  it('error carries structured issues', () => {
    try {
      definePolicy({
        id: '',
        version: -1,
        when: { kind: 'unknown' as never },
        then: { decision: { kind: 'allow' } },
      });
      throw new Error('should not reach');
    } catch (e) {
      expect(e).toBeInstanceOf(PolicyValidationError);
      const err = e as PolicyValidationError;
      expect(err.issues.length).toBeGreaterThanOrEqual(3);
      expect(err.message).toContain('id');
      expect(err.message).toContain('version');
    }
  });
});

describe('globToRegex — action matching', () => {
  const cases: Array<[string, string, boolean]> = [
    ['payment.*', 'payment.create', true],
    ['payment.*', 'payment.refund', true],
    ['payment.*', 'payments.create', false],
    ['payment.**', 'payment.create.user', true],
    ['**', 'a.b.c.d', true],
    ['user.delete', 'user.delete', true],
    ['user.delete', 'user.del', false],
    ['payment.*.confirm', 'payment.x.confirm', true],
    ['payment.*.confirm', 'payment.confirm', false],
    ['payment*', 'payments', true],
    ['payment*', 'payment', true],
    ['payment*', 'payments.create', false],
  ];
  for (const [pattern, input, expected] of cases) {
    it(`${pattern} ${expected ? 'matches' : 'does not match'} ${input}`, () => {
      const d = def({ when: { kind: 'action', pattern } });
      const compiled = compilePolicy(d);
      const inp = makeEngineInput({ intent: defineIntent(input, {}) });
      expect(compiled.evaluate(inp)).toBe(expected);
    });
  }
});

describe('every condition kind', () => {
  const intent = defineIntent('payment.create', { tags: ['pii', 'export'] });
  const actor = makeActor({
    subject: 'u-1',
    authMethod: 'oauth2',
    roles: ['admin'],
    scopes: ['write'],
  });
  const ctx = makeContext({
    method: 'POST',
    path: '/payments',
    ip: '10.0.0.1',
    headers: { 'x-tenant': 'acme' },
  });

  const cases: Array<[string, Condition, boolean]> = [
    ['action glob', { kind: 'action', pattern: 'payment.*' }, true],
    ['tagged', { kind: 'tagged', tag: 'pii' }, true],
    ['tagged miss', { kind: 'tagged', tag: 'audit' }, false],
    ['sensitivity', { kind: 'sensitivity', value: 'internal' }, true],
    ['mutation', { kind: 'mutation', value: 'read' }, true],
    ['authRequirement', { kind: 'authRequirement', value: 'required' }, true],
    ['authenticated true', { kind: 'authenticated', value: true }, true],
    ['authenticated false', { kind: 'authenticated', value: false }, false],
    ['actorSubject equals', { kind: 'actorSubject', equals: 'u-1' }, true],
    ['actorSubject null', { kind: 'actorSubject', equals: null }, false],
    ['actorRole present', { kind: 'actorRole', role: 'admin' }, true],
    ['actorRole missing', { kind: 'actorRole', role: 'editor' }, false],
    ['actorScope', { kind: 'actorScope', scope: 'write' }, true],
    ['actorField subject', { kind: 'actorField', field: 'subject', equals: 'u-1' }, true],
    ['actorField authMethod', { kind: 'actorField', field: 'authMethod', equals: 'oauth2' }, true],
    ['actorAuthMethod', { kind: 'actorAuthMethod', value: 'oauth2' }, true],
    ['actorAuthMethod null', { kind: 'actorAuthMethod', value: null }, false],
    ['riskScoreAtLeast pass', { kind: 'riskScoreAtLeast', value: 30 }, true],
    ['riskScoreAtLeast fail', { kind: 'riskScoreAtLeast', value: 31 }, false],
    ['riskScoreBelow pass', { kind: 'riskScoreBelow', value: 31 }, true],
    ['riskScoreBelow fail', { kind: 'riskScoreBelow', value: 30 }, false],
    ['riskAtLeast medium', { kind: 'riskAtLeast', severity: 'medium' }, true],
    ['riskBelow medium', { kind: 'riskBelow', severity: 'medium' }, false],
    ['signalExists', { kind: 'signalExists', name: 'geo.country' }, true],
    ['signalMissing', { kind: 'signalMissing', name: 'no-such' }, true],
    ['signalValue match', { kind: 'signalValue', name: 'geo.country', equals: 'US' }, true],
    ['signalValue miss', { kind: 'signalValue', name: 'geo.country', equals: 'CA' }, false],
    ['pathMatches', { kind: 'pathMatches', pattern: '^/payments$' }, true],
    ['pathMatches miss', { kind: 'pathMatches', pattern: '^/users$' }, false],
    ['ipMatches', { kind: 'ipMatches', pattern: '^10\\.' }, true],
    ['ipMatches miss', { kind: 'ipMatches', pattern: '^8\\.' }, false],
    ['methodMatches', { kind: 'methodMatches', method: 'POST' }, true],
    ['methodMatches case-insensitive', { kind: 'methodMatches', method: 'post' }, true],
    ['headerEquals', { kind: 'headerEquals', name: 'x-tenant', value: 'acme' }, true],
    ['headerEquals miss', { kind: 'headerEquals', name: 'x-tenant', value: 'other' }, false],
  ];

  for (const [name, cond, expected] of cases) {
    it(name, () => {
      const d = def({ when: cond });
      const c = compilePolicy(d);
      const inp: EngineInput = {
        intent,
        context: ctx,
        actor,
        score: 30,
        severity: 'medium',
        signals: new Map([['geo.country', 'US']]),
        missingSignals: new Set<string>(['no-such']),
      };
      expect(c.evaluate(inp)).toBe(expected);
    });
  }
});

describe('combinators — AND / OR / NOT', () => {
  const inp = makeEngineInput();

  it('AND requires all', () => {
    const d = def({
      when: {
        kind: 'and',
        all: [
          { kind: 'action', pattern: 'payment.*' },
          { kind: 'authenticated', value: true },
        ],
      },
    });
    const c = compilePolicy(d);
    expect(c.evaluate(inp)).toBe(true);
  });

  it('AND returns false when any sub-condition fails', () => {
    const d = def({
      when: {
        kind: 'and',
        all: [
          { kind: 'action', pattern: 'payment.*' },
          { kind: 'authenticated', value: false },
        ],
      },
    });
    expect(compilePolicy(d).evaluate(inp)).toBe(false);
  });

  it('OR returns true when any sub-condition matches', () => {
    const d = def({
      when: {
        kind: 'or',
        any: [
          { kind: 'action', pattern: 'nope.*' },
          { kind: 'authenticated', value: true },
        ],
      },
    });
    expect(compilePolicy(d).evaluate(inp)).toBe(true);
  });

  it('OR returns false when no sub-condition matches', () => {
    const d = def({
      when: {
        kind: 'or',
        any: [
          { kind: 'action', pattern: 'nope.*' },
          { kind: 'authenticated', value: false },
        ],
      },
    });
    expect(compilePolicy(d).evaluate(inp)).toBe(false);
  });

  it('NOT inverts', () => {
    const d = def({ when: { kind: 'not', inner: { kind: 'authenticated', value: false } } });
    expect(compilePolicy(d).evaluate(inp)).toBe(true);
  });

  it('nested combinators', () => {
    const adminActor = makeActor({ roles: ['admin'] });
    const d = def({
      when: {
        kind: 'and',
        all: [
          { kind: 'action', pattern: 'payment.*' },
          {
            kind: 'or',
            any: [
              { kind: 'actorRole', role: 'admin' },
              { kind: 'actorRole', role: 'super' },
            ],
          },
          { kind: 'not', inner: { kind: 'mutation', value: 'destructive' } },
        ],
      },
    });
    expect(compilePolicy(d).evaluate(makeEngineInput({ actor: adminActor }))).toBe(true);
  });

  it('validation rejects AND with empty array', () => {
    expect(() => def({ when: { kind: 'and', all: [] } })).toThrow(/non-empty/);
  });

  it('validation rejects OR with empty array', () => {
    expect(() => def({ when: { kind: 'or', any: [] } })).toThrow(/non-empty/);
  });

  it('validation rejects NOT with missing inner', () => {
    expect(() => def({ when: { kind: 'not', inner: null as never } })).toThrow();
  });
});

describe('decision emission', () => {
  it('returns decision when matched', () => {
    const d = def({ then: { decision: pDeny('blocked', 403) } });
    const bp = toBuiltPolicy(d);
    const out = bp.evaluate(makeEngineInput());
    expect(out).toEqual({ decision: { kind: 'deny', reason: 'blocked', status: 403 } });
  });

  it('returns NOOP when condition does not match', () => {
    const d = def({
      when: { kind: 'action', pattern: 'user.delete' },
      then: { decision: pDeny('x', 403) },
    });
    const bp = toBuiltPolicy(d);
    expect(bp.evaluate(makeEngineInput())).toBe(NOOP);
  });

  it('pAllow / pDeny / pMonitor / pChallenge / pRateLimit builders produce valid decisions', () => {
    expect(pAllow()).toEqual({ kind: 'allow' });
    expect(pMonitor('watched')).toEqual({ kind: 'monitor', reason: 'watched' });
    expect(pChallenge('r', 'mfa', 1000)).toEqual({
      kind: 'challenge',
      reason: 'r',
      challenge: 'mfa',
      ttlMs: 1000,
    });
    expect(
      pRateLimit({ reason: 'slow', limit: 10, remaining: 0, retryAfterMs: 5000, scope: 'ip' }),
    ).toEqual({
      kind: 'rate_limit',
      reason: 'slow',
      limit: 10,
      remaining: 0,
      retryAfterMs: 5000,
      scope: 'ip',
    });
  });
});

describe('evaluatePolicies — engine', () => {
  it('returns default decision when no policies match', () => {
    const p1 = toBuiltPolicy(
      def({
        id: 'p1',
        when: { kind: 'action', pattern: 'nope.*' },
        then: { decision: pDeny('no', 403) },
      }),
    );
    const out = evaluatePolicies(makeEngineInput(), { policies: [p1], defaultDecision: pAllow() });
    expect(out.decision).toEqual({ kind: 'allow' });
    expect(out.matchedPolicyIds).toEqual([]);
  });

  it('returns matched decision', () => {
    const p1 = toBuiltPolicy(
      def({
        id: 'p1',
        when: { kind: 'action', pattern: 'payment.*' },
        then: { decision: pMonitor('soft') },
      }),
    );
    const out = evaluatePolicies(makeEngineInput(), { policies: [p1] });
    expect(out.decision).toEqual({ kind: 'monitor', reason: 'soft' });
    expect(out.matchedPolicyIds).toEqual(['p1']);
  });

  it('merges multiple matched policies by precedence (deny wins)', () => {
    const allowPol = toBuiltPolicy(
      def({
        id: 'a',
        when: { kind: 'action', pattern: 'payment.*' },
        then: { decision: pAllow() },
      }),
    );
    const monitorPol = toBuiltPolicy(
      def({
        id: 'm',
        when: { kind: 'action', pattern: 'payment.*' },
        then: { decision: pMonitor('m') },
      }),
    );
    const denyPol = toBuiltPolicy(
      def({
        id: 'd',
        when: { kind: 'action', pattern: 'payment.*' },
        then: { decision: pDeny('hard', 403) },
      }),
    );
    const out = evaluatePolicies(makeEngineInput(), { policies: [allowPol, monitorPol, denyPol] });
    expect(out.decision).toEqual({ kind: 'deny', reason: 'hard', status: 403 });
    expect([...out.matchedPolicyIds].sort()).toEqual(['a', 'd', 'm']);
  });

  it('trace records matched + duration per policy', () => {
    const p1 = toBuiltPolicy(
      def({
        id: 'p1',
        when: { kind: 'action', pattern: 'payment.*' },
        then: { decision: pAllow() },
      }),
    );
    const p2 = toBuiltPolicy(
      def({
        id: 'p2',
        when: { kind: 'action', pattern: 'nope.*' },
        then: { decision: pDeny('x', 403) },
      }),
    );
    const out = evaluatePolicies(makeEngineInput(), { policies: [p1, p2] });
    expect(out.trace).toHaveLength(2);
    expect(out.trace[0]?.matched).toBe(true);
    expect(out.trace[1]?.matched).toBe(false);
    expect(typeof out.trace[0]?.durationMs).toBe('number');
  });

  it('engine is deterministic (sorted by id) regardless of input order', () => {
    const policies = ['zeta', 'alpha', 'mu'].map((id) =>
      toBuiltPolicy(
        def({
          id,
          when: { kind: 'action', pattern: 'payment.*' },
          then: { decision: pMonitor(id) },
        }),
      ),
    );
    const out1 = evaluatePolicies(makeEngineInput(), { policies });
    const out2 = evaluatePolicies(makeEngineInput(), { policies: [...policies].reverse() });
    expect(out1.matchedPolicyIds).toEqual(['alpha', 'mu', 'zeta']);
    expect(out1.matchedPolicyIds).toEqual(out2.matchedPolicyIds);
  });

  it('engine can be non-deterministic when deterministic=false', () => {
    const policies = ['zeta', 'alpha', 'mu'].map((id) =>
      toBuiltPolicy(
        def({
          id,
          when: { kind: 'action', pattern: 'payment.*' },
          then: { decision: pMonitor(id) },
        }),
      ),
    );
    const out = evaluatePolicies(makeEngineInput(), { policies, deterministic: false });
    expect(out.matchedPolicyIds).toEqual(['zeta', 'alpha', 'mu']);
  });
});

describe('sortPoliciesById', () => {
  it('sorts ascending', () => {
    const arr = [{ id: 'c' }, { id: 'a' }, { id: 'b' }];
    expect(sortPoliciesById(arr).map((x) => x.id)).toEqual(['a', 'b', 'c']);
  });
});

describe('framework-independence', () => {
  it('Policy contains no Express types in its public surface', () => {
    const d = def();
    const json = JSON.stringify(d);
    expect(json).not.toMatch(/express/i);
  });

  it('engine evaluate signature does not mention req/res', () => {
    const fn = evaluatePolicies.toString();
    expect(fn).not.toMatch(/\breq\b|\bres\b/);
  });
});

describe('property tests', () => {
  it('compile + evaluate is idempotent', () => {
    fc.assert(
      fc.property(fc.integer({ min: 0, max: 100 }), (score) => {
        const d = def({ when: { kind: 'riskScoreAtLeast', value: score } });
        const c = compilePolicy(d);
        const r1 = c.evaluate(makeEngineInput({ score }));
        const r2 = c.evaluate(makeEngineInput({ score }));
        expect(r1).toBe(r2);
      }),
      { numRuns: 50 },
    );
  });

  it('glob "x" matches exactly the action x', () => {
    fc.assert(
      fc.property(
        fc.string({ minLength: 1, maxLength: 12 }).filter((s) => /^[a-z][a-z0-9_]*$/.test(s)),
        (segment) => {
          const d = def({ when: { kind: 'action', pattern: segment } });
          expect(
            compilePolicy(d).evaluate(makeEngineInput({ intent: defineIntent(segment, {}) })),
          ).toBe(true);
          const other = `${segment}_other`;
          expect(
            compilePolicy(d).evaluate(makeEngineInput({ intent: defineIntent(other, {}) })),
          ).toBe(false);
        },
      ),
      { numRuns: 50 },
    );
  });
});
