import { describe, it, expect } from 'vitest';

import { validateIntentOptions, validateWindowSpec, isIntentOptions } from './validate.js';
import { defineIntent } from '../intent/builder.js';
import { IntentValidationError } from '../errors.js';
import { freezeContext } from './context.js';
import { hashContext, hashDecision, hashRisk } from './hash.js';
import { allow, deny, challenge, monitor } from '../decision/helpers.js';
import { compareDecisions } from './decision.js';

describe('validateWindowSpec', () => {
  it('accepts valid window specs', () => {
    expect(validateWindowSpec({ amount: 30, unit: 's' }, 'w')).toEqual([]);
    expect(validateWindowSpec({ amount: 1, unit: 'd' }, 'w')).toEqual([]);
  });

  it('rejects non-objects, non-positive numbers, and bad units', () => {
    expect(validateWindowSpec(null, 'w').length).toBeGreaterThan(0);
    expect(validateWindowSpec({ amount: 0, unit: 's' }, 'w')).toHaveLength(1);
    expect(validateWindowSpec({ amount: -1, unit: 's' }, 'w')).toHaveLength(1);
    expect(validateWindowSpec({ amount: 1, unit: 'year' as never }, 'w')).toHaveLength(1);
    expect(validateWindowSpec({ amount: '1', unit: 's' }, 'w')).toHaveLength(1);
  });
});

describe('validateIntentOptions', () => {
  it('accepts an empty object', () => {
    expect(validateIntentOptions({})).toEqual([]);
  });

  it('accepts a fully-populated valid object', () => {
    expect(
      validateIntentOptions({
        auth: 'mfa-required',
        sensitivity: 'critical',
        mutation: 'destructive',
        velocity: { window: { amount: 1, unit: 'm' }, max: 10, per: 'subject' },
        anomaly: { threshold: 0.7, window: { amount: 5, unit: 'm' } },
        authFreshness: { maxAgeMs: 60_000, requiredMethods: ['mfa', 'passkey'] },
        quotas: [{ per: 'subject', window: { amount: 1, unit: 'd' }, max: 3 }],
        tags: ['pii', 'export'],
      }),
    ).toEqual([]);
  });

  it('rejects invalid auth/sensitivity/mutation', () => {
    expect(validateIntentOptions({ auth: 'who' })[0].path).toBe('auth');
    expect(validateIntentOptions({ sensitivity: 'top-secret' })[0].path).toBe('sensitivity');
    expect(validateIntentOptions({ mutation: 'launch' })[0].path).toBe('mutation');
  });

  it('rejects malformed velocity and anomaly', () => {
    expect(validateIntentOptions({ velocity: 'fast' })[0].path).toBe('velocity');
    const v = validateIntentOptions({
      velocity: { window: { amount: 0, unit: 's' }, max: '10', per: 'me' },
    });
    expect(v.find((i) => i.path === 'velocity.window.amount')).toBeTruthy();
    expect(v.find((i) => i.path === 'velocity.max')).toBeTruthy();
    expect(v.find((i) => i.path === 'velocity.per')).toBeTruthy();
  });

  it('rejects malformed quotas array', () => {
    expect(validateIntentOptions({ quotas: 'nope' })[0].path).toBe('quotas');
    const q = validateIntentOptions({
      quotas: [{ per: 'team', window: { amount: 1, unit: 's' }, max: -1 }],
    });
    expect(q.find((i) => i.path === 'quotas[0].per')).toBeTruthy();
    expect(q.find((i) => i.path === 'quotas[0].max')).toBeTruthy();
  });

  it('rejects non-string tags', () => {
    expect(validateIntentOptions({ tags: ['ok', 42] })[0].path).toBe('tags');
  });

  it('isIntentOptions matches validateIntentOptions', () => {
    expect(isIntentOptions({})).toBe(true);
    expect(isIntentOptions({ auth: 'who' })).toBe(false);
  });
});

describe('defineIntent — builder + validation integration', () => {
  it('normalizes partial options with safe defaults', () => {
    const intent = defineIntent('list', {});
    expect(intent).toMatchObject({
      key: 'list',
      auth: 'required',
      sensitivity: 'internal',
      mutation: 'read',
      velocity: null,
      anomaly: null,
      authFreshness: null,
      quotas: [],
      tags: [],
    });
  });

  it('throws IntentValidationError on invalid input', () => {
    expect(() => defineIntent('x', { auth: 'who' as never })).toThrow(IntentValidationError);
  });

  it('throws with a useful message and populated issues', () => {
    try {
      defineIntent('x', { velocity: { window: { amount: 0, unit: 's' }, max: '10', per: 'team' } });
      throw new Error('should not reach');
    } catch (e) {
      expect(e).toBeInstanceOf(IntentValidationError);
      const err = e as IntentValidationError;
      expect(err.issues.length).toBeGreaterThanOrEqual(3);
      expect(err.message).toContain('velocity.window.amount');
    }
  });
});

describe('Decision helpers — runtime invariants', () => {
  it('allow() has no extras', () => {
    expect(allow()).toEqual({ kind: 'allow' });
  });

  it('monitor(reason) carries reason', () => {
    expect(monitor('new-device')).toEqual({ kind: 'monitor', reason: 'new-device' });
  });

  it('challenge(reason, kind, ttl) carries ttl or null', () => {
    expect(challenge('r', 'mfa', 60_000)).toEqual({
      kind: 'challenge',
      reason: 'r',
      challenge: 'mfa',
      ttlMs: 60_000,
    });
    expect(challenge('r', 'captcha')).toEqual({
      kind: 'challenge',
      reason: 'r',
      challenge: 'captcha',
      ttlMs: null,
    });
  });

  it('deny(reason, status=403) is default', () => {
    expect(deny('x')).toEqual({ kind: 'deny', reason: 'x', status: 403 });
    expect(deny('x', 429)).toEqual({ kind: 'deny', reason: 'x', status: 429 });
  });
});

describe('compareDecisions — ordering', () => {
  it('deny < challenge < monitor < allow', () => {
    expect(compareDecisions('deny', 'allow')).toBeLessThan(0);
    expect(compareDecisions('challenge', 'allow')).toBeLessThan(0);
    expect(compareDecisions('monitor', 'allow')).toBeLessThan(0);
    expect(compareDecisions('deny', 'challenge')).toBeLessThan(0);
    expect(compareDecisions('deny', 'monitor')).toBeLessThan(0);
    expect(compareDecisions('challenge', 'monitor')).toBeLessThan(0);
  });
});

describe('freezeContext — deep immutability', () => {
  it('freezes top-level and nested arrays/objects', () => {
    const actor = {
      subject: 'u1',
      authenticated: true,
      authMethod: 'oauth2' as const,
      authRequirement: 'required' as const,
      roles: ['user'],
      scopes: ['read'],
      claims: { x: 1 },
      authenticatedAt: 0,
    };
    const intent = defineIntent('i', {});
    const ctx = freezeContext({
      requestId: 'r1',
      intent,
      actor,
      method: 'GET',
      path: '/x',
      ip: '127.0.0.1',
      headers: { h: 'v' },
      params: {},
      query: {},
      bodyShapeHash: null,
      receivedAt: 0,
      extras: {},
    });
    expect(Object.isFrozen(ctx)).toBe(true);
    expect(Object.isFrozen(ctx.headers)).toBe(true);
    expect(Object.isFrozen(ctx.actor.roles)).toBe(true);
    expect(Object.isFrozen(ctx.actor.claims)).toBe(true);
  });
});

describe('hash — determinism', () => {
  it('hashDecision is deterministic and stable-length', () => {
    const a = hashDecision(deny('r', 403));
    const b = hashDecision(deny('r', 403));
    expect(a).toBe(b);
    expect(a).toHaveLength(16);
  });

  it('hashContext and hashRisk are stable for identical inputs', () => {
    const intent = defineIntent('i', {});
    const ctx = freezeContext({
      requestId: 'r1',
      intent,
      actor: {
        subject: null,
        authenticated: false,
        authMethod: null,
        authRequirement: 'anonymous',
        roles: [],
        scopes: [],
        claims: {},
        authenticatedAt: null,
      },
      method: 'GET',
      path: '/x',
      ip: null,
      headers: {},
      params: {},
      query: {},
      bodyShapeHash: null,
      receivedAt: 0,
      extras: {},
    });
    expect(hashContext(ctx)).toBe(hashContext(ctx));
    expect(hashRisk({ signals: [], missing: [], aggregationHash: '', computedAt: 0 })).toHaveLength(
      16,
    );
  });
});
