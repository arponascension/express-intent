import { describe, it, expect } from 'vitest';
import fc from 'fast-check';

import { InMemoryRateLimiter, buildRateLimitKey } from './rate-limit-memory.js';
import type { RateLimitSpec, RateLimitResult } from './rate-limit-defs.js';
import type { Actor } from './types.js';

const ACTOR: Actor = {
  subject: 'u-1',
  authenticated: true,
  authMethod: 'oauth2',
  authRequirement: 'required',
  roles: [],
  scopes: [],
  claims: {},
  authenticatedAt: 0,
};

function makeActor(partial: Partial<Actor> = {}): Actor {
  return { ...ACTOR, ...partial };
}

describe('buildRateLimitKey — deterministic, normalized', () => {
  it('actor scope: namespaces by subject', () => {
    const k1 = buildRateLimitKey('actor', 'rl', makeActor({ subject: 'u-1' }), null, 'pay.create');
    const k2 = buildRateLimitKey('actor', 'rl', makeActor({ subject: 'U-1' }), null, 'pay.create');
    expect(k1).toBe(k2);
    expect(k1).toBe('rl:rl:actor:u-1');
  });

  it('actor scope falls back to "anonymous" for null subject', () => {
    expect(buildRateLimitKey('actor', 'rl', makeActor({ subject: null }), null, 'a.b')).toBe(
      'rl:rl:actor:anonymous',
    );
  });

  it('ip scope: lowercased', () => {
    expect(buildRateLimitKey('ip', 'rl', null, '10.0.0.1', 'a.b')).toBe('rl:rl:ip:10.0.0.1');
    expect(buildRateLimitKey('ip', 'rl', null, '10.0.0.1', 'a.b')).toBe(
      buildRateLimitKey('ip', 'rl', null, '10.0.0.1', 'a.b'),
    );
  });

  it('ip scope: null becomes "unknown"', () => {
    expect(buildRateLimitKey('ip', 'rl', null, null, 'a.b')).toBe('rl:rl:ip:unknown');
  });

  it('action scope: namespaces by action string', () => {
    expect(buildRateLimitKey('action', 'rl', null, null, 'payment.create')).toBe(
      'rl:rl:action:payment.create',
    );
  });

  it('custom scope: hashes the key for length-bounded namespace safety', () => {
    const k = buildRateLimitKey('custom', 'rl', null, null, 'a.b', 'hello world with spaces');
    expect(k).toMatch(/^rl:rl:custom:[a-f0-9]{16}$/);
  });

  it('custom scope: same key produces same hash', () => {
    const a = buildRateLimitKey('custom', 'rl', null, null, 'a.b', 'tenant:42:user:7');
    const b = buildRateLimitKey('custom', 'rl', null, null, 'a.b', 'tenant:42:user:7');
    expect(a).toBe(b);
  });

  it('custom scope: different keys produce different hashes', () => {
    const a = buildRateLimitKey('custom', 'rl', null, null, 'a.b', 'tenant:42');
    const b = buildRateLimitKey('custom', 'rl', null, null, 'a.b', 'tenant:43');
    expect(a).not.toBe(b);
  });

  it('custom scope: throws when no key provided', () => {
    expect(() => buildRateLimitKey('custom', 'rl', null, null, 'a.b')).toThrow(/custom/);
  });
});

describe('InMemoryRateLimiter — happy path', () => {
  it('allows requests up to max, denies at max+1', async () => {
    const rl = new InMemoryRateLimiter();
    const spec: RateLimitSpec = {
      namespace: 'payment',
      max: 3,
      windowMs: 60_000,
      scope: 'action',
      action: 'payment.create',
    };
    const r1 = await rl.consume(spec);
    const r2 = await rl.consume(spec);
    const r3 = await rl.consume(spec);
    const r4 = await rl.consume(spec);
    expect(r1.allowed).toBe(true);
    expect(r2.allowed).toBe(true);
    expect(r3.allowed).toBe(true);
    expect(r4.allowed).toBe(false);
    expect(r4.count).toBe(4);
    expect(r4.remaining).toBe(0);
    expect(r4.retryAfterMs).toBeGreaterThan(0);
    await rl.shutdown();
  });

  it('first hit: count=1, remaining=max-1, retryAfterMs=0', async () => {
    const rl = new InMemoryRateLimiter();
    const r = await rl.consume({
      namespace: 'n',
      max: 10,
      windowMs: 60_000,
      scope: 'ip',
      ip: '1.1.1.1',
      action: 'a',
    });
    expect(r.count).toBe(1);
    expect(r.remaining).toBe(9);
    expect(r.retryAfterMs).toBe(0);
    expect(r.allowed).toBe(true);
    await rl.shutdown();
  });

  it('window reset: after windowMs, counter resets', async () => {
    let now = 1_000;
    const clock = () => now;
    const rl = new InMemoryRateLimiter({ clock, sweepIntervalMs: 0 });
    const spec: RateLimitSpec = {
      namespace: 'n',
      max: 2,
      windowMs: 1_000,
      scope: 'ip',
      ip: '1.1.1.1',
      action: 'a',
    };
    const a1 = await rl.consume(spec);
    await rl.consume(spec);
    const a3 = await rl.consume(spec);
    expect(a3.allowed).toBe(false);
    now = 2_000;
    const a4 = await rl.consume(spec);
    expect(a4.allowed).toBe(true);
    expect(a4.count).toBe(1);
    expect(a1.resetAt).toBeLessThanOrEqual(a4.resetAt);
    await rl.shutdown();
  });

  it('different scopes produce different keys', async () => {
    const rl = new InMemoryRateLimiter();
    const ip: RateLimitSpec = {
      namespace: 'n',
      max: 1,
      windowMs: 60_000,
      scope: 'ip',
      ip: '1.1.1.1',
      action: 'a',
    };
    const act: RateLimitSpec = {
      namespace: 'n',
      max: 1,
      windowMs: 60_000,
      scope: 'action',
      ip: null,
      action: 'a.b',
    };
    const custom: RateLimitSpec = {
      namespace: 'n',
      max: 1,
      windowMs: 60_000,
      scope: 'custom',
      key: 'k',
      ip: null,
      action: 'a.b',
    };
    expect((await rl.consume(ip)).allowed).toBe(true);
    expect((await rl.consume(act)).allowed).toBe(true);
    expect((await rl.consume(custom)).allowed).toBe(true);
    expect((await rl.consume(ip)).allowed).toBe(false);
    expect((await rl.consume(act)).allowed).toBe(false);
    expect((await rl.consume(custom)).allowed).toBe(false);
    await rl.shutdown();
  });

  it('different actors share no counter', async () => {
    const rl = new InMemoryRateLimiter();
    const spec = (sub: string): RateLimitSpec => ({
      namespace: 'n',
      max: 1,
      windowMs: 60_000,
      scope: 'actor',
      actor: makeActor({ subject: sub }),
      action: 'a',
    });
    expect((await rl.consume(spec('u-1'))).allowed).toBe(true);
    expect((await rl.consume(spec('u-2'))).allowed).toBe(true);
    expect((await rl.consume(spec('u-1'))).allowed).toBe(false);
    await rl.shutdown();
  });

  it('different IPs share no counter', async () => {
    const rl = new InMemoryRateLimiter();
    const spec = (ip: string): RateLimitSpec => ({
      namespace: 'n',
      max: 1,
      windowMs: 60_000,
      scope: 'ip',
      ip,
      action: 'a',
    });
    expect((await rl.consume(spec('1.1.1.1'))).allowed).toBe(true);
    expect((await rl.consume(spec('2.2.2.2'))).allowed).toBe(true);
    await rl.shutdown();
  });

  it('different actions share no counter', async () => {
    const rl = new InMemoryRateLimiter();
    const spec = (action: string): RateLimitSpec => ({
      namespace: 'n',
      max: 1,
      windowMs: 60_000,
      scope: 'action',
      action,
      ip: null,
    });
    expect((await rl.consume(spec('a'))).allowed).toBe(true);
    expect((await rl.consume(spec('b'))).allowed).toBe(true);
    await rl.shutdown();
  });

  it('different namespaces share no counter', async () => {
    const rl = new InMemoryRateLimiter();
    const spec = (ns: string): RateLimitSpec => ({
      namespace: ns,
      max: 1,
      windowMs: 60_000,
      scope: 'ip',
      ip: '1.1.1.1',
      action: 'a',
    });
    expect((await rl.consume(spec('a'))).allowed).toBe(true);
    expect((await rl.consume(spec('b'))).allowed).toBe(true);
    await rl.shutdown();
  });
});

describe('InMemoryRateLimiter — boundary conditions', () => {
  it('at the max boundary (count == max) returns allowed=true', async () => {
    const rl = new InMemoryRateLimiter();
    const spec: RateLimitSpec = {
      namespace: 'n',
      max: 5,
      windowMs: 60_000,
      scope: 'ip',
      ip: '1.1.1.1',
      action: 'a',
    };
    let last;
    for (let i = 0; i < 4; i++) await rl.consume(spec);
    last = await rl.consume(spec);
    expect(last.allowed).toBe(true);
    expect(last.count).toBe(5);
    const next = await rl.consume(spec);
    expect(next.allowed).toBe(false);
    expect(next.count).toBe(6);
    await rl.shutdown();
  });

  it('max+1 returns allowed=false with retryAfterMs > 0', async () => {
    const rl = new InMemoryRateLimiter();
    const spec: RateLimitSpec = {
      namespace: 'n',
      max: 1,
      windowMs: 60_000,
      scope: 'ip',
      ip: '1.1.1.1',
      action: 'a',
    };
    await rl.consume(spec);
    const r = await rl.consume(spec);
    expect(r.allowed).toBe(false);
    expect(r.retryAfterMs).toBeGreaterThan(0);
    expect(r.retryAfterMs).toBeLessThanOrEqual(60_000);
    await rl.shutdown();
  });

  it('max=0 denies every request', async () => {
    const rl = new InMemoryRateLimiter();
    const spec: RateLimitSpec = {
      namespace: 'n',
      max: 0,
      windowMs: 60_000,
      scope: 'ip',
      ip: '1.1.1.1',
      action: 'a',
    };
    const r = await rl.consume(spec);
    expect(r.allowed).toBe(false);
    expect(r.count).toBe(1);
    await rl.shutdown();
  });

  it('reset() clears a key', async () => {
    const rl = new InMemoryRateLimiter();
    const spec: RateLimitSpec = {
      namespace: 'n',
      max: 1,
      windowMs: 60_000,
      scope: 'ip',
      ip: '1.1.1.1',
      action: 'a',
    };
    await rl.consume(spec);
    const r = await rl.consume(spec);
    expect(r.allowed).toBe(false);
    await rl.reset(r.key);
    const after = await rl.consume(spec);
    expect(after.allowed).toBe(true);
    expect(after.count).toBe(1);
    await rl.shutdown();
  });

  it('sweep() removes expired buckets', async () => {
    let now = 1_000;
    const rl = new InMemoryRateLimiter({ clock: () => now, sweepIntervalMs: 0 });
    await rl.consume({
      namespace: 'n',
      max: 1,
      windowMs: 100,
      scope: 'ip',
      ip: '1.1.1.1',
      action: 'a',
    });
    expect(rl.size()).toBe(1);
    now = 2_000;
    const removed = rl.sweep();
    expect(removed).toBe(1);
    expect(rl.size()).toBe(0);
    await rl.shutdown();
  });

  it('shutdown() clears all state and stops sweeper', async () => {
    const rl = new InMemoryRateLimiter({ sweepIntervalMs: 60_000 });
    await rl.consume({
      namespace: 'n',
      max: 1,
      windowMs: 60_000,
      scope: 'ip',
      ip: '1.1.1.1',
      action: 'a',
    });
    expect(rl.size()).toBe(1);
    await rl.shutdown();
    expect(rl.size()).toBe(0);
  });

  it('rejects invalid specs', async () => {
    const rl = new InMemoryRateLimiter({ sweepIntervalMs: 0 });
    await expect(
      rl.consume({ namespace: 'n', max: -1, windowMs: 60_000, scope: 'ip', ip: '1', action: 'a' }),
    ).rejects.toThrow(/max/);
    await expect(
      rl.consume({ namespace: 'n', max: 1, windowMs: 0, scope: 'ip', ip: '1', action: 'a' }),
    ).rejects.toThrow(/windowMs/);
    await expect(
      rl.consume({ namespace: 'n', max: 1, windowMs: 1000, scope: 'custom', action: 'a' }),
    ).rejects.toThrow(/custom/);
    await rl.shutdown();
  });

  it('sweep runs automatically with positive sweepIntervalMs', async () => {
    let now = 1_000;
    const rl = new InMemoryRateLimiter({ clock: () => now, sweepIntervalMs: 10 });
    await rl.consume({
      namespace: 'n',
      max: 1,
      windowMs: 100,
      scope: 'ip',
      ip: '1.1.1.1',
      action: 'a',
    });
    expect(rl.size()).toBe(1);
    await new Promise((r) => setTimeout(r, 50));
    expect(rl.size()).toBeLessThanOrEqual(1);
    await rl.shutdown();
  });
});

describe('InMemoryRateLimiter — concurrency', () => {
  it('serializes concurrent consume() calls into an accurate count', async () => {
    const rl = new InMemoryRateLimiter({ sweepIntervalMs: 0 });
    const spec: RateLimitSpec = {
      namespace: 'n',
      max: 1000,
      windowMs: 60_000,
      scope: 'ip',
      ip: '1.1.1.1',
      action: 'a',
    };
    const N = 250;
    const results = await Promise.all(Array.from({ length: N }, () => rl.consume(spec)));
    const allowedCount = results.filter((r) => r.allowed).length;
    const last = results[results.length - 1]!;
    expect(last.count).toBe(N);
    expect(allowedCount).toBe(N);
    await rl.shutdown();
  });

  it('exactly `max` requests are allowed under concurrent load', async () => {
    const rl = new InMemoryRateLimiter({ sweepIntervalMs: 0 });
    const spec: RateLimitSpec = {
      namespace: 'n',
      max: 10,
      windowMs: 60_000,
      scope: 'ip',
      ip: '1.1.1.1',
      action: 'a',
    };
    const N = 50;
    const results = await Promise.all(Array.from({ length: N }, () => rl.consume(spec)));
    const allowed = results.filter((r) => r.allowed).length;
    expect(allowed).toBe(10);
    const denied = results.filter((r) => !r.allowed);
    expect(denied.length).toBe(40);
    expect(denied.every((r) => r.retryAfterMs > 0)).toBe(true);
    await rl.shutdown();
  });

  it('different IPs in parallel produce independent counts', async () => {
    const rl = new InMemoryRateLimiter({ sweepIntervalMs: 0 });
    const ips = Array.from({ length: 20 }, (_, i) => `10.0.0.${i}`);
    const results = await Promise.all(
      ips.map((ip) =>
        rl.consume({ namespace: 'n', max: 5, windowMs: 60_000, scope: 'ip', ip, action: 'a' }),
      ),
    );
    expect(results.every((r) => r.allowed && r.count === 1)).toBe(true);
    await rl.shutdown();
  });
});

describe('InMemoryRateLimiter — property tests', () => {
  it('consume is monotonic in count for the same key', async () => {
    await fc.assert(
      fc.asyncProperty(fc.integer({ min: 1, max: 100 }), async (n) => {
        const rl = new InMemoryRateLimiter({ sweepIntervalMs: 0 });
        const spec: RateLimitSpec = {
          namespace: 'n',
          max: 1000,
          windowMs: 60_000,
          scope: 'ip',
          ip: '1.1.1.1',
          action: 'a',
        };
        const results: RateLimitResult[] = [];
        for (let i = 0; i < n; i++) results.push(await rl.consume(spec));
        const counts = results.map((r) => r.count);
        for (let i = 1; i < counts.length; i++) {
          expect(counts[i]).toBeGreaterThan(counts[i - 1]!);
        }
        await rl.shutdown();
      }),
      { numRuns: 20 },
    );
  });

  it('count never exceeds number of calls', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.integer({ min: 1, max: 50 }),
        fc.integer({ min: 1, max: 100 }),
        async (n, max) => {
          const rl = new InMemoryRateLimiter({ sweepIntervalMs: 0 });
          const spec: RateLimitSpec = {
            namespace: 'n',
            max,
            windowMs: 60_000,
            scope: 'ip',
            ip: '1.1.1.1',
            action: 'a',
          };
          let lastCount = 0;
          for (let i = 0; i < n; i++) {
            const r = await rl.consume(spec);
            expect(r.count).toBeGreaterThanOrEqual(lastCount);
            lastCount = r.count;
          }
          expect(lastCount).toBe(n);
          await rl.shutdown();
        },
      ),
      { numRuns: 20 },
    );
  });
});

describe('RateLimiter contract — shape sanity', () => {
  it('consume returns RateLimitResult with all fields', async () => {
    const rl = new InMemoryRateLimiter({ sweepIntervalMs: 0 });
    const r = await rl.consume({
      namespace: 'n',
      max: 10,
      windowMs: 60_000,
      scope: 'ip',
      ip: '1.1.1.1',
      action: 'a',
    });
    expect(r).toEqual({
      allowed: true,
      limit: 10,
      remaining: 9,
      count: 1,
      retryAfterMs: 0,
      resetAt: expect.any(Number),
      namespace: 'n',
      scope: 'ip',
      key: expect.stringMatching(/^rl:n:ip:1\.1\.1\.1$/),
    });
    await rl.shutdown();
  });
});
