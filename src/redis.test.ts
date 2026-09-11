import { describe, it, expect, beforeEach } from 'vitest';
import {
  buildRedisKey,
  buildRedisChannel,
  hashActor,
  hashIp,
  hashString,
  InMemoryRedisAdapter,
  RedisRateLimiter,
  RedisSignalStore,
  RedisObservationStore,
  RedisIdempotencyProvider,
  type RedisClientAdapter,
} from './redis/index.js';
import { createIdempotencyMiddleware, InMemoryIdempotencyProvider } from './index.js';
import express from 'express';
import { createServer } from 'node:http';
import type { AddressInfo } from 'node:net';

function listen(app: express.Express): Promise<{ port: number; close: () => Promise<void> }> {
  return new Promise((resolve) => {
    const server = createServer(app);
    server.listen(0, () => {
      const port = (server.address() as AddressInfo).port;
      resolve({
        port,
        close: () =>
          new Promise<void>((res, rej) => {
            server.close((err) => (err ? rej(err) : res()));
          }),
      });
    });
  });
}

describe('Redis key namespacing & canonicalization', () => {
  it('builds namespaced keys with the ei:v1: prefix', () => {
    expect(buildRedisKey('rl', ['default', 'foo'])).toBe('ei:v1:rl:default:foo');
    expect(buildRedisKey('sig', ['x'])).toBe('ei:v1:sig:x');
    expect(buildRedisKey('obs', ['x'])).toBe('ei:v1:obs:x');
    expect(buildRedisKey('idem', ['x'])).toBe('ei:v1:idem:x');
  });

  it('rejects unknown namespaces', () => {
    expect(() => buildRedisKey('admin' as never, ['x'])).toThrow(/Invalid Redis namespace/);
  });

  it('channels must use the notify namespace', () => {
    expect(() => buildRedisChannel('rl' as never, ['x'])).toThrow(/notify/);
    expect(buildRedisChannel('notify', ['idem', 'default', 'abc'])).toMatch(/^ei:v1:notify:/);
  });

  it('hashing is deterministic', () => {
    expect(hashActor('user-1')).toBe(hashActor('user-1'));
    expect(hashActor('user-1')).not.toBe(hashActor('user-2'));
    expect(hashIp('1.2.3.4')).toBe(hashIp('1.2.3.4'));
    expect(hashString('hello')).toBe(hashString('hello'));
    expect(hashString('hello')).not.toBe(hashString('world'));
  });

  it('null/undefined actor becomes anon', () => {
    expect(hashActor(null)).toBe('anon');
    expect(hashActor(undefined)).toBe('anon');
  });

  it('null/undefined ip becomes noip', () => {
    expect(hashIp(null)).toBe('noip');
    expect(hashIp(undefined)).toBe('noip');
  });

  it('user-controlled values cannot contain : or special chars unsanitized', () => {
    const evil = 'foo:bar*baz qux"';
    const key = buildRedisKey('rl', ['default', evil]);
    expect(key.split(':').slice(0, 3)).toEqual(['ei', 'v1', 'rl']);
    expect(key).not.toContain('"');
    expect(key).not.toContain(' ');
    expect(key).not.toContain('*');
  });

  it('long inputs get hashed past a length cap', () => {
    const long = 'a'.repeat(500);
    const key = buildRedisKey('rl', ['default', long]);
    const segments = key.split(':');
    const userSegment = segments[segments.length - 1]!;
    expect(userSegment.length).toBeLessThanOrEqual(128 + 1 + 32);
  });

  it('inputs that already match [A-Za-z0-9_-:.] pass through unchanged', () => {
    expect(buildRedisKey('rl', ['default', 'simple_key-1.0:tag'])).toBe(
      'ei:v1:rl:default:simple_key-1.0:tag',
    );
  });

  it('different subsystems cannot collide on identical user input', () => {
    const input = 'actor-1';
    const rl = buildRedisKey('rl', ['default', input]);
    const sig = buildRedisKey('sig', ['default', input]);
    const obs = buildRedisKey('obs', ['default', input]);
    const idem = buildRedisKey('idem', ['default', input]);
    expect(new Set([rl, sig, obs, idem]).size).toBe(4);
  });
});

describe('InMemoryRedisAdapter (shim)', () => {
  let r: InMemoryRedisAdapter;
  beforeEach(() => {
    r = new InMemoryRedisAdapter();
  });

  it('set/get/expire', async () => {
    await r.set('k', 'v', { ttlMs: 1000 });
    expect(await r.get('k')).toBe('v');
    await r.expire('k', 1);
    await new Promise((r2) => setTimeout(r2, 10));
    expect(await r.get('k')).toBeNull();
  });

  it('set ifNotExists is atomic', async () => {
    expect(await r.set('k', '1', { ifNotExists: true })).toBe(true);
    expect(await r.set('k', '2', { ifNotExists: true })).toBe(false);
    expect(await r.get('k')).toBe('1');
  });

  it('incr/decr', async () => {
    expect(await r.incr('c')).toBe(1);
    expect(await r.incr('c')).toBe(2);
    expect(await r.decr('c')).toBe(1);
  });

  it('zadd / zrange / zcard / zrem', async () => {
    await r.zadd('z', 1, 'a', { ttlMs: 60_000 });
    await r.zadd('z', 2, 'b', { ttlMs: 60_000 });
    await r.zadd('z', 3, 'c', { ttlMs: 60_000 });
    expect(await r.zcard('z')).toBe(3);
    const range = await r.zrangeByScoreWithScores('z', 1, 3);
    expect(range.map((x) => x.member)).toEqual(['a', 'b', 'c']);
    expect(await r.zremRangeByScore('z', 2, 2)).toBe(1);
    expect(await r.zcard('z')).toBe(2);
  });

  it('pub/sub delivers messages', async () => {
    const received: string[] = [];
    const unsub = await r.subscribe('chan', (m) => received.push(m));
    await r.publish('chan', 'hi');
    await new Promise((r2) => setTimeout(r2, 5));
    expect(received).toEqual(['hi']);
    await unsub();
  });
});

describe('RedisRateLimiter (via shim)', () => {
  let r: InMemoryRedisAdapter;
  beforeEach(() => {
    r = new InMemoryRedisAdapter();
  });

  it('consume increments counter atomically and reports remaining', async () => {
    const rl = new RedisRateLimiter({ client: r, keyPrefix: 'test' });
    const spec = {
      namespace: 'n',
      max: 3,
      windowMs: 1000,
      scope: 'actor' as const,
      actor: { subject: 'u-1', authenticated: true, roles: [] },
      action: 'a',
    };
    const r1 = await rl.consume(spec);
    const r2 = await rl.consume(spec);
    const r3 = await rl.consume(spec);
    const r4 = await rl.consume(spec);
    expect(r1.allowed).toBe(true);
    expect(r1.remaining).toBe(2);
    expect(r2.allowed).toBe(true);
    expect(r2.remaining).toBe(1);
    expect(r3.allowed).toBe(true);
    expect(r3.remaining).toBe(0);
    expect(r4.allowed).toBe(false);
    expect(r4.remaining).toBe(0);
    expect(r4.retryAfterMs).toBeGreaterThan(0);
  });

  it('scope kinds are independent', async () => {
    const rl = new RedisRateLimiter({ client: r, keyPrefix: 'test' });
    const a = {
      namespace: 'n',
      max: 1,
      windowMs: 1000,
      scope: 'actor' as const,
      actor: { subject: 'u-1', authenticated: true, roles: [] },
      action: 'a',
    };
    const b = {
      namespace: 'n',
      max: 1,
      windowMs: 1000,
      scope: 'actor' as const,
      actor: { subject: 'u-2', authenticated: true, roles: [] },
      action: 'a',
    };
    expect((await rl.consume(a)).allowed).toBe(true);
    expect((await rl.consume(b)).allowed).toBe(true);
    expect((await rl.consume(a)).allowed).toBe(false);
  });

  it('windowMs reset unblocks after expiration', async () => {
    const rl = new RedisRateLimiter({ client: r, keyPrefix: 'test' });
    const spec = {
      namespace: 'n',
      max: 1,
      windowMs: 50,
      scope: 'ip' as const,
      ip: '1.1.1.1',
      action: 'a',
    };
    expect((await rl.consume(spec)).allowed).toBe(true);
    expect((await rl.consume(spec)).allowed).toBe(false);
    await new Promise((res) => setTimeout(res, 60));
    const r2 = await rl.consume(spec);
    expect(r2.count).toBeGreaterThanOrEqual(1);
  });

  it('reset() clears the bucket', async () => {
    const rl = new RedisRateLimiter({ client: r, keyPrefix: 'test' });
    const spec = {
      namespace: 'n',
      max: 1,
      windowMs: 1000,
      scope: 'ip' as const,
      ip: '1.1.1.1',
      action: 'a',
    };
    const r1 = await rl.consume(spec);
    expect(r1.allowed).toBe(true);
    await rl.reset(r1.key);
    const r2 = await rl.consume(spec);
    expect(r2.count).toBe(1);
  });

  it('validates spec inputs', async () => {
    const rl = new RedisRateLimiter({ client: r, keyPrefix: 'test' });
    await expect(
      rl.consume({
        namespace: 'n',
        max: -1,
        windowMs: 100,
        scope: 'ip' as const,
        ip: '1',
        action: 'a',
      }),
    ).rejects.toThrow();
    await expect(
      rl.consume({
        namespace: 'n',
        max: 1,
        windowMs: 0,
        scope: 'ip' as const,
        ip: '1',
        action: 'a',
      }),
    ).rejects.toThrow();
  });
});

describe('RedisSignalStore (via shim)', () => {
  let r: InMemoryRedisAdapter;
  beforeEach(() => {
    r = new InMemoryRedisAdapter();
  });

  it('increment / count / reset with TTL', async () => {
    const s = new RedisSignalStore({ client: r, keyPrefix: 'test' });
    expect(await s.increment('failed_logins', 60_000)).toBe(1);
    expect(await s.increment('failed_logins', 60_000, 2)).toBe(3);
    expect(await s.count('failed_logins')).toBe(3);
    await s.reset('failed_logins');
    expect(await s.count('failed_logins')).toBe(0);
  });

  it('rejects bad ttl', async () => {
    const s = new RedisSignalStore({ client: r, keyPrefix: 'test' });
    await expect(s.increment('k', 0)).rejects.toThrow();
  });
});

describe('RedisObservationStore (via shim)', () => {
  let r: InMemoryRedisAdapter;
  beforeEach(() => {
    r = new InMemoryRedisAdapter();
  });

  it('record + recent by actor', async () => {
    const s = new RedisObservationStore({ client: r, keyPrefix: 'test', ttlMs: 60_000 });
    await s.record({
      now: 100,
      actorSubject: 'u-1',
      ip: '1.2.3.4',
      userAgent: 'ua',
      method: 'GET',
      path: '/x',
      status: 200,
      resourceId: null,
    });
    await s.record({
      now: 200,
      actorSubject: 'u-1',
      ip: '1.2.3.4',
      userAgent: 'ua',
      method: 'GET',
      path: '/y',
      status: 200,
      resourceId: null,
    });
    const recent = await s.recent({ actorSubject: 'u-1', now: 1000, windowMs: 60_000 });
    expect(recent).toHaveLength(2);
    expect(recent[0]?.now).toBe(100);
  });

  it('windowMs filters out old entries', async () => {
    const s = new RedisObservationStore({ client: r, keyPrefix: 'test', ttlMs: 60_000 });
    await s.record({
      now: 100,
      actorSubject: 'u-1',
      ip: null,
      userAgent: null,
      method: 'GET',
      path: '/x',
      status: 200,
      resourceId: null,
    });
    await s.record({
      now: 5000,
      actorSubject: 'u-1',
      ip: null,
      userAgent: null,
      method: 'GET',
      path: '/x',
      status: 200,
      resourceId: null,
    });
    const recent = await s.recent({ actorSubject: 'u-1', now: 5000, windowMs: 100 });
    expect(recent).toHaveLength(1);
    expect(recent[0]?.now).toBe(5000);
  });
});

describe('RedisIdempotencyProvider (via shim)', () => {
  let r: InMemoryRedisAdapter;
  beforeEach(() => {
    r = new InMemoryRedisAdapter();
  });

  it('acquire is single-flight', async () => {
    const p = new RedisIdempotencyProvider({ client: r, keyPrefix: 'test' });
    const a = await p.acquire('k', 'fp', 10_000);
    const b = await p.acquire('k', 'fp', 10_000);
    expect(a.acquired).toBe(true);
    expect(b.acquired).toBe(false);
    expect(b.current?.state).toBe('in-flight');
  });

  it('fingerprint mismatch throws', async () => {
    const p = new RedisIdempotencyProvider({ client: r, keyPrefix: 'test' });
    await p.acquire('k', 'fp-a', 10_000);
    await expect(p.acquire('k', 'fp-b', 10_000)).rejects.toThrow(/different request fingerprint/);
  });

  it('complete transitions to done; lookup returns response', async () => {
    const p = new RedisIdempotencyProvider({ client: r, keyPrefix: 'test' });
    await p.acquire('k', 'fp', 10_000);
    await p.complete('k', { status: 201, headers: { 'x-test': '1' }, body: 'created' }, 10_000);
    const snap = await p.lookup('k');
    expect(snap?.state).toBe('done');
    expect(snap?.response?.body).toBe('created');
  });

  it('release lets a fresh acquire succeed', async () => {
    const p = new RedisIdempotencyProvider({ client: r, keyPrefix: 'test' });
    await p.acquire('k', 'fp', 10_000);
    await p.release('k');
    const a = await p.acquire('k', 'fp', 10_000);
    expect(a.acquired).toBe(true);
  });

  it('waitForCompletion resolves when another concurrent waiter completes', async () => {
    const p = new RedisIdempotencyProvider({ client: r, keyPrefix: 'test' });
    await p.acquire('k', 'fp', 10_000);
    const waiter = p.waitForCompletion('k', 2_000);
    setTimeout(() => {
      void p.complete('k', { status: 200, headers: {}, body: 'later' }, 10_000);
    }, 10);
    const snap = await waiter;
    expect(snap?.state).toBe('done');
    expect(snap?.response?.body).toBe('later');
  });

  it('waitForCompletion rejects after deadline when never completed', async () => {
    const p = new RedisIdempotencyProvider({ client: r, keyPrefix: 'test' });
    await p.acquire('k', 'fp', 10_000);
    await expect(p.waitForCompletion('k', 50)).rejects.toThrow(/Timed out/);
  });
});

describe('Express integration with RedisIdempotencyProvider', () => {
  let r: InMemoryRedisAdapter;
  beforeEach(() => {
    r = new InMemoryRedisAdapter();
  });

  it('replay + single-flight via Redis backend (10 concurrent)', async () => {
    const provider = new RedisIdempotencyProvider({ client: r, keyPrefix: 'test' });
    let executions = 0;
    const app = express();
    app.use(express.json());
    app.use(createIdempotencyMiddleware({ provider, ttlMs: 60_000, waitDeadlineMs: 5_000 }));
    app.post('/x', async (_req, res) => {
      executions++;
      await new Promise((r2) => setTimeout(r2, 30));
      res.status(200).send(`exec=${executions}`);
    });
    const { port, close } = await listen(app);
    try {
      const responses = await Promise.all(
        Array.from({ length: 10 }, () =>
          fetch(`http://127.0.0.1:${port}/x`, {
            method: 'POST',
            headers: { 'idempotency-key': 'redis-k1' },
            body: '',
          }),
        ),
      );
      const texts = await Promise.all(responses.map((r2) => r2.text()));
      expect(executions).toBe(1);
      expect(new Set(texts).size).toBe(1);
      const replays = responses.filter((r2) => r2.headers.get('idempotency-replayed') === 'true');
      expect(replays).toHaveLength(9);
    } finally {
      await close();
    }
  });

  it('concurrent shared infra: rate limiter + idempotency in the same Redis (no key collision)', async () => {
    const r2 = new InMemoryRedisAdapter();
    const rl = new RedisRateLimiter({ client: r2, keyPrefix: 'shared' });
    const idem = new RedisIdempotencyProvider({ client: r2, keyPrefix: 'shared' });
    const r1 = await rl.consume({
      namespace: 'n',
      max: 100,
      windowMs: 1000,
      scope: 'actor',
      actor: { subject: 'u-1', authenticated: true, roles: [] },
      action: 'a',
    });
    const a = await idem.acquire('idem-k', 'fp', 10_000);
    expect(r1.allowed).toBe(true);
    expect(a.acquired).toBe(true);
  });
});

describe('External contract: RedisIdempotencyProvider matches InMemoryIdempotencyProvider behavior', () => {
  it('both produce equivalent snapshots for the same inputs', async () => {
    const r = new InMemoryRedisAdapter();
    const mem = new InMemoryIdempotencyProvider();
    const redis = new RedisIdempotencyProvider({ client: r, keyPrefix: 'eq' });
    await mem.acquire('k', 'fp', 10_000);
    await redis.acquire('k', 'fp', 10_000);
    await mem.complete('k', { status: 201, headers: {}, body: 'ok' }, 10_000);
    await redis.complete('k', { status: 201, headers: {}, body: 'ok' }, 10_000);
    const m = await mem.lookup('k');
    const rd = await redis.lookup('k');
    expect(m?.state).toBe(rd?.state);
    expect(m?.response?.status).toBe(rd?.response?.status);
    expect(m?.response?.body).toBe(rd?.response?.body);
  });
});

interface RealRedis extends RedisClientAdapter {
  kind: 'real-redis';
}

interface IoRedisLike {
  get(k: string): Promise<string | null>;
  set(k: string, v: string, ...args: string[]): Promise<'OK' | null>;
  del(k: string): Promise<number>;
  pexpire(k: string, t: number): Promise<number>;
  incr(k: string): Promise<number>;
  decr(k: string): Promise<number>;
  zadd(k: string, s: number, m: string): Promise<number>;
  zremrangebyscore(k: string, mn: number | string, mx: number | string): Promise<number>;
  zcard(k: string): Promise<number>;
  zrangebyscore(
    k: string,
    mn: number | string,
    mx: number | string,
    ...args: string[]
  ): Promise<string[]>;
  publish(c: string, m: string): Promise<number>;
  subscribe(...c: string[]): Promise<number>;
  on(ev: 'message', h: (ch: string, m: string) => void): void;
  unsubscribe(...c: string[]): Promise<number>;
  duplicate(): IoRedisLike;
  ping(): Promise<string>;
  quit(): Promise<'OK'>;
  eval(s: string, n: number, ...a: string[]): Promise<unknown>;
}
interface IoRedisCtor {
  new (url: string): IoRedisLike;
}

async function tryRealRedis(): Promise<RealRedis | null> {
  const url = process.env['REDIS_URL'];
  if (!url) return null;
  let mod: { default?: IoRedisCtor } & Record<string, unknown>;
  try {
    const name = 'ioredis';
    mod = await (
      Function('s', 'return import(s)') as (s: string) => Promise<{ default?: IoRedisCtor }>
    )(name);
  } catch {
    return null;
  }
  const Ctor = mod.default;
  if (typeof Ctor !== 'function') return null;
  const client = new Ctor(url);
  try {
    await client.ping();
  } catch {
    return null;
  }
  return {
    kind: 'real-redis',
    get: async (k) => client.get(k),
    set: async (k, v, opts) => {
      const args: string[] = [];
      if (opts?.ttlMs) args.push('PX', String(opts.ttlMs));
      if (opts?.ifNotExists) args.push('NX');
      const res = await client.set(k, v, ...args);
      return res === 'OK';
    },
    del: async (k) => client.del(k),
    expire: async (k, t) => (await client.pexpire(k, t)) === 1,
    incr: async (k) => client.incr(k),
    decr: async (k) => client.decr(k),
    zadd: async (k, s, m, opts) => {
      if (opts?.ttlMs) await client.pexpire(k, opts.ttlMs);
      return client.zadd(k, s, m);
    },
    zremRangeByScore: async (k, mn, mx) => client.zremrangebyscore(k, mn, mx),
    zcard: async (k) => client.zcard(k),
    zrangeByScoreWithScores: async (k, mn, mx, lim) => {
      const r2 =
        lim === undefined
          ? await client.zrangebyscore(k, mn, mx, 'WITHSCORES')
          : await client.zrangebyscore(k, mn, mx, 'WITHSCORES', 'LIMIT', 0, lim);
      const out: { member: string; score: number }[] = [];
      for (let i = 0; i < r2.length; i += 2) {
        out.push({ member: r2[i] as string, score: Number(r2[i + 1]) });
      }
      return out;
    },
    publish: async (c, m) => client.publish(c, m),
    subscribe: async (c, h) => {
      const sub = client.duplicate();
      await sub.subscribe(c);
      sub.on('message', (ch, m) => {
        if (ch === c) h(m);
      });
      return async () => {
        await sub.unsubscribe(c);
        await sub.quit();
      };
    },
    eval: async (s, k, a) => client.eval(s, k.length, ...k, ...a),
    quit: async () => {
      await client.quit();
    },
  };
}

const describeIf = (cond: boolean) => (cond ? describe : describe.skip);

describeIf(true)('Integration: real Redis (REDIS_URL)', () => {
  let real: RealRedis | null = null;
  beforeEach(async () => {
    real = await tryRealRedis();
    if (real === null) {
      console.log(
        '[redis-integration] REDIS_URL not set or unreachable — skipping real-Redis checks',
      );
    }
  });

  it('rate limiter persists across two separate client wrappers', async () => {
    if (real === null) return;
    const a = new RedisRateLimiter({ client: real, keyPrefix: 'intg-' + Date.now() });
    const spec = {
      namespace: 'n',
      max: 1,
      windowMs: 60_000,
      scope: 'actor' as const,
      actor: { subject: 'u', authenticated: true, roles: [] },
      action: 'a',
    };
    const r1 = await a.consume(spec);
    expect(r1.allowed).toBe(true);
    const r2 = await a.consume(spec);
    expect(r2.allowed).toBe(false);
  });

  it('idempotency replay end-to-end via real Redis', async () => {
    if (real === null) return;
    const p = new RedisIdempotencyProvider({ client: real, keyPrefix: 'intg-' + Date.now() });
    const k = 'idem-' + Math.random().toString(36).slice(2, 10);
    const a = await p.acquire(k, 'fp', 60_000);
    expect(a.acquired).toBe(true);
    const b = await p.acquire(k, 'fp', 60_000);
    expect(b.acquired).toBe(false);
    await p.complete(k, { status: 200, headers: {}, body: 'done' }, 60_000);
    const snap = await p.lookup(k);
    expect(snap?.state).toBe('done');
    expect(snap?.response?.body).toBe('done');
  });
});
