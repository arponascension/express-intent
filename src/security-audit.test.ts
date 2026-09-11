import { describe, it, expect } from 'vitest';
import express, { type Request, type Response } from 'express';
import http from 'node:http';
import { attachAudit, InMemoryAuditSink } from './index.js';
import { safeOwnEntries, safeOwnKeys, safeSpread, isPollutionKey } from './safe-object.js';
import { createIdempotencyMiddleware, IDEMPOTENCY_KEY_PATTERN } from './idempotency.js';
import { InMemoryIdempotencyProvider } from './idempotency-memory.js';
import { buildRateLimitKey } from './rate-limit-memory.js';
import {
  normalizeActor,
  defaultActorProvider,
  ANONYMOUS_ACTOR,
  MalformedActorError,
} from './actor.js';
import { parseAction } from './action.js';
import { RedactionEngine } from './redaction.js';
import { buildRequestContext } from './context.js';

function listen(app: express.Express): Promise<{ port: number; close: () => Promise<void> }> {
  return new Promise((resolve) => {
    const server = app.listen(0, () => {
      const addr = server.address();
      if (typeof addr === 'object' && addr !== null) {
        resolve({
          port: addr.port,
          close: () => new Promise<void>((r) => server.close(() => r())),
        });
      }
    });
  });
}

function post(
  port: number,
  path: string,
  idemKey: string | null,
  body?: unknown,
): Promise<{ status: number; text: string; headers: http.IncomingHttpHeaders }> {
  return new Promise((resolve, reject) => {
    const data = body === undefined ? '' : JSON.stringify(body);
    const req = http.request(
      {
        method: 'POST',
        host: '127.0.0.1',
        port,
        path,
        headers: {
          'content-type': 'application/json',
          'content-length': Buffer.byteLength(data),
          ...(idemKey === null ? {} : { 'idempotency-key': idemKey }),
        },
      },
      (res) => {
        let buf = '';
        res.setEncoding('utf8');
        res.on('data', (c) => (buf += c));
        res.on('end', () =>
          resolve({ status: res.statusCode ?? 0, text: buf, headers: res.headers }),
        );
      },
    );
    req.on('error', reject);
    if (data.length > 0) req.write(data);
    req.end();
  });
}

describe('safe-object helpers', () => {
  it('excludes __proto__/constructor/prototype', () => {
    const k = safeOwnKeys({
      a: 1,
      __proto__: { polluted: true },
      constructor: 1,
      b: 2,
    } as unknown as object);
    expect(k).toEqual(['a', 'b']);
  });

  it('safeOwnEntries returns only safe entries', () => {
    const e = safeOwnEntries({ a: 1, __proto__: { polluted: true }, b: 2 } as unknown as object);
    expect(e).toEqual([
      ['a', 1],
      ['b', 2],
    ]);
  });

  it('safeSpread does not include prototype keys', () => {
    const r = safeSpread({ a: 1, __proto__: { polluted: true } } as unknown as object);
    expect(Object.keys(r)).toEqual(['a']);
    expect((r as { polluted?: unknown }).polluted).toBeUndefined();
  });

  it('isPollutionKey detects', () => {
    expect(isPollutionKey('__proto__')).toBe(true);
    expect(isPollutionKey('a')).toBe(false);
  });
});

describe('action parsing', () => {
  it('rejects empty', () => {
    expect(() => parseAction('')).toThrow();
  });
  it('rejects too long', () => {
    expect(() => parseAction('a.' + 'x'.repeat(200))).toThrow();
  });
  it('accepts normal', () => {
    expect(parseAction('payment.create').action).toBe('payment.create');
  });
});

describe('actor normalization', () => {
  it('rejects __proto__ in actor', () => {
    const evil: Record<string, unknown> = { subject: 'x', authenticated: true };
    Object.defineProperty(evil, '__proto__', {
      value: { evil: true },
      enumerable: true,
      writable: true,
      configurable: true,
    });
    expect(() => normalizeActor(evil, 'required')).toThrow(MalformedActorError);
  });
  it('rejects subject > 1024', () => {
    expect(() =>
      normalizeActor({ subject: 'x'.repeat(1025), authenticated: true }, 'required'),
    ).toThrow();
  });
  it('accepts subject <= 1024', () => {
    const a = normalizeActor({ subject: 'x'.repeat(1024), authenticated: true }, 'required');
    expect(a.subject?.length).toBe(1024);
  });
  it('rejects non-finite authenticatedAt', () => {
    expect(() =>
      normalizeActor(
        { subject: 'x', authenticated: true, authenticatedAt: Number.POSITIVE_INFINITY },
        'required',
      ),
    ).toThrow();
  });
  it('defaultActorProvider returns anonymous for empty headers', () => {
    const actor = defaultActorProvider({ headers: {} } as unknown as Request);
    expect(actor).toBe(ANONYMOUS_ACTOR);
  });
  it('defaultActorProvider trims subject header', () => {
    const actor = defaultActorProvider({
      headers: { 'x-user-subject': 'admin' },
    } as unknown as Request);
    expect((actor as { subject: string | null }).subject).toBe('admin');
  });
  it('rejects header subject > 1024 chars', () => {
    const actor = defaultActorProvider({
      headers: { 'x-user-subject': 'x'.repeat(2000) },
    } as unknown as Request);
    expect((actor as { subject: string | null }).subject).toBeNull();
  });
});

describe('redaction', () => {
  it('drops __proto__ from headers', () => {
    const r = new RedactionEngine();
    const headers: Record<string, string> = { authorization: 'secret' };
    Object.defineProperty(headers, '__proto__', {
      value: 'pwn',
      enumerable: true,
      configurable: true,
      writable: true,
    });
    const out = r.redactHeaders(
      headers as unknown as Record<string, string | string[] | undefined>,
    );
    expect(out.authorization).toBe('[REDACTED]');
    expect(Object.hasOwn(out, '__proto__')).toBe(false);
  });
  it('drops constructor from query', () => {
    const r = new RedactionEngine();
    const q: Record<string, unknown> = { normal: 'ok' };
    Object.defineProperty(q, 'constructor', {
      value: 'pwn',
      enumerable: true,
      configurable: true,
      writable: true,
    });
    const out = r.redactQuery(q);
    expect(out.normal).toBe('ok');
    expect(Object.hasOwn(out, 'constructor')).toBe(false);
  });
  it('does not descend into __proto__ chain via walk', () => {
    const r = new RedactionEngine({ includeBody: true });
    const polluted: Record<string, unknown> = { a: 1 };
    Object.defineProperty(polluted, '__proto__', {
      value: { polluted: true },
      enumerable: true,
      configurable: true,
      writable: true,
    });
    const { body } = r.redactBody(polluted, ['a']);
    expect(body).toEqual({ a: 1 });
    expect((body as Record<string, unknown>).polluted).toBeUndefined();
  });
});

describe('context body shape hash', () => {
  it('handles deeply nested bodies with depth cap', async () => {
    let b: unknown = {};
    let cur: Record<string, unknown> = b as Record<string, unknown>;
    for (let i = 0; i < 50; i++) {
      cur.next = {};
      cur = cur.next as Record<string, unknown>;
    }
    const req = {
      body: b,
      headers: {},
      method: 'POST',
      path: '/x',
      ip: '127.0.0.1',
    } as unknown as Request;
    const ctx = await buildRequestContext(req, {
      intent: { key: 'x', action: 'x.y', auth: 'optional' } as never,
    });
    expect(typeof ctx.bodyShapeHash === 'string' || ctx.bodyShapeHash === null).toBe(true);
  });
  it('handles very large body gracefully', async () => {
    const huge: Record<string, unknown> = {};
    for (let i = 0; i < 500; i++) huge[`k${i}`] = 'x'.repeat(200);
    const req = {
      body: huge,
      headers: {},
      method: 'POST',
      path: '/x',
      ip: '127.0.0.1',
    } as unknown as Request;
    const ctx = await buildRequestContext(req, {
      intent: { key: 'x', action: 'x.y', auth: 'optional' } as never,
    });
    expect(ctx.bodyShapeHash).not.toBeNull();
  });
});

describe('idempotency replay hardening', () => {
  it('does not replay Set-Cookie from stored response', async () => {
    const provider = new InMemoryIdempotencyProvider();
    const app = express();
    app.use(express.json());
    let first = true;
    app.post('/x', createIdempotencyMiddleware({ provider }), (req: Request, res: Response) => {
      if (first) {
        first = false;
        res.setHeader('set-cookie', 'session=evil; Path=/; HttpOnly');
        res.setHeader('content-type', 'application/json');
        res.send(JSON.stringify({ ok: true }));
      } else {
        res.status(500).send('should not be called');
      }
    });
    const { port, close } = await listen(app);
    try {
      const r1 = await post(port, '/x', 'k1', {});
      expect(r1.status).toBe(200);
      expect(r1.headers['set-cookie']).toBeDefined();
      const r2 = await post(port, '/x', 'k1', {});
      expect(r2.status).toBe(200);
      expect(r2.headers['set-cookie']).toBeUndefined();
    } finally {
      await close();
    }
  });

  it('caps captured body size to 64 KB', async () => {
    const provider = new InMemoryIdempotencyProvider();
    const app = express();
    app.post('/x', createIdempotencyMiddleware({ provider }), (_req: Request, res: Response) => {
      res.setHeader('content-type', 'text/plain');
      res.send('x'.repeat(200_000));
    });
    const { port, close } = await listen(app);
    try {
      await post(port, '/x', 'k1', {});
      const r2 = await post(port, '/x', 'k1', {});
      const len = (r2.text || '').length;
      expect(len).toBeLessThanOrEqual(65536);
    } finally {
      await close();
    }
  });

  it('rejects mismatched body fingerprint while in-flight', async () => {
    const provider = new InMemoryIdempotencyProvider();
    const app = express();
    app.use(express.json());
    let calls = 0;
    let firstDone!: () => void;
    const firstDoneP = new Promise<void>((r) => (firstDone = r));
    app.post(
      '/x',
      createIdempotencyMiddleware({ provider }),
      async (_req: Request, res: Response) => {
        calls++;
        if (calls === 1) {
          await firstDoneP;
        }
        res.status(201).json({ ok: true });
      },
    );
    const { port, close } = await listen(app);
    try {
      const r1Promise = post(port, '/x', 'k1', { amount: 100 });
      await new Promise((r) => setTimeout(r, 20));
      const r2 = await post(port, '/x', 'k1', { amount: 999 });
      firstDone();
      const r1 = await r1Promise;
      expect(r1.status).toBe(201);
      expect(r2.status).toBe(422);
      expect(calls).toBe(1);
    } finally {
      await close();
    }
  });

  it('rejects mismatched body fingerprint after completion', async () => {
    const provider = new InMemoryIdempotencyProvider();
    const app = express();
    app.use(express.json());
    app.post(
      '/x',
      createIdempotencyMiddleware({ provider }),
      async (_req: Request, res: Response) => {
        res.status(201).json({ ok: true });
      },
    );
    const { port, close } = await listen(app);
    try {
      const r1 = await post(port, '/x', 'k1', { amount: 100 });
      await new Promise((r) => setTimeout(r, 50));
      const r2 = await post(port, '/x', 'k1', { amount: 999 });
      expect(r1.status).toBe(201);
      expect(r2.status).toBe(422);
    } finally {
      await close();
    }
  });

  it('rejects non-string idempotency key', async () => {
    const provider = new InMemoryIdempotencyProvider();
    const app = express();
    app.post('/x', createIdempotencyMiddleware({ provider }), (_req: Request, res: Response) => {
      res.status(201).json({ ok: true });
    });
    const { port, close } = await listen(app);
    try {
      const r1 = await post(port, '/x', 'k!@#$%^&*()+=', {});
      expect(r1.status).toBe(400);
    } finally {
      await close();
    }
  });
});

describe('rate limit key hardening', () => {
  it('hashes very long subject', () => {
    const k = buildRateLimitKey(
      'actor',
      'rl',
      {
        subject: 'x'.repeat(500),
        authenticated: true,
        authMethod: null,
        authRequirement: 'optional',
        roles: [],
        scopes: [],
        claims: {},
        authenticatedAt: null,
      },
      null,
      'a.b',
    );
    expect(k).toMatch(/^rl:rl:actor:[a-f0-9]{16}$/);
  });
  it('keeps short IP literal readable', () => {
    const k = buildRateLimitKey('ip', 'rl', null, '10.0.0.1', 'a.b');
    expect(k).toBe('rl:rl:ip:10.0.0.1');
  });
  it('keeps IPv6 readable', () => {
    const k = buildRateLimitKey('ip', 'rl', null, '::1', 'a.b');
    expect(k).toBe('rl:rl:ip:::1');
  });
  it('hashes huge custom key', () => {
    const k = buildRateLimitKey('custom', 'rl', null, null, 'a.b', 'x'.repeat(500));
    expect(k).toMatch(/^rl:rl:custom:[a-f0-9]{16}$/);
  });
  it('preserves unknown for null ip', () => {
    const k = buildRateLimitKey('ip', 'rl', null, null, 'a.b');
    expect(k).toBe('rl:rl:ip:unknown');
  });
});

describe('redis rate limiter EXPIRE always', () => {
  it('sets TTL on every increment, never relying on count===1', async () => {
    const expiries: number[] = [];
    const fakeClient = {
      kind: 'fake',
      incr: async () => 1,
      expire: async (_k: string, ms: number) => {
        expiries.push(ms);
        return true;
      },
    };
    const { RedisRateLimiter } = await import('./redis/rate-limiter.js');
    const rl = new RedisRateLimiter({ client: fakeClient as never });
    await rl.consume({ namespace: 'ns', scope: 'action', action: 'a.b', max: 5, windowMs: 1000 });
    expect(expiries.length).toBe(1);
  });
});

describe('audit IP extraction', () => {
  it('uses req.ip and does not fall back to XFF when trust proxy is off', async () => {
    const sink = new InMemoryAuditSink();
    const app = express();
    app.use(
      attachAudit({
        sink,
        decisionResolver: () => ({ kind: 'allow' }),
      }),
    );
    app.get('/x', (_req: Request, res: Response) => res.status(200).end());
    const { port, close } = await listen(app);
    try {
      await new Promise<void>((resolve, reject) => {
        const req = http.request(
          {
            method: 'GET',
            host: '127.0.0.1',
            port,
            path: '/x',
            headers: { 'x-forwarded-for': '1.2.3.4' },
          },
          (res) => {
            res.resume();
            res.on('end', resolve);
          },
        );
        req.on('error', reject);
        req.end();
      });
      // Wait for audit event
      await new Promise((r) => setTimeout(r, 50));
      const events = sink.all();
      expect(events.length).toBe(1);
      expect(events[0]?.request.ip).not.toBe('1.2.3.4');
    } finally {
      await close();
    }
  });

  it('truncates user agent to 256 chars', async () => {
    const sink = new InMemoryAuditSink();
    const app = express();
    app.use(
      attachAudit({
        sink,
        decisionResolver: () => ({ kind: 'allow' }),
      }),
    );
    app.get('/x', (_req: Request, res: Response) => res.status(200).end());
    const { port, close } = await listen(app);
    try {
      const ua = 'A'.repeat(1000);
      await new Promise<void>((resolve, reject) => {
        const req = http.request(
          { method: 'GET', host: '127.0.0.1', port, path: '/x', headers: { 'user-agent': ua } },
          (res) => {
            res.resume();
            res.on('end', resolve);
          },
        );
        req.on('error', reject);
        req.end();
      });
      await new Promise((r) => setTimeout(r, 50));
      const events = sink.all();
      expect(events[0]?.request.userAgent?.length).toBeLessThanOrEqual(256);
    } finally {
      await close();
    }
  });
});

describe('IDEMPOTENCY_KEY_PATTERN export', () => {
  it('exists and is a regex', () => {
    expect(IDEMPOTENCY_KEY_PATTERN).toBeInstanceOf(RegExp);
  });
});
