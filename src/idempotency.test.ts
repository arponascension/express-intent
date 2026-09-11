import { describe, it, expect } from 'vitest';
import express, { type Express, type Request, type Response, type NextFunction } from 'express';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import {
  createIdempotencyMiddleware,
  InMemoryIdempotencyProvider,
  IDEMPOTENCY_KEY_PATTERN,
  isValidIdempotencyKey,
  type IdempotencySnapshot,
  type StoredResponse,
} from './index.js';

function makeApp(
  provider: InMemoryIdempotencyProvider,
  opts: { delayMs?: number; withJson?: boolean } = {},
): Express {
  const app = express();
  app.use(express.json());
  app.use(
    createIdempotencyMiddleware({
      provider,
      ttlMs: 60_000,
      waitDeadlineMs: 5_000,
    }),
  );
  app.post('/charge', async (req: Request, res: Response, next: NextFunction) => {
    try {
      if (opts.delayMs) {
        await new Promise((r) => setTimeout(r, opts.delayMs));
      }
      res.status(201);
      if (opts.withJson) {
        res.setHeader('content-type', 'application/json');
        res.send(
          JSON.stringify({
            id: 'ch_1',
            amount: req.body?.amount ?? 0,
            key: req.idempotency?.key ?? null,
          }),
        );
      } else {
        res.send('ok');
      }
    } catch (e) {
      next(e);
    }
  });
  app.get('/echo', (req, res) => {
    res.status(200);
    res.send('echo:' + (req.idempotency?.key ?? ''));
  });
  return app;
}

async function listen(
  app: Express,
): Promise<{ server: Server; port: number; close: () => Promise<void> }> {
  const server = createServer(app);
  await new Promise<void>((r) => server.listen(0, r));
  const port = (server.address() as AddressInfo).port;
  return {
    server,
    port,
    close: () =>
      new Promise<void>((res, rej) => {
        server.close((err) => (err ? rej(err) : res()));
      }),
  };
}

function post(
  port: number,
  path: string,
  key: string,
  body: unknown,
): Promise<{ status: number; text: string; replayed: string | null }> {
  return fetch(`http://127.0.0.1:${port}${path}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'idempotency-key': key },
    body: JSON.stringify(body),
  }).then(async (r) => ({
    status: r.status,
    text: await r.text(),
    replayed: r.headers.get('idempotency-replayed'),
  }));
}

describe('idempotency key validation', () => {
  it('pattern matches alnum, _, -, :, . and length 1-255', () => {
    expect(isValidIdempotencyKey('abc-123_X.y:z')).toBe(true);
    expect(isValidIdempotencyKey('a'.repeat(255))).toBe(true);
    expect(isValidIdempotencyKey('a'.repeat(256))).toBe(false);
    expect(isValidIdempotencyKey('')).toBe(false);
    expect(isValidIdempotencyKey('has space')).toBe(false);
    expect(isValidIdempotencyKey('has/slash')).toBe(false);
    expect(isValidIdempotencyKey('has?qs')).toBe(false);
  });
  it('pattern is exposed', () => {
    expect(IDEMPOTENCY_KEY_PATTERN.test('good_key-1.0:prod')).toBe(true);
  });
});

describe('createIdempotencyMiddleware', () => {
  it('passes through requests without an Idempotency-Key header', async () => {
    const provider = new InMemoryIdempotencyProvider();
    const app = makeApp(provider);
    const { port, close } = await listen(app);
    try {
      const r1 = await fetch(`http://127.0.0.1:${port}/echo`);
      const r2 = await fetch(`http://127.0.0.1:${port}/echo`);
      expect(r1.status).toBe(200);
      expect(r2.status).toBe(200);
      expect(await r1.text()).toBe('echo:');
      expect(await r2.text()).toBe('echo:');
    } finally {
      await close();
    }
  });

  it('rejects malformed keys with 400', async () => {
    const provider = new InMemoryIdempotencyProvider();
    const app = makeApp(provider);
    const { port, close } = await listen(app);
    try {
      const r = await fetch(`http://127.0.0.1:${port}/charge`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', 'idempotency-key': 'has space' },
        body: '{}',
      });
      expect(r.status).toBe(400);
      expect(await r.json()).toEqual({ error: 'invalid_idempotency_key' });
    } finally {
      await close();
    }
  });

  it('replays the first response on duplicate key + same body', async () => {
    const provider = new InMemoryIdempotencyProvider();
    const app = makeApp(provider, { withJson: true });
    const { port, close } = await listen(app);
    try {
      const r1 = await post(port, '/charge', 'k1', { amount: 100 });
      const r2 = await post(port, '/charge', 'k1', { amount: 100 });
      expect(r1.status).toBe(201);
      expect(r1.replayed).toBeNull();
      const j1 = JSON.parse(r1.text);
      const j2 = JSON.parse(r2.text);
      expect(j2).toEqual(j1);
      expect(r2.status).toBe(201);
      expect(r2.replayed).toBe('true');
    } finally {
      await close();
    }
  });

  it('rejects duplicate key with different body via 422', async () => {
    const provider = new InMemoryIdempotencyProvider();
    const app = makeApp(provider, { withJson: true });
    const { port, close } = await listen(app);
    try {
      const r1 = await post(port, '/charge', 'k2', { amount: 100 });
      const r2 = await post(port, '/charge', 'k2', { amount: 999 });
      expect(r1.status).toBe(201);
      expect(r2.status).toBe(422);
      expect(JSON.parse(r2.text)).toEqual({ error: 'idempotency_key_mismatch' });
    } finally {
      await close();
    }
  });

  it('single-flight: concurrent requests with same key only execute body once', async () => {
    const provider = new InMemoryIdempotencyProvider();
    const app = makeApp(provider, { delayMs: 50, withJson: true });
    const { port, close } = await listen(app);
    try {
      const requests = Array.from({ length: 10 }, () =>
        post(port, '/charge', 'concurrent-key', { amount: 50 }),
      );
      const responses = await Promise.all(requests);
      const ok = responses.filter((r) => r.status === 201);
      const replays = responses.filter((r) => r.replayed === 'true');
      expect(ok).toHaveLength(10);
      expect(replays).toHaveLength(9);
      const bodies = new Set(ok.map((r) => r.text));
      expect(bodies.size).toBe(1);
    } finally {
      await close();
    }
  });

  it('single-flight: exactly one body execution across racing duplicates', async () => {
    const provider = new InMemoryIdempotencyProvider();
    let executions = 0;
    const app = express();
    app.use(express.json());
    app.use(
      createIdempotencyMiddleware({
        provider,
        ttlMs: 60_000,
        waitDeadlineMs: 5_000,
      }),
    );
    app.post('/counter', async (req, res) => {
      executions++;
      await new Promise((r) => setTimeout(r, 30));
      res.status(200);
      res.send(`exec=${executions}`);
    });
    const { port, close } = await listen(app);
    try {
      const responses = await Promise.all(
        Array.from({ length: 25 }, () =>
          fetch(`http://127.0.0.1:${port}/counter`, {
            method: 'POST',
            headers: { 'idempotency-key': 'race' },
            body: '',
          }),
        ),
      );
      const texts = await Promise.all(responses.map((r) => r.text()));
      const counts = texts.map((t) => Number(t.split('=')[1]));
      expect(new Set(texts).size).toBe(1);
      expect(executions).toBe(1);
      expect(counts).toEqual(new Array(25).fill(1));
    } finally {
      await close();
    }
  });

  it('TTL expiry allows a new request to execute after expiration', async () => {
    let now = 1_000_000;
    const provider = new InMemoryIdempotencyProvider({ clock: () => now });
    let exec = 0;
    const app = express();
    app.use(
      createIdempotencyMiddleware({
        provider,
        ttlMs: 1000,
        waitDeadlineMs: 1000,
      }),
    );
    app.post('/t', (req, res) => {
      exec++;
      res.status(200);
      res.send('ok:' + exec);
    });
    const { port, close } = await listen(app);
    try {
      const opts = (key: string) =>
        fetch(`http://127.0.0.1:${port}/t`, {
          method: 'POST',
          headers: { 'idempotency-key': key },
          body: '',
        });
      const a = await opts('k-ttl');
      expect(a.status).toBe(200);
      now += 500;
      const b = await opts('k-ttl');
      expect(b.status).toBe(200);
      expect(b.headers.get('idempotency-replayed')).toBe('true');
      now += 2000;
      const c = await opts('k-ttl');
      expect(c.status).toBe(200);
      expect(c.headers.get('idempotency-replayed')).toBeNull();
      expect(exec).toBe(2);
    } finally {
      await close();
    }
  });

  it('exposes idempotency context on req', async () => {
    const provider = new InMemoryIdempotencyProvider();
    let firstKey: string | null = null;
    let firstReplayed: boolean | null = null;
    const app = express();
    app.use(createIdempotencyMiddleware({ provider, ttlMs: 60_000 }));
    app.post('/ctx', (req, res) => {
      firstKey = req.idempotency?.key ?? null;
      firstReplayed = req.idempotency?.replayed ?? null;
      res.status(204).end();
    });
    const { port, close } = await listen(app);
    try {
      const r = await fetch(`http://127.0.0.1:${port}/ctx`, {
        method: 'POST',
        headers: { 'idempotency-key': 'kctx' },
        body: '',
      });
      expect(r.status).toBe(204);
      expect(firstKey).toBe('kctx');
      expect(firstReplayed).toBe(false);
    } finally {
      await close();
    }
  });

  it('provider.acquire is single-flight at the API level', async () => {
    const provider = new InMemoryIdempotencyProvider();
    const key = 'unit-key';
    const fp = 'fp';
    const a = await provider.acquire(key, fp, 10_000);
    const b = await provider.acquire(key, fp, 10_000);
    expect(a.acquired).toBe(true);
    expect(b.acquired).toBe(false);
    expect(b.current?.state).toBe('in-flight');
  });

  it('provider.complete transitions to done; subsequent lookups return done', async () => {
    const provider = new InMemoryIdempotencyProvider();
    const key = 'unit-2';
    const acq = await provider.acquire(key, 'fp', 10_000);
    expect(acq.acquired).toBe(true);
    const resp: StoredResponse = { status: 201, headers: { 'x-test': '1' }, body: 'created' };
    await provider.complete(key, resp, 10_000);
    const snap = await provider.lookup(key);
    expect(snap?.state).toBe('done');
    expect(snap?.response?.status).toBe(201);
    expect(snap?.response?.body).toBe('created');
  });

  it('provider.release lets a fresh acquire succeed', async () => {
    const provider = new InMemoryIdempotencyProvider();
    const key = 'unit-3';
    await provider.acquire(key, 'fp', 10_000);
    await provider.release(key);
    const acq2 = await provider.acquire(key, 'fp', 10_000);
    expect(acq2.acquired).toBe(true);
  });

  it('fingerprint mismatch on provider.acquire throws', async () => {
    const provider = new InMemoryIdempotencyProvider();
    const key = 'unit-4';
    await provider.acquire(key, 'fp-a', 10_000);
    await expect(provider.acquire(key, 'fp-b', 10_000)).rejects.toThrow(
      /different request fingerprint/,
    );
  });

  it('waitForCompletion resolves when another concurrent waiter completes the key', async () => {
    const provider = new InMemoryIdempotencyProvider();
    const key = 'unit-5';
    await provider.acquire(key, 'fp', 10_000);
    const waiter = provider.waitForCompletion(key, 2_000);
    setTimeout(() => {
      void provider.complete(key, { status: 200, headers: {}, body: 'later' }, 10_000);
    }, 20);
    const snap = (await waiter) as IdempotencySnapshot;
    expect(snap.state).toBe('done');
    expect(snap.response?.body).toBe('later');
  });

  it('waitForCompletion rejects after deadline when never completed', async () => {
    const provider = new InMemoryIdempotencyProvider();
    const key = 'unit-6';
    await provider.acquire(key, 'fp', 10_000);
    await expect(provider.waitForCompletion(key, 50)).rejects.toThrow(/Timed out/);
  });

  it('respects maxEntries eviction', async () => {
    const provider = new InMemoryIdempotencyProvider({ maxEntries: 2 });
    await provider.acquire('a', 'fp', 10_000);
    await provider.acquire('b', 'fp', 10_000);
    await provider.acquire('c', 'fp', 10_000);
    expect(provider.size()).toBe(2);
    expect(await provider.lookup('a')).toBeNull();
    expect((await provider.lookup('b'))?.state).toBe('in-flight');
    expect((await provider.lookup('c'))?.state).toBe('in-flight');
  });

  it('cleans up expired entries on lookup', async () => {
    let now = 0;
    const provider = new InMemoryIdempotencyProvider({ clock: () => now });
    await provider.acquire('exp', 'fp', 1_000, 0);
    now = 2_000;
    const snap = await provider.lookup('exp', 2_000);
    expect(snap).toBeNull();
    expect(provider.size()).toBe(0);
  });

  it('shutdown rejects all waiters and clears state', async () => {
    const provider = new InMemoryIdempotencyProvider();
    const key = 'shut';
    await provider.acquire(key, 'fp', 10_000);
    const wait = provider.waitForCompletion(key, 5_000);
    await provider.shutdown();
    await expect(wait).rejects.toThrow(/shutdown/);
    expect(provider.size()).toBe(0);
  });
});
