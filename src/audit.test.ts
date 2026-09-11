import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import express, { type Express } from 'express';
import { createServer } from 'node:http';
import type { AddressInfo } from 'node:net';
import {
  attachAudit,
  InMemoryAuditSink,
  ConsoleAuditSink,
  RedactionEngine,
  isSensitiveHeader,
  isSensitiveQueryParam,
  isSensitiveBodyKey,
  DEFAULT_REDACTION_CONFIG,
  type AuditEvent,
  type AuditSink,
} from './index.js';

function listen(app: Express): Promise<{ port: number; close: () => Promise<void> }> {
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

async function postJson(
  port: number,
  path: string,
  body: unknown,
  headers: Record<string, string> = {},
): Promise<{ status: number; text: string; respHeaders: Headers }> {
  const r = await fetch(`http://127.0.0.1:${port}${path}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', ...headers },
    body: JSON.stringify(body),
  });
  return { status: r.status, text: await r.text(), respHeaders: r.headers };
}

describe('RedactionEngine - header redaction', () => {
  const engine = new RedactionEngine();

  it('redacts Authorization header (Bearer tokens)', () => {
    const out = engine.redactHeaders({ authorization: 'Bearer abc.def.ghi' });
    expect(out.authorization).toBe('[REDACTED]');
  });

  it('redacts Basic auth too', () => {
    const out = engine.redactHeaders({ authorization: 'Basic dXNlcjpwYXNz' });
    expect(out.authorization).toBe('[REDACTED]');
  });

  it('redacts cookie and set-cookie', () => {
    const out = engine.redactHeaders({
      cookie: 'session=abc; csrf=xyz',
      'set-cookie': 'session=abc; HttpOnly',
    });
    expect(out.cookie).toBe('[REDACTED]');
    expect(out['set-cookie']).toBe('[REDACTED]');
  });

  it('redacts x-api-key / api-key / x-auth-token', () => {
    const out = engine.redactHeaders({
      'x-api-key': 'live_key_123',
      'api-key': 'another',
      'x-auth-token': 'tok',
      'x-csrf-token': 'csrf',
    });
    expect(out['x-api-key']).toBe('[REDACTED]');
    expect(out['api-key']).toBe('[REDACTED]');
    expect(out['x-auth-token']).toBe('[REDACTED]');
    expect(out['x-csrf-token']).toBe('[REDACTED]');
  });

  it('redacts x-forwarded-for / x-real-ip / x-amz-security-token', () => {
    const out = engine.redactHeaders({
      'x-forwarded-for': '1.2.3.4',
      'x-real-ip': '1.2.3.4',
      'x-amz-security-token': 'aws-token',
    });
    expect(out['x-forwarded-for']).toBe('[REDACTED]');
    expect(out['x-real-ip']).toBe('[REDACTED]');
    expect(out['x-amz-security-token']).toBe('[REDACTED]');
  });

  it('keeps non-sensitive headers intact (truncated only if oversized)', () => {
    const out = engine.redactHeaders({
      accept: 'application/json',
      'user-agent': 'ua',
    });
    expect(out.accept).toBe('application/json');
    expect(out['user-agent']).toBe('ua');
  });

  it('truncates long non-sensitive header values', () => {
    const big = 'x'.repeat(5000);
    const out = engine.redactHeaders({ 'x-trace-id': big });
    expect(out['x-trace-id'].length).toBeLessThan(big.length);
    expect(out['x-trace-id']).toMatch(/truncated/);
  });

  it('is case-insensitive', () => {
    const out = engine.redactHeaders({ AUTHORIZATION: 'Bearer x', Cookie: 'a=b' });
    expect(out.AUTHORIZATION).toBe('[REDACTED]');
    expect(out.Cookie).toBe('[REDACTED]');
  });

  it('custom replacement is honored', () => {
    const e = new RedactionEngine({ replacement: '***' });
    const out = e.redactHeaders({ authorization: 'Bearer x' });
    expect(out.authorization).toBe('***');
  });
});

describe('RedactionEngine - query redaction', () => {
  const engine = new RedactionEngine();
  it('redacts token, api_key, password, secret, code, state', () => {
    const out = engine.redactQuery({
      token: 't',
      api_key: 'k',
      password: 'p',
      secret: 's',
      code: 'c',
      state: 'st',
    });
    expect(out.token).toBe('[REDACTED]');
    expect(out.api_key).toBe('[REDACTED]');
    expect(out.password).toBe('[REDACTED]');
    expect(out.secret).toBe('[REDACTED]');
    expect(out.code).toBe('[REDACTED]');
    expect(out.state).toBe('[REDACTED]');
  });
  it('keeps safe params intact', () => {
    const out = engine.redactQuery({ q: 'hello', page: '2' });
    expect(out.q).toBe('hello');
    expect(out.page).toBe('2');
  });
});

describe('RedactionEngine - body redaction', () => {
  it('does NOT include body by default', () => {
    const engine = new RedactionEngine();
    const { body, bodyKeys } = engine.redactBody({ password: 'hunter2', email: 'a@b.c' }, [
      'password',
      'email',
    ]);
    expect(body).toBeNull();
    expect(bodyKeys).toEqual(['email', 'password']);
  });

  it('redacts nested password/secret/token when includeBody=true', () => {
    const engine = new RedactionEngine({ includeBody: true });
    const { body } = engine.redactBody(
      { email: 'a@b.c', password: 'hunter2', nested: { token: 'tk', apiKey: 'ak' } },
      ['email', 'password', 'nested'],
    );
    expect(body).toEqual({
      email: 'a@b.c',
      password: '[REDACTED]',
      nested: { token: '[REDACTED]', apiKey: '[REDACTED]' },
    });
  });

  it('redacts card number, cvv, ssn', () => {
    const engine = new RedactionEngine({ includeBody: true });
    const { body } = engine.redactBody(
      { card_number: '4111111111111111', cvv: '123', ssn: '111-22-3333' },
      [],
    );
    expect(body).toEqual({ card_number: '[REDACTED]', cvv: '[REDACTED]', ssn: '[REDACTED]' });
  });

  it('redacts in arrays recursively', () => {
    const engine = new RedactionEngine({ includeBody: true });
    const { body } = engine.redactBody(
      {
        items: [
          { id: 1, secret: 'x' },
          { id: 2, password: 'p' },
        ],
      },
      [],
    );
    expect(body).toEqual({
      items: [
        { id: 1, secret: '[REDACTED]' },
        { id: 2, password: '[REDACTED]' },
      ],
    });
  });

  it('does not mutate input', () => {
    const engine = new RedactionEngine({ includeBody: true });
    const input = { password: 'p', nested: { token: 't' } };
    const snapshot = JSON.parse(JSON.stringify(input));
    engine.redactBody(input, ['password', 'nested']);
    expect(input).toEqual(snapshot);
  });

  it('truncates very long string values', () => {
    const engine = new RedactionEngine({ includeBody: true, maxStringLength: 16 });
    const { body } = engine.redactBody({ note: 'a'.repeat(200) }, ['note']);
    expect((body as { note: string }).note.length).toBeLessThanOrEqual(50);
    expect((body as { note: string }).note).toMatch(/truncated/);
  });

  it('truncates large object keys', () => {
    const engine = new RedactionEngine({ includeBody: true, maxObjectKeys: 3 });
    const obj: Record<string, string> = {};
    for (let i = 0; i < 10; i++) obj['k' + i] = 'v' + i;
    const { body } = engine.redactBody(obj, Object.keys(obj));
    const b = body as Record<string, unknown>;
    expect(Object.keys(b).filter((k) => k.startsWith('k')).length).toBe(3);
    expect(b.__truncated_keys__).toBe(7);
  });

  it('truncates large arrays', () => {
    const engine = new RedactionEngine({ includeBody: true, maxArrayLength: 3 });
    const { body } = engine.redactBody({ xs: [1, 2, 3, 4, 5] }, ['xs']);
    const b = body as { xs: unknown[] };
    expect(b.xs.length).toBe(4);
    expect(b.xs[3]).toMatch(/truncated/);
  });

  it('customFieldRedactor can override field redaction', () => {
    const engine = new RedactionEngine({
      includeBody: true,
      customFieldRedactor: (_key, value) => (value === 'p' ? '<<<masked>>>' : undefined),
    });
    const { body } = engine.redactBody({ password: 'p' }, ['password']);
    expect(body).toEqual({ password: '<<<masked>>>' });
  });

  it('allowList bypasses redaction for specified keys', () => {
    const engine = new RedactionEngine({ includeBody: true, bodyKeyAllowList: ['publicToken'] });
    const { body } = engine.redactBody({ publicToken: 'visible', password: 'p' }, [
      'publicToken',
      'password',
    ]);
    expect(body).toEqual({ publicToken: 'visible', password: '[REDACTED]' });
  });
});

describe('sensitive detection helpers', () => {
  it('isSensitiveHeader covers the standard set', () => {
    expect(isSensitiveHeader('authorization')).toBe(true);
    expect(isSensitiveHeader('cookie')).toBe(true);
    expect(isSensitiveHeader('x-api-key')).toBe(true);
    expect(isSensitiveHeader('accept')).toBe(false);
    expect(isSensitiveHeader('user-agent')).toBe(false);
  });
  it('isSensitiveQueryParam', () => {
    expect(isSensitiveQueryParam('token')).toBe(true);
    expect(isSensitiveQueryParam('api_key')).toBe(true);
    expect(isSensitiveQueryParam('q')).toBe(false);
  });
  it('isSensitiveBodyKey', () => {
    expect(isSensitiveBodyKey('password')).toBe(true);
    expect(isSensitiveBodyKey('clientSecret')).toBe(true);
    expect(isSensitiveBodyKey('access_token')).toBe(true);
    expect(isSensitiveBodyKey('email')).toBe(false);
  });
});

describe('attachAudit middleware', () => {
  let sink: InMemoryAuditSink;
  let port: number;
  let close: () => Promise<void>;

  beforeEach(async () => {
    sink = new InMemoryAuditSink();
    const app = express();
    app.use(express.json());
    app.use(attachAudit({ sink }));
    app.post('/login', (req, res) => {
      res.status(200).send('ok');
    });
    const l = await listen(app);
    port = l.port;
    close = l.close;
  });

  afterEach(async () => {
    await close();
  });

  it('emits exactly one intent.evaluated event per request', async () => {
    const r = await postJson(port, '/login', { email: 'a@b.c' });
    expect(r.status).toBe(200);
    await new Promise((r2) => setTimeout(r2, 20));
    const events = sink.all();
    expect(events.length).toBe(1);
    expect(events[0]!.type).toBe('intent.evaluated');
    expect(events[0]!.outcome).toBe('allow');
  });

  it('redacts authorization header end-to-end', async () => {
    await postJson(
      port,
      '/login',
      { email: 'a@b.c' },
      { authorization: 'Bearer secret.token.value' },
    );
    await new Promise((r) => setTimeout(r, 20));
    const e = sink.all()[0]!;
    expect(e.request.headers['authorization']).toBe('[REDACTED]');
    expect(JSON.stringify(e)).not.toContain('secret.token.value');
  });

  it('redacts cookie, x-api-key end-to-end', async () => {
    await postJson(port, '/login', {}, { cookie: 'sess=abc', 'x-api-key': 'live_xyz' });
    await new Promise((r) => setTimeout(r, 20));
    const e = sink.all()[0]!;
    expect(e.request.headers['cookie']).toBe('[REDACTED]');
    expect(e.request.headers['x-api-key']).toBe('[REDACTED]');
    expect(JSON.stringify(e)).not.toContain('live_xyz');
    expect(JSON.stringify(e)).not.toContain('sess=abc');
  });

  it('does NOT include body by default', async () => {
    await postJson(port, '/login', { password: 'hunter2', email: 'a@b.c' });
    await new Promise((r) => setTimeout(r, 20));
    const e = sink.all()[0]!;
    expect(e.request.body).toBeNull();
    expect(e.request.bodyKeys).toEqual(['email', 'password']);
    expect(JSON.stringify(e)).not.toContain('hunter2');
  });

  it('redacts body fields when includeBody=true', async () => {
    sink.clear();
    const app = express();
    app.use(express.json());
    app.use(attachAudit({ sink, includeBody: true }));
    app.post('/login', (_req, res) => res.status(200).send('ok'));
    const l = await listen(app);
    try {
      const r = await postJson(l.port, '/login', { email: 'a@b.c', password: 'hunter2' });
      expect(r.status).toBe(200);
      await new Promise((r2) => setTimeout(r2, 20));
      const e = sink.all()[0]!;
      expect(e.request.body).toEqual({ email: 'a@b.c', password: '[REDACTED]' });
      expect(JSON.stringify(e)).not.toContain('hunter2');
    } finally {
      await l.close();
    }
  });

  it('records request method, path, ip, status, duration', async () => {
    await postJson(port, '/login', { x: 1 });
    await new Promise((r) => setTimeout(r, 20));
    const e = sink.all()[0]!;
    expect(e.request.method).toBe('POST');
    expect(e.request.path).toBe('/login');
    expect(typeof e.request.ip).toBe('string');
    expect(e.response.status).toBe(200);
    expect(e.response.durationMs).toBeGreaterThanOrEqual(0);
  });

  it('uses decisionResolver for outcome / severity / type', async () => {
    sink.clear();
    const app = express();
    app.use(express.json());
    app.use(
      attachAudit({
        sink,
        decisionResolver: () => ({ kind: 'deny', severity: 'error', type: 'security.denied' }),
      }),
    );
    app.post('/x', (_req, res) => res.status(403).send('no'));
    const l = await listen(app);
    try {
      await postJson(l.port, '/x', { a: 1 });
      await new Promise((r) => setTimeout(r, 20));
      const e = sink.all()[0]!;
      expect(e.outcome).toBe('deny');
      expect(e.severity).toBe('error');
      expect(e.type).toBe('security.denied');
    } finally {
      await l.close();
    }
  });

  it('events are frozen', async () => {
    await postJson(port, '/login', { a: 1 });
    await new Promise((r) => setTimeout(r, 20));
    const e = sink.all()[0]!;
    expect(Object.isFrozen(e)).toBe(true);
    expect(() => {
      (e as unknown as { type: string }).type = 'hacked';
    }).toThrow();
  });

  it('null sink is a safe no-op (no errors)', async () => {
    const app = express();
    app.use(express.json());
    app.use(attachAudit({}));
    app.post('/x', (_req, res) => res.status(200).send('ok'));
    const l = await listen(app);
    try {
      const r = await postJson(l.port, '/x', { a: 1 });
      expect(r.status).toBe(200);
    } finally {
      await l.close();
    }
  });

  it('audit failure never breaks the response', async () => {
    const brokenSink: AuditSink = {
      name: 'broken',
      emit: () => {
        throw new Error('sink blew up');
      },
    };
    const app = express();
    app.use(express.json());
    app.use(attachAudit({ sink: brokenSink }));
    app.post('/x', (_req, res) => res.status(200).send('still ok'));
    const l = await listen(app);
    try {
      const r = await postJson(l.port, '/x', { a: 1 });
      expect(r.status).toBe(200);
    } finally {
      await l.close();
    }
  });

  it('InMemoryAuditSink supports byType / bySeverity / clear / size', () => {
    const s = new InMemoryAuditSink();
    s.emit(Object.freeze({ type: 'intent.evaluated', severity: 'debug' }) as unknown as AuditEvent);
    s.emit(Object.freeze({ type: 'security.denied', severity: 'error' }) as unknown as AuditEvent);
    expect(s.size()).toBe(2);
    expect(s.byType('security.denied').length).toBe(1);
    expect(s.bySeverity('error').length).toBe(1);
    s.clear();
    expect(s.size()).toBe(0);
  });

  it('ConsoleAuditSink JSON mode emits parseable JSON per line', async () => {
    const lines: string[] = [];
    const sink = new ConsoleAuditSink({ stream: { log: (l) => lines.push(l) } });
    const app = express();
    app.use(express.json());
    app.use(attachAudit({ sink, includeBody: true }));
    app.post('/c', (_req, res) => res.status(200).send('ok'));
    const l = await listen(app);
    try {
      await postJson(l.port, '/c', { email: 'a@b.c', password: 'p' });
      await new Promise((r) => setTimeout(r, 20));
      expect(lines.length).toBeGreaterThan(0);
      const parsed = JSON.parse(lines[lines.length - 1]!);
      expect(parsed.outcome).toBe('allow');
      expect(parsed.request.body.password).toBe('[REDACTED]');
      expect(lines.join('\n')).not.toContain('"p"');
    } finally {
      await l.close();
    }
  });
});

describe('default config & coverage', () => {
  it('exposes DEFAULT_REDACTION_CONFIG with includeBody=false', () => {
    expect(DEFAULT_REDACTION_CONFIG.includeBody).toBe(false);
  });
  it('covers all required redaction patterns', () => {
    for (const h of [
      'authorization',
      'cookie',
      'set-cookie',
      'x-api-key',
      'api-key',
      'x-auth-token',
      'x-csrf-token',
    ]) {
      expect(isSensitiveHeader(h)).toBe(true);
    }
    for (const q of ['token', 'api_key', 'password', 'secret', 'access_token', 'refresh_token']) {
      expect(isSensitiveQueryParam(q)).toBe(true);
    }
    for (const b of [
      'password',
      'secret',
      'token',
      'access_token',
      'apiKey',
      'authorization',
      'cookie',
      'credit_card',
      'ssn',
      'private_key',
    ]) {
      expect(isSensitiveBodyKey(b)).toBe(true);
    }
  });
});
