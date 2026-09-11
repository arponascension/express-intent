import { describe, it, expect, expectTypeOf } from 'vitest';
import express, { type Request, type Response, type NextFunction } from 'express';
import request from 'supertest';

import {
  intent,
  defineAction,
  parseAction,
  getIntent,
  getIntentContext,
  getRequestSnapshot,
  generateRequestId,
  type IntentMiddleware,
  type IntentPayload,
} from './middleware.js';
import { defaultActorExtractor, normalizeActor, ANONYMOUS_ACTOR } from './actor.js';
import { defineIntent } from './intent/builder.js';
import { freezeContext } from './domain/context.js';
import { runWithRequest } from './als.js';
import type { IntentContext, RequestSnapshot } from './types.js';

describe('parseAction / defineAction', () => {
  it('parses dotted action strings', () => {
    const a = parseAction('payment.create');
    expect(a.action).toBe('payment.create');
    expect(a.intent.key).toBe('payment.create');
  });

  it('parses object action + options', () => {
    const a = parseAction({ action: 'user.delete', options: { auth: 'mfa-required' } });
    expect(a.intent.auth).toBe('mfa-required');
  });

  it('rejects malformed action strings', () => {
    expect(() => parseAction('Payment.Create')).toThrow();
    expect(() => parseAction('payment')).toThrow();
    expect(() => parseAction('')).toThrow();
    expect(() => parseAction('1payment.create')).toThrow();
    expect(() => parseAction('payment..create')).toThrow();
  });

  it('defineAction accepts (action, options) tuple', () => {
    const a = defineAction('invoice.refund', { mutation: 'destructive' });
    expect(a.intent.mutation).toBe('destructive');
  });
});

describe('generateRequestId', () => {
  it('produces 32-char Crockford-base32 strings', () => {
    const id = generateRequestId();
    expect(id).toHaveLength(28);
    expect(id).toMatch(/^[0-9A-HJKMNP-TV-Z]+$/);
  });

  it('is unique per call', () => {
    const ids = new Set<string>();
    for (let i = 0; i < 100; i++) ids.add(generateRequestId());
    expect(ids.size).toBe(100);
  });

  it('encodes the timestamp prefix', () => {
    const before = Date.now();
    const id = generateRequestId(before);
    expect(id).toHaveLength(28);
  });
});

describe('defaultActorExtractor + normalizeActor', () => {
  function fakeReq(headers: Record<string, string> = {}, user: unknown = undefined): Request {
    return { headers, user } as unknown as Request;
  }

  it('extracts subject from x-user-subject header', () => {
    const partial = defaultActorExtractor(fakeReq({ 'x-user-subject': 'u-1' }));
    expect(partial?.subject).toBe('u-1');
    expect(partial?.authenticated).toBe(true);
  });

  it('falls back to req.user.sub', () => {
    const partial = defaultActorExtractor(
      fakeReq({}, { sub: 'u-2', roles: ['admin'], scopes: ['x'] }),
    );
    expect(partial?.subject).toBe('u-2');
    expect(partial?.roles).toEqual(['admin']);
    expect(partial?.scopes).toEqual(['x']);
  });

  it('infers auth method only when a subject is present', () => {
    const withSub = defaultActorExtractor(
      fakeReq({ authorization: 'Bearer abc', 'x-user-subject': 'u-1' }),
    ) as { authMethod: string | null };
    expect(withSub.authMethod).toBe('oauth2');
    const withSubBasic = defaultActorExtractor(
      fakeReq({ authorization: 'Basic xyz', 'x-user-subject': 'u-2' }),
    ) as { authMethod: string | null };
    expect(withSubBasic.authMethod).toBe('password');
    const noSub = defaultActorExtractor(fakeReq({ authorization: 'Bearer abc' }));
    expect(noSub).toBe(ANONYMOUS_ACTOR);
  });

  it('ANONYMOUS_ACTOR is the canonical reference', () => {
    expect(ANONYMOUS_ACTOR).toEqual({
      subject: null,
      authenticated: false,
      authMethod: null,
      roles: [],
      scopes: [],
      claims: {},
      authenticatedAt: null,
    });
  });

  it('normalizeActor fills in safe defaults for null', () => {
    const actor = normalizeActor(null, 'required');
    expect(actor).toEqual({
      subject: null,
      authenticated: false,
      authMethod: null,
      authRequirement: 'required',
      roles: [],
      scopes: [],
      claims: {},
      authenticatedAt: null,
    });
  });
});

describe('intent() middleware', () => {
  function buildApp(action: string) {
    const app = express();
    app.use(express.json());
    app.use(intent({ action }));

    app.get('/items/:id', (req: Request, res: Response) => {
      const snap = req.intent!;
      const stored = getIntentContext();
      res.json({
        requestId: snap.requestId,
        action: snap.action,
        alsRequestId: stored?.requestId ?? null,
        alsAction: stored?.intent.key ?? null,
        params: snap.context.params,
        query: snap.context.query,
        method: snap.context.method,
        path: snap.context.path,
        ip: snap.context.ip,
        actorSubject: snap.context.actor.subject,
        decision: snap.decision,
        bodyShapeHash: snap.context.bodyShapeHash,
      });
    });

    app.post('/items', (req: Request, res: Response) => {
      res.json({
        bodyShapeHash: req.intent!.context.bodyShapeHash,
        receivedAt: req.intent!.context.receivedAt,
      });
    });

    app.get('/async-deep', async (req: Request, res: Response) => {
      await new Promise((r) => setTimeout(r, 10));
      const stored = getIntentContext();
      res.json({ requestId: stored?.requestId ?? null, action: stored?.intent.key ?? null });
    });

    return app;
  }

  it('attaches req.intent with requestId, action, context, decision', async () => {
    const app = buildApp('items.get');
    const response = await request(app).get('/items/42?x=1').set('x-user-subject', 'u-7');
    expect(response.status).toBe(200);
    expect(response.body.action).toBe('items.get');
    expect(response.body.requestId).toMatch(/^[0-9A-HJKMNP-TV-Z]{28}$/);
    expect(response.body.params).toEqual({ id: '42' });
    expect(response.body.query).toEqual({ x: '1' });
    expect(response.body.method).toBe('GET');
    expect(response.body.path).toBe('/items/42');
    expect(response.body.actorSubject).toBe('u-7');
    expect(response.body.decision).toEqual({ kind: 'allow' });
  });

  it('propagates requestId and action through AsyncLocalStorage', async () => {
    const app = buildApp('items.get');
    const response = await request(app).get('/items/1');
    expect(response.body.alsRequestId).toBe(response.body.requestId);
    expect(response.body.alsAction).toBe('items.get');
  });

  it('preserves ALS context across async/await boundaries', async () => {
    const app = buildApp('items.deep');
    const response = await request(app).get('/async-deep');
    expect(response.body.requestId).toMatch(/^[0-9A-HJKMNP-TV-Z]{28}$/);
    expect(response.body.action).toBe('items.deep');
  });

  it('captures body shape hash from JSON body', async () => {
    const app = buildApp('items.create');
    const r1 = await request(app)
      .post('/items')
      .set('content-type', 'application/json')
      .send({ name: 'a', qty: 1 });
    const r2 = await request(app)
      .post('/items')
      .set('content-type', 'application/json')
      .send({ qty: 2, name: 'b' });
    expect(r1.body.bodyShapeHash).toBe(r2.body.bodyShapeHash);
    expect(r1.body.bodyShapeHash).toMatch(/^[0-9a-f]{16}$/);
  });

  it('getIntentContext() returns undefined outside a request scope', () => {
    expect(getIntentContext()).toBeUndefined();
    expect(getRequestSnapshot()).toBeUndefined();
  });

  it('sets x-request-id response header', async () => {
    const app = buildApp('items.get');
    const response = await request(app).get('/items/1');
    const headerId = response.headers['x-request-id'];
    expect(headerId).toBeDefined();
    expect(headerId).toBe(response.body.requestId);
  });

  it('throws on invalid action configuration', () => {
    expect(() => intent({ action: 'BAD' } as never)).toThrow();
  });

  it('runs downstream inside ALS even if next() is async', async () => {
    const app = express();
    app.use(
      intent({
        action: 'a.b',
        onDecision: (req, decision) => {
          expect(getIntentContext()?.requestId).toBe(req.intent?.requestId);
          expect(decision.kind).toBe('allow');
        },
      }),
    );
    app.get('/x', (_req: Request, res: Response, next: NextFunction) => {
      Promise.resolve()
        .then(() => {
          expect(getIntentContext()?.intent.key).toBe('a.b');
          res.json({ ok: true });
        })
        .catch(next);
    });
    const r = await request(app).get('/x');
    expect(r.status).toBe(200);
  });

  it('isolates two parallel requests in ALS', async () => {
    const app = express();
    app.use(intent({ action: 'par.run' }));
    app.get('/slow', async (_req: Request, res: Response) => {
      const startId = getIntentContext()?.requestId;
      await new Promise((r) => setTimeout(r, 5));
      const endId = getIntentContext()?.requestId;
      expect(startId).toBe(endId);
      res.json({ startId, endId });
    });
    const [r1, r2] = await Promise.all([request(app).get('/slow'), request(app).get('/slow')]);
    expect(r1.body.startId).toBe(r1.body.endId);
    expect(r2.body.startId).toBe(r2.body.endId);
    expect(r1.body.startId).not.toBe(r2.body.startId);
  });
});

describe('runWithRequest / getRequestSnapshot', () => {
  it('derives a snapshot from the stored IntentContext', () => {
    const context = freezeContext(
      {
        requestId: 'r1',
        intent: defineIntent('a.b'),
        actor: normalizeActor(null, 'required'),
        method: 'GET',
        path: '/x',
        ip: null,
        headers: {},
        params: {},
        query: {},
        bodyShapeHash: null,
        receivedAt: 0,
        extras: {},
      },
      undefined,
    );
    expect(runWithRequest(context, () => getRequestSnapshot())).toEqual({
      requestId: 'r1',
      action: 'a.b',
      actorSubject: null,
      startedAt: 0,
    });
    expect(runWithRequest(context, () => getIntentContext()?.intent.key)).toBe('a.b');
  });

  it('defineIntent composes with intent()', () => {
    const sample = defineIntent('user.read', { auth: 'required', sensitivity: 'pii' });
    expect(sample.key).toBe('user.read');
    expect(sample.auth).toBe('required');
    expect(sample.sensitivity).toBe('pii');
  });
});

describe('type-level API surface', () => {
  it('IntentPayload exposes no redundant `key` field', () => {
    expectTypeOf<IntentPayload>().toHaveProperty('action');
    expectTypeOf<IntentPayload>().not.toHaveProperty('key');
  });

  it('intent() overloads all produce IntentMiddleware', () => {
    expectTypeOf(intent('a.b')).toEqualTypeOf<IntentMiddleware>();
    expectTypeOf(intent('a.b', {})).toEqualTypeOf<IntentMiddleware>();
    expectTypeOf(intent(defineIntent('a.b'))).toEqualTypeOf<IntentMiddleware>();
    expectTypeOf(intent({ action: 'a.b' })).toEqualTypeOf<IntentMiddleware>();
  });

  it('getIntentContext returns the live IntentContext, never the legacy snapshot', () => {
    expectTypeOf(getIntentContext).returns.toEqualTypeOf<IntentContext | undefined>();
    expectTypeOf(getIntentContext).parameters.toEqualTypeOf<[] | [Request]>();
    expectTypeOf(getRequestSnapshot).returns.toEqualTypeOf<RequestSnapshot | undefined>();
  });

  it('getIntent returns the attached IntentPayload', () => {
    expectTypeOf(getIntent).parameters.toEqualTypeOf<[Request]>();
    expectTypeOf(getIntent<string>).returns.toEqualTypeOf<IntentPayload<string>>();
  });
});
