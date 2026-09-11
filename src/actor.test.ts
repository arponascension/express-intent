import { describe, it, expect } from 'vitest';
import express, { type Request } from 'express';
import request from 'supertest';

import { intent, getIntentContext } from './middleware.js';
import {
  defaultActorProvider,
  defaultActorExtractor,
  normalizeActor,
  resolveActor,
  anonymousActor,
  ANONYMOUS_ACTOR,
  type ActorProvider,
} from './actor.js';
import { MalformedActorError } from './errors.js';

describe('ActorProvider interface — defaults', () => {
  it('defaultActorProvider is the canonical ActorProvider', () => {
    expect(typeof defaultActorProvider).toBe('function');
  });

  it('defaultActorExtractor remains as a backward-compatible alias', () => {
    expect(defaultActorExtractor).toBe(defaultActorProvider);
  });

  it('returns ANONYMOUS_ACTOR when no headers / user are present', () => {
    const req = { headers: {} } as Request;
    const result = defaultActorProvider(req);
    expect(result).toBe(ANONYMOUS_ACTOR);
  });

  it('extracts subject from x-user-subject header', () => {
    const req = { headers: { 'x-user-subject': 'u-7' } } as unknown as Request;
    const result = defaultActorProvider(req) as { subject: string | null };
    expect(result.subject).toBe('u-7');
  });

  it('extracts subject from req.user.sub when present', () => {
    const req = { headers: {}, user: { sub: 'u-9', roles: ['admin'] } } as unknown as Request;
    const result = defaultActorProvider(req) as {
      subject: string | null;
      roles: ReadonlyArray<string>;
    };
    expect(result.subject).toBe('u-9');
    expect(result.roles).toEqual(['admin']);
  });
});

describe('anonymousActor() + ANONYMOUS_ACTOR — singleton contract', () => {
  it('anonymousActor() returns the same reference', () => {
    expect(anonymousActor()).toBe(ANONYMOUS_ACTOR);
  });

  it('ANONYMOUS_ACTOR is fully anonymous and frozen-shaped', () => {
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
});

describe('normalizeActor — happy paths', () => {
  it('null → anonymous actor with authRequirement stamped in', () => {
    expect(normalizeActor(null, 'required')).toEqual({
      ...ANONYMOUS_ACTOR,
      authRequirement: 'required',
    });
  });

  it('undefined → anonymous actor', () => {
    expect(normalizeActor(undefined, 'mfa-required')).toMatchObject({
      authenticated: false,
      authRequirement: 'mfa-required',
    });
  });

  it('ANONYMOUS_ACTOR reference → anonymous actor', () => {
    expect(normalizeActor(ANONYMOUS_ACTOR, 'required')).toEqual({
      ...ANONYMOUS_ACTOR,
      authRequirement: 'required',
    });
  });

  it('complete partial → fully-populated Actor', () => {
    const a = normalizeActor(
      {
        subject: 'u-1',
        authenticated: true,
        authMethod: 'oauth2',
        roles: ['admin', 'editor'],
        scopes: ['x', 'y'],
        claims: { tenant: 'acme' },
        authenticatedAt: 1700000000000,
      },
      'required',
    );
    expect(a).toEqual({
      subject: 'u-1',
      authenticated: true,
      authMethod: 'oauth2',
      authRequirement: 'required',
      roles: ['admin', 'editor'],
      scopes: ['x', 'y'],
      claims: { tenant: 'acme' },
      authenticatedAt: 1700000000000,
    });
  });

  it('fills missing optional fields with safe defaults', () => {
    const a = normalizeActor({ subject: 'u-2', authenticated: true }, 'required');
    expect(a.roles).toEqual([]);
    expect(a.scopes).toEqual([]);
    expect(a.claims).toEqual({});
    expect(a.authMethod).toBeNull();
    expect(a.authenticatedAt).toBeNull();
  });
});

describe('normalizeActor — malformed input throws MalformedActorError', () => {
  it('rejects non-object input', () => {
    expect(() => normalizeActor(42 as never, 'required')).toThrow(MalformedActorError);
    expect(() => normalizeActor('string' as never, 'required')).toThrow(MalformedActorError);
    expect(() => normalizeActor(true as never, 'required')).toThrow(MalformedActorError);
  });

  it('rejects when subject is not string or null', () => {
    expect(() => normalizeActor({ subject: 7, authenticated: true } as never, 'required')).toThrow(
      MalformedActorError,
    );
  });

  it('rejects when authenticated is missing', () => {
    expect(() => normalizeActor({ subject: 'u-1' } as never, 'required')).toThrow(
      MalformedActorError,
    );
  });

  it('rejects when authenticated is not boolean', () => {
    expect(() =>
      normalizeActor({ subject: 'u-1', authenticated: 'yes' } as never, 'required'),
    ).toThrow(MalformedActorError);
  });

  it('rejects when claims is not a plain object', () => {
    expect(() =>
      normalizeActor({ subject: 'u-1', authenticated: true, claims: 'no' } as never, 'required'),
    ).toThrow(MalformedActorError);
    expect(() =>
      normalizeActor({ subject: 'u-1', authenticated: true, claims: [1, 2] } as never, 'required'),
    ).toThrow(MalformedActorError);
  });

  it('rejects when authMethod is not string or null', () => {
    expect(() =>
      normalizeActor({ subject: 'u-1', authenticated: true, authMethod: 5 } as never, 'required'),
    ).toThrow(MalformedActorError);
  });

  it('rejects when authenticatedAt is not number or null', () => {
    expect(() =>
      normalizeActor(
        { subject: 'u-1', authenticated: true, authenticatedAt: 'yesterday' } as never,
        'required',
      ),
    ).toThrow(MalformedActorError);
  });

  it('error carries the source for diagnostics', () => {
    try {
      normalizeActor(7 as never, 'required', 'my-jwt-extractor');
      throw new Error('unreachable');
    } catch (e) {
      expect(e).toBeInstanceOf(MalformedActorError);
      expect((e as MalformedActorError).source).toBe('my-jwt-extractor');
      expect((e as Error).message).toContain('my-jwt-extractor');
    }
  });
});

describe('resolveActor — synchronous provider', () => {
  const req = {} as Request;

  it('returns frozen anonymous actor for null/undefined', async () => {
    const a = await resolveActor(req, () => null, { requirement: 'required' });
    expect(a).toEqual({ ...ANONYMOUS_ACTOR, authRequirement: 'required' });
    expect(Object.isFrozen(a.roles)).toBe(true);
    expect(Object.isFrozen(a.scopes)).toBe(true);
    expect(Object.isFrozen(a.claims)).toBe(true);
  });

  it('normalizes and returns a populated Actor', async () => {
    const provider: ActorProvider = () => ({
      subject: 'u-1',
      authenticated: true,
      authMethod: 'passkey',
      roles: ['admin'],
      scopes: [],
      claims: { tier: 'gold' },
      authenticatedAt: 100,
    });
    const a = await resolveActor(req, provider, { requirement: 'mfa-required' });
    expect(a.subject).toBe('u-1');
    expect(a.authRequirement).toBe('mfa-required');
    expect(a.authMethod).toBe('passkey');
  });

  it('forwards malformed shape → throws MalformedActorError', async () => {
    const provider: ActorProvider = () => ({ subject: 9, authenticated: true }) as never;
    await expect(resolveActor(req, provider, { requirement: 'required' })).rejects.toThrow(
      MalformedActorError,
    );
  });
});

describe('resolveActor — asynchronous provider', () => {
  const req = {} as Request;

  it('awaits a Promise<ActorLike>', async () => {
    const provider: ActorProvider = async () => ({
      subject: 'u-async',
      authenticated: true,
    });
    const a = await resolveActor(req, provider, { requirement: 'required' });
    expect(a.subject).toBe('u-async');
  });

  it('awaits a Promise<AnonymousActor | null>', async () => {
    const provider: ActorProvider = async () => null;
    const a = await resolveActor(req, provider, { requirement: 'required' });
    expect(a.authenticated).toBe(false);
  });

  it('forwards errors thrown by provider', async () => {
    const provider: ActorProvider = async () => {
      throw new Error('jwt verification failed');
    };
    await expect(resolveActor(req, provider, { requirement: 'required' })).rejects.toThrow(
      'jwt verification failed',
    );
  });
});

describe('resolveActor — timeout fallback', () => {
  const req = {} as Request;

  it('falls back to anonymous actor when provider exceeds timeoutMs', async () => {
    const provider: ActorProvider = () =>
      new Promise((resolve) => {
        setTimeout(() => resolve({ subject: 'too-late', authenticated: true }), 200);
      });
    const a = await resolveActor(req, provider, { requirement: 'required', timeoutMs: 20 });
    expect(a.authenticated).toBe(false);
    expect(a.authRequirement).toBe('required');
  });

  it('completes fast providers within timeoutMs', async () => {
    const provider: ActorProvider = async () => ({ subject: 'u-fast', authenticated: true });
    const a = await resolveActor(req, provider, { requirement: 'required', timeoutMs: 100 });
    expect(a.subject).toBe('u-fast');
  });

  it('default timeoutMs is short and safe', async () => {
    const provider: ActorProvider = () =>
      new Promise((resolve) => {
        setTimeout(() => resolve({ subject: 'x', authenticated: true }), 5000);
      });
    const start = Date.now();
    const a = await resolveActor(req, provider, { requirement: 'required' });
    const elapsed = Date.now() - start;
    expect(a.authenticated).toBe(false);
    expect(elapsed).toBeLessThan(200);
  });
});

describe('intent() middleware — actor integration', () => {
  function buildApp(provider?: ActorProvider) {
    const app = express();
    app.use(intent({ action: 'users.read', actor: provider, timeoutMs: 50 }));
    app.get('/me', (req, res) => {
      res.json({
        subject: req.intent!.context.actor.subject,
        authenticated: req.intent!.context.actor.authenticated,
        authRequirement: req.intent!.context.actor.authRequirement,
        alsSubject: getIntentContext()?.actor.subject ?? null,
      });
    });
    return app;
  }

  it('integrates a custom authenticated provider', async () => {
    const provider: ActorProvider = (req) => {
      const sub = (req.headers['x-test-user'] as string | undefined) ?? null;
      if (sub === null) return null;
      return {
        subject: sub,
        authenticated: true,
        authMethod: 'oauth2',
        roles: ['user'],
        scopes: [],
      };
    };
    const r = await request(buildApp(provider)).get('/me').set('x-test-user', 'alice');
    expect(r.status).toBe(200);
    expect(r.body).toEqual({
      subject: 'alice',
      authenticated: true,
      authRequirement: 'required',
      alsSubject: 'alice',
    });
  });

  it('integrates an anonymous request when provider returns null', async () => {
    const provider: ActorProvider = () => null;
    const r = await request(buildApp(provider)).get('/me');
    expect(r.body.subject).toBeNull();
    expect(r.body.authenticated).toBe(false);
    expect(r.body.alsSubject).toBeNull();
  });

  it('integrates an asynchronous provider (JWT-style)', async () => {
    const provider: ActorProvider = async (req) => {
      const token = req.headers.authorization as string | undefined;
      if (!token || !token.startsWith('Bearer ')) return null;
      await new Promise((r) => setTimeout(r, 5));
      return {
        subject: 'jwt-user',
        authenticated: true,
        authMethod: 'oauth2',
        roles: ['admin'],
        scopes: ['read', 'write'],
      };
    };
    const r = await request(buildApp(provider))
      .get('/me')
      .set('authorization', 'Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig');
    expect(r.body.subject).toBe('jwt-user');
    expect(r.body.authenticated).toBe(true);
  });

  it('falls back to anonymous on provider timeout', async () => {
    const provider: ActorProvider = async () => {
      await new Promise((r) => setTimeout(r, 200));
      return { subject: 'too-late', authenticated: true };
    };
    const r = await request(buildApp(provider)).get('/me');
    expect(r.body.authenticated).toBe(false);
    expect(r.body.subject).toBeNull();
  });

  it('falls back to anonymous when no provider is configured', async () => {
    const app = express();
    app.use(intent({ action: 'users.read' }));
    app.get('/me', (req, res) => {
      res.json({
        subject: req.intent!.context.actor.subject,
        authenticated: req.intent!.context.actor.authenticated,
      });
    });
    const r = await request(app).get('/me');
    expect(r.body.subject).toBeNull();
    expect(r.body.authenticated).toBe(false);
  });

  it('propagates malformed provider error to error middleware', async () => {
    const provider: ActorProvider = () => ({ subject: 7, authenticated: true }) as never;
    const app = express();
    app.use(intent({ action: 'users.read', actor: provider }));
    app.use((err: Error, _req: Request, res: express.Response, _next: express.NextFunction) => {
      res.status(500).json({ name: err.name, message: err.message });
    });
    app.get('/me', (_req, res) => res.json({ ok: true }));
    const r = await request(app).get('/me');
    expect(r.status).toBe(500);
    expect(r.body.name).toBe('MalformedActorError');
  });

  it('sync provider returning null is treated as anonymous (no error)', async () => {
    const provider: ActorProvider = () => null;
    const r = await request(buildApp(provider)).get('/me');
    expect(r.status).toBe(200);
    expect(r.body.authenticated).toBe(false);
  });

  it('IntentContext.actor is always populated (never undefined)', async () => {
    const provider: ActorProvider = () => null;
    const r = await request(buildApp(provider)).get('/me');
    expect(r.body.subject).toBeDefined();
    expect(typeof r.body.authenticated).toBe('boolean');
  });
});

describe('resolveActor — defaultActorProvider wired in', () => {
  const req = { headers: { 'x-user-subject': 'u-w' } } as unknown as Request;

  it('defaultActorProvider is a valid ActorProvider for resolveActor', async () => {
    const a = await resolveActor(req, defaultActorProvider, { requirement: 'required' });
    expect(a.subject).toBe('u-w');
    expect(a.authenticated).toBe(true);
  });

  it('defaultActorProvider returns anonymous for headerless requests', async () => {
    const r = { headers: {} } as unknown as Request;
    const a = await resolveActor(r, defaultActorProvider, { requirement: 'required' });
    expect(a.authenticated).toBe(false);
  });
});
