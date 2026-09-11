# express-intent

Express middleware that converts API intent declarations into runtime decisions (`allow`, `monitor`, `challenge`, `deny`).

`express-intent` is a pre-1.0 package (`0.0.0`). The public API is actively being simplified; expect breaking changes between minor releases.

## Install

```bash
npm install express-intent
```

Requires Node.js ≥ 20 and Express 4 or 5.

## Quick start

Declare an intent with a dotted action name and let the middleware attach a rich per-request context to `req.intent`:

```ts
import express from 'express';
import { intent } from 'express-intent';

const app = express();
app.use(express.json());

app.use(intent('users.read'));

app.get('/users/:id', (req, res) => {
  const { action, context, decision, requestId } = req.intent!;
  res.json({
    action,
    requestId,
    actorSubject: context.actor.subject,
    allowed: decision.kind === 'allow',
  });
});
```

`intent()` never blocks a request unless you ask it to. See [Enforcement](#enforcement).

## Creating the middleware

The `intent()` factory accepts three identical shapes:

```ts
// 1. Action string + options
intent('payment.create', { enforce: true });

// 2. A pre-built Intent (normalized contract) + options
import { defineIntent } from 'express-intent';
intent(defineIntent('payment.create', { mutation: 'create', auth: 'required' }), { enforce: true });

// 3. Options object with the action inline
intent({ action: 'payment.create', enforce: true });
```

Use `defineAction('payment.create', opts)` when you want to reuse a configured action across routes without a string-configured copy:

```ts
import { defineAction, intent } from 'express-intent';

const createPayment = defineAction('payment.create', { mutation: 'create' });

app.post('/payments', intent(createPayment, { enforce: true }));
```

### Intent options

| option          | type                                              | default    | purpose                              |
| --------------- | ------------------------------------------------- | ---------- | ------------------------------------ |
| `auth`          | `anonymous \| required \| mfa-required`           | `required` | minimum authentication level         |
| `sensitivity`   | `public \| internal \| pii \| critical`           | `internal` | data class of the intent             |
| `mutation`      | `none \| read \| create \| update \| destructive` | `read`     | whether/how the intent mutates state |
| `velocity`      | `{ window, max, per }`                            | `null`     | rate hints                           |
| `anomaly`       | `{ threshold, window }`                           | `null`     | anomaly hints                        |
| `authFreshness` | `{ maxAgeMs, requiredMethods? }`                  | `null`     | stale-auth hints                     |
| `quotas`        | `Array<{ per, window, max }>`                     | `[]`       | quota hints                          |
| `tags`          | `string[]`                                        | `[]`       | free-form tags                       |

## What gets attached: `req.intent`

```ts
interface IntentPayload {
  requestId: string; // Crockford-base32, unique per request
  action: string; // dotted action name (canonical identifier)
  context: IntentContext; // frozen snapshot of request + intent + actor
  decision: Decision; // { kind: 'allow' | 'monitor' | 'rate_limit' | 'challenge' | 'deny', ... }
  startedAt: number;
  actor: Actor; // === context.actor
  isAllowed: boolean; // === decision.kind === 'allow'
  isDenied: boolean; // === decision.kind === 'deny'
}
```

`req.intent` is added to the Express `Request` type via module augmentation on `express-serve-static-core`, so it is fully typed without extra setup.

### `IntentContext`

`IntentContext` is deeply `Object.freeze`-d and captures the request at middleware time:

```ts
interface IntentContext {
  requestId: string;
  intent: Intent;
  actor: Actor;
  method: string;
  path: string;
  ip: string | null;
  headers: Readonly<Record<string, string>>;
  params: Readonly<Record<string, string>>; // lazy: resolved by the router by the time a handler reads it
  query: Readonly<Record<string, string>>;
  bodyShapeHash: string | null; // stable hash of the JSON body shape, not the values
  receivedAt: number;
  extras: Readonly<Record<string, unknown>>;
}
```

## Actors

The `actor` on every context has a subject (or `null` for anonymous), `authenticated`, `authMethod`, `roles`, `scopes`, `claims`, and `authRequirement`.

By default the actor provider reads `x-user-subject`, falls back to `req.user.sub`, and otherwise returns an anonymous actor.

Custom provider:

```ts
import { intent } from 'express-intent';
import type { ActorProvider } from 'express-intent';

const provider: ActorProvider = async (req) => {
  const token = req.headers.authorization;
  if (!token) return null; // anonymous
  const user = await yourVerifyToken(token);
  return {
    subject: user.id,
    authenticated: true,
    authMethod: 'oauth2',
    roles: user.roles,
    scopes: [],
    claims: {},
  };
};

app.use(intent({ action: 'payment.create', actor: provider, enforce: true }));
```

A provider may be async. Use `resolveActor(req, provider, opts)` to reuse resolution outside middleware.

## Enforcement

Enforcement is off by default. Enable it with `enforce: true`, `policies`, or a `decisionEngine`; the middleware then short-circuits non-`allow` decisions with an HTTP response:

| decision     | response                                                    |
| ------------ | ----------------------------------------------------------- |
| `deny`       | `401` or the decision's `status` (default `403`), JSON body |
| `challenge`  | `401` with `{ challenge: 'mfa', ... }`                      |
| `rate_limit` | `429` with `Retry-After`                                    |

Tune the response with `onDeny`, `onChallenge`, `onRateLimit`, or `throwOnDeny` (forwards an `IntentDeniedError` to Express error middleware).

The built-in enforce path checks `auth` versus the actor (`required`/`mfa-required`) plus destructive mutations, then runs the risk decision engine (`evaluateDecision`).

## Policies

Policies are declarative rules with `when` conditions and `then` effects:

```ts
import { intent, definePolicy, when, policyDeny, policyMonitor } from 'express-intent';

const blockAdminDeletes = definePolicy({
  id: 'no-admin-ops-destructive',
  version: 1,
  when: { kind: 'action', pattern: '*.delete' },
  then: { decision: policyDeny('destructive ops are admin-only', 403) },
});

app.use(intent({ action: 'users.delete', policies: [blockAdminDeletes] }));
```

Policy effects are built by `policyAllow`, `policyDeny`, `policyMonitor`, `policyChallenge`, `policyRateLimit`. Evaluate a policy set standalone with `evaluatePolicies` and the `toBuiltPolicy`/`compilePolicy` helpers.

## Working outside handlers

Middleware runs handlers (including async ones) inside an `AsyncLocalStorage` scope so you can read request context anywhere downstream without passing `req` around:

```ts
import { getIntentContext } from 'express-intent';

export function auditLog() {
  const ctx = getIntentContext();
  return { requestId: ctx?.requestId, action: ctx?.intent.key, subject: ctx?.actor.subject };
}
```

- `getIntentContext(req?)` — the live `IntentContext` (from `req.intent.context` when a request is passed, otherwise from ALS).
- `getRequestSnapshot()` — a lightweight `{ requestId, action, actorSubject, startedAt }` derived from the stored context.
- `runWithRequest(context, fn)` — run `fn` inside a scope with a caller-supplied `IntentContext`.
- `generateRequestId()` — the Crockford-base32 id generator used per request.
- `buildRequestContext(req, options)` — build an `IntentContext` for a request outside middleware.

## Rate limiting

A standalone sliding-window in-memory limiter plus the decision helper:

```ts
import { InMemoryRateLimiter, rateLimit } from 'express-intent';

const limiter = new InMemoryRateLimiter();

const result = await limiter.consume({
  namespace: 'default',
  max: 10,
  windowMs: 60_000,
  scope: 'ip',
  ip: '1.2.3.4',
  action: 'payment.create',
});
const decision = result.allowed
  ? { kind: 'allow' }
  : rateLimit({
      reason: 'too fast',
      limit: result.limit,
      remaining: 0,
      retryAfterMs: result.retryAfterMs,
      scope: 'ip',
    });
```

## Audit

`attachAudit` writes an `AuditEvent` per request to a sink when the response finishes (or closes):

```ts
import { attachAudit, InMemoryAuditSink } from 'express-intent';

app.use(attachAudit({ sink: new InMemoryAuditSink() }));
```

`ConsoleAuditSink` prints human-readable events; `NullAuditSink` is the default. `RedactionEngine` + `isSensitiveHeader/QueryParam/BodyKey` strip secrets before events are emitted.

## Idempotency

Replay protection for mutating routes:

```ts
import { idempotency, InMemoryIdempotencyProvider } from 'express-intent';

const provider = new InMemoryIdempotencyProvider({ ttlMs: 24 * 60 * 60_000 });
app.post('/charge', idempotency({ provider }), handler);
```

Replays of the same `Idempotency-Key` return the original response; concurrent duplicates are single-flighted. `createIdempotencyMiddleware` is the long-form alias.

## Subpath modules

Optional integrations live behind their own entry points so core users don't pay for them:

### `express-intent/metrics`

Prometheus-compatible counters/gauges/histograms with a cardinality guard and a no-crash default provider:

```ts
import { createPrometheusMetricsProvider, CoreMetrics } from 'express-intent/metrics';
```

### `express-intent/redis`

Redis-backed implementations of the core stores and rate/idempotency primitives. Requires `ioredis` (peer):

```ts
import {
  RedisRateLimiter,
  RedisSignalStore,
  RedisObservationStore,
  RedisIdempotencyProvider,
  InMemoryRedisAdapter,
} from 'express-intent/redis';
```

### `express-intent/otel`

OpenTelemetry span recording with an optional `@opentelemetry/api` peer:

```ts
import { createOTelTelemetry, OTelSpanRecorder, AttributeRedactor } from 'express-intent/otel';
```

## Errors

- `IntentError` — base class, thrown by `getIntent` when a route is missing intent context.
- `IntentValidationError` — invalid actions or intent options.
- `IntentDeniedError` — used by `throwOnDeny`.
- `MalformedActorError` — an actor provider returned an invalid actor.

## TypeScript

The package ships `*.d.ts` for ESM and CJS and augments the Express `Request` type via `declare module 'express-serve-static-core'`, so `req.intent` and `req.intent.context` are typed without extra setup.
