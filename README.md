<div align="center">

# 🎯 express-intent

### Intent-aware authorization, security, and observability middleware for Express.js

**Turn a one-line API intent declaration into real runtime decisions — `allow`, `monitor`, `rate_limit`, `challenge`, `deny` — with policy enforcement, risk scoring, anomaly detection, rate limiting, idempotency, audit logging, Redis backends, Prometheus metrics, and OpenTelemetry tracing.**

[![npm version](https://img.shields.io/npm/v/express-intent?color=cb3837&label=npm)](https://www.npmjs.com/package/express-intent)
[![npm downloads](https://img.shields.io/npm/dw/express-intent.svg)](https://www.npmjs.com/package/express-intent)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Node.js](https://img.shields.io/badge/node-%3E%3D%2020-brightgreen.svg)](package.json)
[![Express 4 | 5](https://img.shields.io/badge/express-4%20%7C%205-orange.svg)](package.json)
[![TypeScript](https://img.shields.io/badge/types-TypeScript-blue.svg)](package.json)
[![PRs welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](https://github.com/arponascension/express-intent)
[![github status](https://img.shields.io/github/stars/arponascension/express-intent?label=GitHub&style=social)](https://github.com/arponascension/express-intent)

*Declarative intent. Runtime decisions. Zero-guess security for Node.js APIs.*

</div>

---

## Contents

- [What is express-intent?](#what-is-express-intent)
- [Features](#features)
- [Installation](#installation)
- [Quick start](#quick-start)
- [How it works: intent → decision](#how-it-works-intent--decision)
- [Creating the middleware](#creating-the-middleware)
- [Intent options](#intent-options)
- [What gets attached: `req.intent`](#what-gets-attached-reqintent)
- [Actors: who is calling](#actors-who-is-calling)
- [Enforcement: allow, challenge, rate-limit, deny](#enforcement-allow-challenge-rate-limit-deny)
- [Policies: declarative rules](#policies-declarative-rules)
- [Risk: weighted signal scoring](#risk-weighted-signal-scoring)
- [Anomaly detection](#anomaly-detection)
- [Rate limiting](#rate-limiting)
- [Idempotency](#idempotency)
- [Audit logging](#audit-logging)
- [Working outside handlers (AsyncLocalStorage)](#working-outside-handlers-asynclocalstorage)
- [Metrics: Prometheus-ready](#metrics-prometheus-ready)
- [Redis backends](#redis-backends)
- [OpenTelemetry](#opentelemetry)
- [Redaction engine](#redaction-engine)
- [Errors](#errors)
- [Performance](#performance)
- [TypeScript](#typescript)
- [Comparison: express-intent vs alternatives](#comparison-express-intent-vs-alternatives)
- [Use cases](#use-cases)
- [Design goals & non-goals](#design-goals--non-goals)
- [Roadmap](#roadmap)
- [License](#license)

---

## What is express-intent?

`express-intent` is an Express middleware library that gives every route a **declarative, machine-readable intent** (e.g. `users.read`, `payment.create`) and then **enforces what happens at runtime**. Instead of hand-wiring `req.user` checks, rate-limit buckets, audit hooks, and challenge flows in each handler, you declare the intent once and let the middleware produce a rich, typed decision for every request.

The core loop is simple:

```text
API intent declaration  →   runtime decision  →   action
users.read                    allow               →  proceed
payment.create                monitor             →  proceed + watch
users.login                   challenge           →  require MFA
admin.delete                  deny                →  403 Forbidden
```

The decision engine is the single source of truth. Everything else — enforcement, policies, risk scoring, anomaly detection, rate limiting, idempotency, audit, metrics, tracing — plugs into it without touching your route code.

**Version note:** Current release is `0.1.0`. The public API is being actively simplified, so expect disciplined breaking changes between minor releases — nothing is silently dropped, and everything is documented here.

---

## Features

| Area | What you get |
| ---- | ------------ |
| 🧠 **Intent declarations** | Dotted action names (`payment.create`), typed options, reusable `defineAction` contracts |
| ⚖️ **Decision engine** | Deterministic `allow / monitor / rate_limit / challenge / deny` from risk score, auth requirement, mutation class, and hard rules |
| 🚦 **Enforcement** | Mount-and-forget `401 / 403 / 429` responses, `onDeny` / `onChallenge` / `onRateLimit` hooks, `throwOnDeny` for error middleware |
| 📜 **Policy engine** | Declarative `when → then` rules with 20+ typed conditions, glob action patterns, boolean logic (`and` / `or` / `not`), evaluation traces |
| 📊 **Risk scoring** | Weighted, normalizable, decaying risk signals (`evaluateRisk`) with full breakdown and severity classification |
| 🕵️ **Anomaly detection** | Built-in detectors: velocity, enumeration, user-agent change, IP change, endpoint pattern; pluggable via `AnomalyEngine` |
| ⏱️ **Rate limiting** | In-memory sliding-window limiter + decision helper; Redis-backed `RedisRateLimiter` for shared state |
| 🔁 **Idempotency** | First-class `Idempotency-Key` replay protection, single-flight concurrency, in-memory or Redis providers |
| 📝 **Audit logging** | `AuditEvent` per request with redaction, plugin sinks (`InMemory`, `Console`, `Null`), never throws |
| 🔐 **Redaction** | `RedactionEngine` strips `authorization`, passwords, tokens, PII from headers, query params, and body keys |
| 📈 **Metrics** | Prometheus text-format via `express-intent/metrics` with cardinality guards and safe no-crash providers |
| 🛰️ **OpenTelemetry** | Optional span recording / tracing bridge via `express-intent/otel` |
| 💾 **Redis backends** | Adapter-based stores for rate limits, signals, observations, and idempotency — all behind one interface |
| 🧵 **Async context** | `AsyncLocalStorage`-backed request context readable anywhere downstream without passing `req` |

---

## Installation

```bash
npm install express-intent
```

**Requirements**
- Node.js `>= 20`
- Express `^4.18.0` **or** `^5.0.0` (optional peer dependency)

**Module format:** ships ESM (`import`) and CommonJS (`require`) builds plus generated `.d.ts` types.

Optional integrations are isolated behind subpath exports so the core is dependency-free:

```bash
npm install express-intent           # core
npm install ioredis                  # peer, only for express-intent/redis
npm install @opentelemetry/api       # peer, only for express-intent/otel
```

---

## Quick start

Declare an intent with a dotted action name and let the middleware attach a rich, typed per-request context to `req.intent`:

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

`intent()` never blocks a request unless you ask it to. See [Enforcement](#enforcement-allow-challenge-rate-limit-deny).

Enable enforcement on a mutating route with one option:

```ts
app.post('/payments', intent('payment.create', { enforce: true }), createPayment);
```

---

## How it works: intent → decision

1. **Declare** — call `intent('users.read', opts)` anywhere in the middleware chain (per-route or `app.use`).
2. **Build context** — the middleware snapshots the frozen `IntentContext` (requestId, action, actor, method, path, IP, headers, params, query, body-shape hash, receivedAt).
3. **Evaluate** — the configured decision path runs (hard rules → policies → risk engine → decision thresholds, or a custom `decisionEngine`).
4. **Attach** — `req.intent` is populated, `X-Request-Id` is set, and the request runs inside an `AsyncLocalStorage` scope.
5. **Enforce (optional)** — non-`allow` decisions short-circuit with the configured HTTP response, or forward errors.

---

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

Use `defineAction('payment.create', opts)` to reuse a configured action across routes without re-declaring options:

```ts
import { defineAction, intent } from 'express-intent';

const createPayment = defineAction('payment.create', { mutation: 'create' });

app.post('/payments', intent(createPayment, { enforce: true }));
```

---

## Intent options

All fields are optional; sensible security defaults are applied.

| option          | type                                                | default       | purpose                                   |
| --------------- | --------------------------------------------------- | ------------- | ----------------------------------------- |
| `auth`          | `'anonymous' \| 'required' \| 'mfa-required'`       | `'required'`  | minimum authentication level               |
| `sensitivity`   | `'public' \| 'internal' \| 'pii' \| 'critical'`     | `'internal'`  | data class of the intent                  |
| `mutation`      | `'none' \| 'read' \| 'create' \| 'update' \| 'destructive'` | `'read'` | whether/how the intent mutates state |
| `velocity`      | `{ window, max, per }`                              | `null`        | rate hints (`window: { amount, unit }`)   |
| `anomaly`       | `{ threshold, window }`                             | `null`        | anomaly tolerance hints                    |
| `authFreshness` | `{ maxAgeMs, requiredMethods? }`                    | `null`        | stale-auth hints                          |
| `quotas`        | `Array<{ per, window, max }>`                       | `[]`          | quota hints (`per: 'subject' \| 'ip' \| 'pair'`) |
| `tags`          | `string[]`                                          | `[]`          | free-form tags for policies                |
| `decisionOverrides` | `{ rateLimitAt?, challengeAt?, denyAt?, challengeKind?, challengeTtlMs?, denyStatus?, limit? }` | `{}` | per-intent threshold overrides |

All defaults are exported as constants (`DEFAULT_DECISION_CONFIG`, `DEFAULT_DENY_STATUS`, `DEFAULT_CHALLENGE_TTL_MS`, `DEFAULT_LIMIT`, `DEFAULT_RISK_CONFIG`, `DEFAULT_THRESHOLDS`, `DEFAULT_ANOMALY_CONFIG`, `DEFAULT_REDACTION_CONFIG`).

Actions are validated at middleware creation: dotted, lowercase names (`payment.create`), 1–128 chars, and invalid actions throw an `IntentValidationError` with actionable hints.

---

## What gets attached: `req.intent`

```ts
interface IntentPayload {
  requestId: string;   // Crockford-base32, unique per request (time + 16 random chars)
  action: string;      // dotted action name (canonical identifier)
  context: IntentContext;   // frozen snapshot of request + intent + actor
  decision: Decision;  // { kind: 'allow' | 'monitor' | 'rate_limit' | 'challenge' | 'deny', ... }
  startedAt: number;
  actor: Actor;        // === context.actor
  isAllowed: boolean;  // === decision.kind === 'allow'
  isDenied: boolean;   // === decision.kind === 'deny'
}
```

`req.intent` is added to the Express `Request` type via module augmentation on `express-serve-static-core`, so it is fully typed with zero setup.

### `IntentContext`

`IntentContext` is deeply `Object.freeze`-d and captures the request at middleware time:

```ts
interface IntentContext {
  requestId: string;
  intent: Intent;                       // normalized, validated intent contract
  actor: Actor;                         // normalized + frozen actor
  method: string;
  path: string;
  ip: string | null;
  headers: Readonly<Record<string, string>>;   // lowercased snapshot
  params: Readonly<Record<string, string>>;    // lazy: resolved by the router on first read
  query: Readonly<Record<string, string>>;
  bodyShapeHash: string | null;         // stable SHA-256 of the JSON body shape, not values
  receivedAt: number;
  extras: Readonly<Record<string, unknown>>;
}
```

`params` and `query` are lazy and cached: the Express router populates them *after* the middleware runs, so they are snapshotted on first access (O(1) thereafter).

---

## Actors: who is calling

The `actor` on every context carries `subject` (or `null` for anonymous), `authenticated`, `authMethod`, `roles`, `scopes`, `claims`, `authRequirement`, and `authenticatedAt`.

**Default provider:** reads `x-user-subject` (falls back to `x-subject`, then `req.user`.sub / subject / id / username / email), infers `authMethod` from the `Authorization` header scheme (`Bearer` → `oauth2`, `Basic` → `password`, `ApiKey` → `api-key`, etc.). No subject header → anonymous actor.

Custom provider (may be async):

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

- Providers can be sync or async; async providers race against `timeoutMs` (default `50ms`) and degrade to anonymous on timeout.
- Actors are normalized (`normalizeActor`) and validated against prototype-pollution keys; invalid actors throw `MalformedActorError`.
- Use `resolveActor(req, provider, opts)` to resolve actors outside middleware.

---

## Enforcement: allow, challenge, rate-limit, deny

Enforcement is **off by default**. Enable it with `enforce: true`, `policies`, or a `decisionEngine`; the middleware then short-circuits non-`allow` decisions:

| decision     | response                                                    |
| ------------ | ----------------------------------------------------------- |
| `deny`       | `401` (auth-required) or `403` (default / destructive), JSON body |
| `challenge`  | `401` with `{ challenge: 'mfa', ... }`                      |
| `rate_limit` | `429` with `Retry-After`                                    |

Tune with `onDeny`, `onChallenge`, `onRateLimit`, or `throwOnDeny` (forwards an `IntentDeniedError` to Express error middleware). `onDecision` observes every decision without altering the flow.

The built-in enforce path checks:
1. `auth` vs. the actor — `required` without authentication → `401`; `mfa-required` without authentication → `401` challenge; destructive mutation without authentication → `403`.
2. The risk → decision engine (`evaluateDecision`), which applies hard rules first, then score thresholds.

**Hard rules (fail-closed):**
- `mfa-required` intent + anonymous actor → `challenge` (MFA)
- destructive mutation + anonymous actor → `deny`
- required signal missing → `deny`

**Decision thresholds:** risk score `≥ 25` → `rate_limit`, `≥ 50` → `challenge`, `≥ 75` → `deny` (overridable per intent via `decisionOverrides`).

---

## Policies: declarative rules

Policies are declarative `when → then` rules evaluated deterministically:

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

**Conditions** (`when`) — all typed with runtime validation:
- Intents: `when.action('*.delete')` (glob), `when.tag`, `when.sensitivity`, `when.mutation`, `when.authRequirement`
- Actor: `when.authenticated`, `when.subject`, `when.role`, `when.scope`, `when.authMethod`, `when.actorField`
- Risk: `when.riskScoreAtLeast`, `when.riskScoreBelow`, `when.riskAtLeast`, `when.riskBelow`, `when.signalExists`, `when.signalMissing`, `when.signalValue`
- Request: `when.path`, `when.ip`, `when.method`, `when.header`
- Logic: `when.and(...)`, `when.or(...)`, `when.not(...)`

**Effects** (`then`): built by `policyAllow`, `policyDeny`, `policyMonitor`, `policyChallenge`, `policyRateLimit` — each returns a fully-formed `Decision`.

**Evaluation**: `evaluatePolicies(input, { policies })` returns `{ decision, trace, matchedPolicyIds }`. Policies are sorted by id for deterministic output; deny is the most-severe merged effect when multiple policies match. `compilePolicy` and `toBuiltPolicy` are available to pre-compile predicates for hot paths. Invalid definitions throw `PolicyValidationError`.

---

## Risk: weighted signal scoring

Risk scoring turns a set of typed signals into a 0–100 score and a severity:

```ts
import { evaluateRisk, DEFAULT_RISK_CONFIG } from 'express-intent';

const { score, severity, breakdown, risk } = evaluateRisk(
  [
    { name: 'geo-anomaly', kind: 'boolean', value: false, weight: 0.3, computedAt: now, confidence: 1, ttlMs: 60_000 },
    { name: 'velocity', kind: 'numeric', value: 3, weight: 0.1, computedAt: now, confidence: 1, ttlMs: 60_000 },
  ],
  { missing: ['device-fingerprint'] },
  DEFAULT_RISK_CONFIG,
  { now },
);
```

- **Signal kinds:** `boolean`, `numeric` (with optional `min`/`max` ranges + invert), `categorical` (value→score tables).
- **Weighting:** per-signal weights normalized by total weight; signals can have zero weight, expire via TTL, or degrade by confidence.
- **Decay:** optional `{ halfLifeMs, floor }` config makes older signals contribute less.
- **Severity thresholds:** `low 25`, `medium 50`, `high 75`, `critical 90` (overridable).
- Every evaluation returns a `breakdown` entry per signal, explaining *why* (in-range / missing / expired / no-weight), plus an aggregation hash for caching/dedup.

Missing required signals fail closed in the decision engine: `evaluateDecision` denies when a required signal is listed in `missingSignals`.

---

## Anomaly detection

`AnomalyEngine` coordinates detectors against a bounded observation store:

```ts
import { AnomalyEngine, InMemoryObservationStore, BUILTIN_DETECTORS } from 'express-intent';

const engine = new AnomalyEngine({
  detectors: BUILTIN_DETECTORS,
  store: new InMemoryObservationStore({ maxEntries: 10_000, ttlMs: 300_000 }),
});

const report = await engine.observe({
  actorSubject: 'user-1234', ip: '203.0.113.7',
  userAgent: 'Mozilla/5.0', action: 'items.read',
  method: 'GET', path: '/items/42', now,
});
```

**Built-in detectors:**
| detector | flags                                                            |
| -------- | ---------------------------------------------------------------- |
| `VELOCITY` | request bursts exceeding `velocityMax` per window                |
| `ENUMERATION` | too many distinct `resourceId`s (resource trawling)             |
| `USER_AGENT_CHANGE` | subject's user-agent suddenly differs from history        |
| `IP_CHANGE` | subject's IP suddenly differs from history                        |
| `ENDPOINT_PATTERN` | too many distinct `method + path` combos per window        |

Detectors are pluggable (`register(detector)`), report `maxConfidence` per observation, and ship with sensible defaults (`DEFAULT_ANOMALY_CONFIG`). Stores are swappable — including a [Redis-backed](redis-backends) `RedisObservationStore`.

---

## Rate limiting

A standalone fixed-window in-memory limiter plus a decision helper:

```ts
import { InMemoryRateLimiter, rateLimit } from 'express-intent';

const limiter = new InMemoryRateLimiter({ maxKeys: 100_000, sweepIntervalMs: 60_000 });

const result = await limiter.consume({
  namespace: 'default', max: 10, windowMs: 60_000,
  scope: 'ip', ip: '1.2.3.4', action: 'payment.create',
});

const decision = result.allowed
  ? { kind: 'allow' }
  : rateLimit({ reason: 'too fast', limit: result.limit, remaining: 0, retryAfterMs: result.retryAfterMs, scope: 'ip' });
```

- Scopes: `actor`, `ip`, `action`, `custom` (keys are SHA-256 normalized via `buildRateLimitKey`).
- Bounded: `maxKeys` with oldest-expiry eviction; background sweeper (disable with `sweepIntervalMs: 0`).
- Redis scale-out: `RedisRateLimiter` from `express-intent/redis` (INCR + EXPIRE) — see below.

---

## Idempotency

Replay protection for mutating routes, `POST /charge` safe by default:

```ts
import { idempotency, InMemoryIdempotencyProvider } from 'express-intent';

const provider = new InMemoryIdempotencyProvider({ ttlMs: 24 * 60 * 60_000 });
app.post('/charge', idempotency({ provider }), handler);
```

- Reads `Idempotency-Key` (validated against `IDEMPOTENCY_KEY_PATTERN`), suggests TTL `24h`, wait deadline `30s`.
- Replays of the same key return the original response (with safe-header allowlist and a bounded captured body).
- Concurrent duplicates are **single-flighted** — the second request waits for the in-flight one instead of double-processing.
- Response fingerprinting bounds replay bodies to `maxReplayBodyBytes` (64 KB default).
- `createIdempotencyMiddleware` is the long-form alias; `getIdempotency(req)` reads `req.idempotency = { key, replayed }`.
- Scale-out: `RedisIdempotencyProvider` uses `SET NX` acquire + pub/sub for wait notification.

---

## Audit logging

`attachAudit` writes one `AuditEvent` per request when the response finishes or closes:

```ts
import { attachAudit, InMemoryAuditSink } from 'express-intent';

app.use(attachAudit({ sink: new InMemoryAuditSink(), includeBody: false }));
```

- **Sinks:** `InMemoryAuditSink` (ring buffer, query helpers), `ConsoleAuditSink` (JSON lines), `NullAuditSink` (default no-op).
- **Event types:** `intent.evaluated`, `security.denied`, `security.challenged`, `security.rate_limited`, `security.anomaly`, `security.error` — severities `debug | info | warn | error`.
- Emits on `response` `finish`/`close`, **never throws** into the request path.
- Integrates `decisionResolver` for your application's decision data, and `RedactionEngine` for privacy (see below).
- In-memory sink helpers: `all()`, `clear()`, `size()`, `byType()`, `bySeverity()` — handy for tests.

---

## Working outside handlers (AsyncLocalStorage)

Middleware runs handlers inside an `AsyncLocalStorage` scope, so request context is readable anywhere downstream without threading `req` around:

```ts
import { getIntentContext } from 'express-intent';

export function auditLog() {
  const ctx = getIntentContext();
  return { requestId: ctx?.requestId, action: ctx?.intent.key, subject: ctx?.actor.subject };
}
```

- `getIntentContext(req?)` — the live `IntentContext` (from `req.intent.context` when a request is passed, otherwise from ALS).
- `getRequestSnapshot()` — lightweight `{ requestId, action, actorSubject, startedAt }`.
- `runWithRequest(context, fn)` — run `fn` inside a scope with your own context.
- `generateRequestId()` — the Crockford-base32 generator (12-char time + 16-char random, no `I`/`L`/`O`/`U`).
- `buildRequestContext(req, options)` — build a context outside middleware.

---

## Metrics: Prometheus-ready

Isolated subpath export keeps the core dependency-free:

```ts
import { createPrometheusMetricsProvider, CoreMetrics } from 'express-intent/metrics';

const provider = createPrometheusMetricsProvider();
const metrics = CoreMetrics(provider);
```

**Maintained metrics** (Prometheus text format via `toPrometheusText`):

| metric                                                    | type      | key labels                                        |
| --------------------------------------------------------- | --------- | ------------------------------------------------- |
| `express_intent_requests_total`                           | counter   | action, intent_key, http_method, http_route, outcome |
| `express_intent_decisions_total`                          | counter   | action, intent_key, decision, severity            |
| `express_intent_risk_evaluations_total`                   | counter   | action, intent_key, severity                      |
| `express_intent_risk_score`                               | histogram | action, intent_key (buckets 0/10/25/50/75/90/100) |
| `express_intent_anomalies_total`                          | counter   | action, anomaly_type, anomaly_confidence_bucket   |
| `express_intent_rate_limits_total`                        | counter   | action, intent_key, scope, outcome                |
| `express_intent_evaluation_duration_ms`                   | histogram | action, intent_key, decision                      |

- `GuardedMetricsProvider` enforces a cardinality guard (`DEFAULT_CARDINALITY_GUARD`) and **no-crash** behavior — if anything goes wrong it degrades to no-ops.
- `createCoreMetrics` wires counters/histograms to any `MetricsProvider`, so the same code works with a real Prometheus client or your favorite exporter.

---

## Redis backends

`express-intent/redis` provides adapter-based, horizontally-scalable implementations of the core stores. Requires `ioredis` (optional peer):

```ts
import {
  RedisRateLimiter,
  RedisSignalStore,
  RedisObservationStore,
  RedisIdempotencyProvider,
  InMemoryRedisAdapter,
} from 'express-intent/redis';
```

| component            | backing primitives                                  |
| -------------------- | --------------------------------------------------- |
| `RedisRateLimiter`   | `INCR` + `EXPIRE` fixed-window buckets               |
| `RedisSignalStore`   | incremental counters + expiry                        |
| `RedisObservationStore` | timestamped ZSETs per actor and IP, TTL-pruned     |
| `RedisIdempotencyProvider` | `SET NX` acquire + pub/sub notification           |
| `InMemoryRedisAdapter` | full drop-in `RedisClientAdapter` for dev/tests    |

All backends sit behind a small `RedisClientAdapter` interface, so you can swap in any client (ioredis, node-redis, or the in-memory shim) by implementing `get/set/del/incr/zadd/publish/...`. Keys are namespaced (`ei:v1:<ns>:...`) and collision-safe.

---

## OpenTelemetry

Optional span recording and tracing via `express-intent/otel`:

```ts
import { createOTelTelemetry, OTelSpanRecorder, AttributeRedactor } from 'express-intent/otel';
```

- `OTelSpanRecorder` adapts captures spans with redaction support (`AttributeRedactor`).
- `createOTelTelemetry` wires telemetry hooks for intent evaluation, risk evaluation, policy evaluation, and decisions.
- Loads the `@opentelemetry/api` peer only when present (`tryLoadOTelAPI`) — no hard dependency.

---

## Redaction engine

`RedactionEngine` + `isSensitiveHeader` / `isSensitiveQueryParam` / `isSensitiveBodyKey` strip secrets before events are emitted:

```ts
import { RedactionEngine, DEFAULT_REDACTION_CONFIG } from 'express-intent';

const engine = new RedactionEngine(DEFAULT_REDACTION_CONFIG);
const safeHeaders = engine.redactHeaders(req.headers);
```

**Redacted by default:**
- Headers: `authorization`, `proxy-authorization`, `cookie`, `set-cookie`, `x-api-key`, `api-key`, `x-auth-token`, `x-csrf-token`, `csrf-token`, `x-forwarded-for`, `x-real-ip`, `x-amz-security-token`.
- Query params: `token`, `access_token`, `refresh_token`, `id_token`, `api_key` / `api-key` / `apikey`, `password`, `passwd`, `pwd`, `secret`, `code`, `state`, `x-api-key`.
- Body keys: password variants, secrets, tokens, API keys, authorization/cookie, card data (`credit-card`, `cvv`, `cvc`, `ssn`, `social-security`), private keys.

Also truncates long values (`maxStringLength`), bounds arrays/objects, honors body allow-lists, and skips prototype-pollution keys.

---

## Errors

| class | thrown when |
| ----- | ----------- |
| `IntentError` | `getIntent(req)` runs on a route missing intent context |
| `IntentValidationError` | invalid action names, intent options, or window specs |
| `IntentDeniedError` | `throwOnDeny` forwards a denial to Express error middleware |
| `MalformedActorError` | an actor provider returned an invalid actor |
| `PolicyValidationError` | an invalid policy definition (bad condition/effect) |

---

## Performance

Representative numbers from the package's own microbench harness (`node --expose-gc bench/run.cjs`), Node 20, local loopback:

| scenario                                  | mean      | notes                          |
| ----------------------------------------- | --------- | ------------------------------ |
| `evaluateDecision` (allow path)           | ~700 ns   | ≈ 1.4M ops/s                   |
| `InMemoryRateLimiter.consume` (warm)      | ~1.2 µs   | ≈ 820k ops/s                   |
| `InMemoryIdempotencyProvider` acquire+complete | ~1.1 µs | ≈ 940k ops/s                |
| `AnomalyEngine.observe` (50 actors, warm) | ~34 µs    | detector pipeline              |
| `evaluateRisk` (5 signals)                | ~34 µs    | weighted + breakdown           |
| HTTP: baseline Express `GET /items/42`    | ~0.96 ms  | —                              |
| HTTP: with `express-intent`               | ~1.55 ms  | 646 req/s on the bench machine |

The decision path is allocation-light and synchronous by default; only custom actor providers or remote store backends add await points. Tune `sweepIntervalMs`, `maxKeys`, and store TTLs to match your traffic.

---

## TypeScript

- Ships complete `.d.ts` for both ESM and CJS.
- Augments the Express `Request` type via `declare module 'express-serve-static-core'`, so `req.intent` / `req.intent.context` are typed with **zero setup**.
- Exports 60+ named types: `Intent`, `IntentOptions`, `Decision`, `IntentContext`, `Actor`, `PolicyDefinition`, `Condition`, `RiskConfig`, `AuditEvent`, `IdempotencyProvider`, `MetricsProvider`, `RedisClientAdapter`, and more.
- Strict, frozen, readonly-by-default objects — no surprise mutation.

---

## Comparison: express-intent vs alternatives

| capability | express-intent | express-rate-limit | express-jwt / passport | express-jwt-permissions |
| ---------- | -------------- | ------------------ | ----------------------- | ----------------------- |
| Intent declarations per route | ✅ | ❌ | ❌ | ❌ |
| Decisions (allow/monitor/rate_limit/challenge/deny) | ✅ | ❌ | ❌ | ❌ |
| Risk-based thresholding | ✅ unified | ❌ fixed windows only | ❌ | ❌ |
| Declarative policy engine + traces | ✅ | ❌ | ❌ | partial (RBAC only) |
| Anomaly detection (velocity, enumeration, UA/IP change) | ✅ | ❌ | ❌ | ❌ |
| Idempotency + single-flight | ✅ | ❌ | ❌ | ❌ |
| Audit events + redaction | ✅ | ❌ | ❌ | ❌ |
| Optional Redis scale-out | ✅ | add-on | add-on | ❌ |
| Optional Prometheus + OTel | ✅ | add-on | ❌ | ❌ |
| Typed Express augmentation | ✅ | ❌ | type packages | ❌ |

`express-intent` replaces **four separate middleware stacks** (JWT enforcement, RBAC, rate limiting, idempotency, audit) with one declarative layer — while still composing with any JWT/passport middleware you already use.

---

## Use cases

- **APIs needing request authentication gating** — declare `auth: 'required'` / `'mfa-required'` and let enforcement short-circuit.
- **Rate-limited public endpoints** — combine `velocity` hints, `InMemoryRateLimiter`, and the `rate_limit` decision with `Retry-After`.
- **Payment / destructive operations** — idempotency middleware + destructive-mutation hard-rule denial.
- **Multi-tenant RBAC/ABAC** — policy conditions on `when.role`, `when.scope`, `when.actorField`, `when.sensitivity`.
- **Abuse & fraud monitoring** — anomaly detectors (velocity, enumeration, user-agent/IP change) feeding `monitor` / `challenge` decisions.
- **Compliance-ready logging** — `attachAudit` + `RedactionEngine` to keep PII and secrets out of logs.
- **Serverless / multi-instance deployments** — swap in the Redis rate-limit, signal, observation, and idempotency backends.

---

## Design goals & non-goals

**Goals**
- Declarative intent as the *single source of truth* per route.
- Fail-closed security with zero-guess defaults.
- Deterministic, testable decision output (pure functions, frozen objects).
- Modular: optional integrations never inflate the core install.
- Node-first performance: sync fast path, micro-allocation-aware.

**Non-goals**
- Not an authentication provider — you bring your own token verification (JWT, passport, sessions) via the `actor` provider.
- Not a full WAF / request firewall — anomaly detection and headers apply to common abuse patterns, not deep payload inspection.
- Not a replacement for a database-backed authorization service at scale — Redis backends are for shared rate/idempotency state, not ACL management.

---

## Roadmap

- `0.2.x` — `metric`-driven `auto` mode (metrics feed back into risk signals), per-tenant signal namespaces
- `0.3.x` — expression-style policy language, allowlist/provenance for policy bundles, `fetch`-based policy signing
- `0.4.x` — first-class Fastify adapter, streaming body-shape hashing, sub-millisecond async actor caching
- `1.0` — API freeze; codemods for any breaking changes; full observability example repo

*Feel free to open issues or PRs — contributions, benchmarks, and adapter integrations are welcome.*

---

## License

[MIT](LICENSE) © Arpon Ascension

<p align="center">
  <sub><b>express-intent</b> — declare intent, enforce decisions, sleep at night. Built for Express 4 & 5. ✨</sub>
</p>