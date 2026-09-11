'use strict';

/**
 * Microbenchmark harness for express-intent.
 * Runs each scenario in a self-contained async loop, computes mean / p50 / p99
 * wall-clock time, ops/sec, and tracks heap delta. Pure Node; no deps.
 *
 * Usage: node --expose-gc bench/run.cjs [iterations]
 * Default iterations: 200_000
 */

const path = require('node:path');
const { performance } = require('node:perf_hooks');

const DIST = path.resolve(__dirname, '..', 'dist');
const ei = require(path.join(DIST, 'index.cjs'));

const expressModule = require('express');
const express = expressModule.default || expressModule;
const http = require('node:http');

const ITER = Number.parseInt(process.argv[2] || '50000', 10);

const fmtNs = (ns) => {
  if (ns < 1_000) return `${ns.toFixed(0)} ns`;
  if (ns < 1_000_000) return `${(ns / 1_000).toFixed(2)} us`;
  return `${(ns / 1_000_000).toFixed(2)} ms`;
};

const fmtBytes = (n) => {
  const abs = Math.abs(n);
  if (abs < 1024) return `${n} B`;
  if (abs < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(2)} MB`;
};

function benchSync(name, fn, iters = ITER) {
  for (let i = 0; i < 2000; i++) fn(i);
  if (global.gc) global.gc();
  const memBefore = process.memoryUsage();
  const samples = new Float64Array(iters);
  const t0 = performance.now();
  for (let i = 0; i < iters; i++) {
    const s = performance.now();
    fn(i);
    samples[i] = performance.now() - s;
  }
  const total = performance.now() - t0;
  if (global.gc) global.gc();
  const memAfter = process.memoryUsage();

  const sorted = Array.from(samples).sort((a, b) => a - b);
  const sum = sorted.reduce((s, v) => s + v, 0);
  const mean = (sum / iters) * 1_000_000;
  const p50 = sorted[Math.floor(iters * 0.5)] * 1_000_000;
  const p99 = sorted[Math.floor(iters * 0.99)] * 1_000_000;
  const p999 = sorted[Math.floor(iters * 0.999)] * 1_000_000;
  const min = sorted[0] * 1_000_000;
  const max = sorted[iters - 1] * 1_000_000;
  const opsPerSec = 1000 / ((sum / iters) || 1e-9);
  const heapDelta = memAfter.heapUsed - memBefore.heapUsed;
  return { name, iters, totalMs: total, mean, p50, p99, p999, min, max, opsPerSec, heapDelta };
}

async function benchAsync(name, fn, iters = ITER) {
  for (let i = 0; i < 1000; i++) await fn(i);
  if (global.gc) global.gc();
  const memBefore = process.memoryUsage();
  const samples = new Float64Array(iters);
  const t0 = performance.now();
  for (let i = 0; i < iters; i++) {
    const s = performance.now();
    await fn(i);
    samples[i] = performance.now() - s;
  }
  const total = performance.now() - t0;
  if (global.gc) global.gc();
  const memAfter = process.memoryUsage();
  const sorted = Array.from(samples).sort((a, b) => a - b);
  const sum = sorted.reduce((s, v) => s + v, 0);
  const mean = (sum / iters) * 1_000_000;
  const p50 = sorted[Math.floor(iters * 0.5)] * 1_000_000;
  const p99 = sorted[Math.floor(iters * 0.99)] * 1_000_000;
  const min = sorted[0] * 1_000_000;
  const max = sorted[iters - 1] * 1_000_000;
  const opsPerSec = 1000 / ((sum / iters) || 1e-9);
  const heapDelta = memAfter.heapUsed - memBefore.heapUsed;
  return { name, iters, totalMs: total, mean, p50, p99, min, max, opsPerSec, heapDelta };
}

function printResult(r) {
  console.log(
    `  ${r.name.padEnd(54)}  mean=${fmtNs(r.mean).padStart(9)}  p50=${fmtNs(r.p50).padStart(9)}  p99=${fmtNs(r.p99).padStart(9)}  ` +
    `min=${fmtNs(r.min).padStart(9)}  max=${fmtNs(r.max).padStart(9)}  ops/s=${r.opsPerSec.toFixed(0).padStart(11)}  heap=${r.heapDelta >= 0 ? '+' : ''}${fmtBytes(r.heapDelta)}`,
  );
}

function scenario_riskEvaluation() {
  console.log('\n=== risk evaluation ===');
  const signals = [
    { name: 'authenticated', kind: 'boolean', value: true, weight: 0.4, computedAt: 1_000_000, confidence: 1, ttlMs: 60_000 },
    { name: 'mutation', kind: 'categorical', value: 'read', weight: 0.2, computedAt: 1_000_000, confidence: 1, ttlMs: 60_000 },
    { name: 'time-of-day', kind: 'numeric', value: 14, weight: 0.1, computedAt: 1_000_000, confidence: 1, ttlMs: 60_000 },
    { name: 'geo-anomaly', kind: 'boolean', value: false, weight: 0.3, computedAt: 1_000_000, confidence: 1, ttlMs: 60_000 },
    { name: 'velocity', kind: 'numeric', value: 3, weight: 0.1, computedAt: 1_000_000, confidence: 1, ttlMs: 60_000 },
  ];
  const context = { missing: [] };
  const r = benchSync('evaluateRisk(5 signals)', () => ei.evaluateRisk(signals, context, ei.DEFAULT_RISK_CONFIG, { now: 1_000_000 }));
  printResult(r);
}

function scenario_decision() {
  console.log('\n=== decision engine ===');
  const input = {
    intent: { key: 'items.read', action: 'items.read', auth: 'optional', sensitivity: 'low', mutation: 'read', velocity: null, anomaly: null, authFreshness: null, quotas: [], tags: [], decisionOverrides: {} },
    actor: { subject: 'user-1234', authenticated: true, authMethod: 'oauth2', authRequirement: 'optional', roles: ['reader'], scopes: [], claims: {}, authenticatedAt: 100 },
    risk: { score: 25, severity: 'low', breakdown: [], anomalyReport: { anomalies: [], evaluatedAt: 0, totalAnomalies: 0 } },
    score: 25,
    severity: 'low',
    signals: new Map(),
    missingSignals: new Set(),
  };
  const r = benchSync('evaluateDecision(allow path)', () => ei.evaluateDecision(input));
  printResult(r);

  const input2 = { ...input, score: 95, severity: 'critical' };
  const r2 = benchSync('evaluateDecision(critical score)', () => ei.evaluateDecision(input2));
  printResult(r2);
}

function scenario_policyEvaluation() {
  console.log('\n=== policy evaluation ===');
  const makePolicy = (id, when, decision) => ei.compilePolicy(ei.definePolicy({
    id, version: 1, severity: 'low', effect: decision.kind,
    when,
    then: { decision },
  }));
  const policies = [
    makePolicy('allow-internal-ips', { kind: 'pathMatches', pattern: '/internal/*' }, { kind: 'allow', reason: 'internal' }),
    makePolicy('deny-large-mutation', { kind: 'pathMatches', pattern: '/api/charge' }, { kind: 'deny', reason: 'no', status: 403 }),
    makePolicy('challenge-elevated', { kind: 'pathMatches', pattern: '/admin/*' }, { kind: 'challenge', reason: 'no', challenge: 'mfa', ttlMs: 60000 }),
  ];
  const baseInput = {
    intent: { key: 'i', action: 'i.x', auth: 'optional', sensitivity: 'low', mutation: 'read', velocity: null, anomaly: null, authFreshness: null, quotas: [], tags: [], decisionOverrides: {} },
    context: { path: '/internal/ping', method: 'GET' },
    actor: { subject: 'u', authenticated: true, authMethod: 'oauth2', authRequirement: 'optional', roles: ['admin'], scopes: [], claims: {}, authenticatedAt: 1 },
    score: 10,
    severity: 'low',
  };
  const r = benchSync('evaluatePolicies(3 policies, 1 match)', () => ei.evaluatePolicies(baseInput, { policies, defaultEffect: 'allow' }));
  printResult(r);

  const input2 = { ...baseInput, context: { path: '/api/charge', method: 'POST' } };
  const r2 = benchSync('evaluatePolicies(3 policies, no match for path)', () => ei.evaluatePolicies(input2, { policies, defaultEffect: 'allow' }));
  printResult(r2);
}

async function scenario_anomalyDetection() {
  console.log('\n=== anomaly detection ===');
  const store = new ei.InMemoryObservationStore({ maxEntries: 1_000, ttlMs: 60_000 });
  const engine = new ei.AnomalyEngine({ detectors: ei.BUILTIN_DETECTORS, store });
  const obs = (i) => ({
    actorId: `user-${i % 50}`,
    actorSubject: `user-${i % 50}`,
    ip: `203.0.113.${(i % 250) + 1}`,
    userAgent: 'Mozilla/5.0',
    action: 'items.read',
    method: 'GET',
    path: `/items/${i % 100}`,
    resourceId: `${i % 100}`,
    status: 200,
    now: 1_000_000 + i,
  });
  // Warm
  for (let i = 0; i < 100; i++) await engine.observe(obs(i));
  // Profile
  const r = await benchAsync('AnomalyEngine.observe (50 actors, warm)', async (i) => engine.observe(obs(i)), 1_000);
  printResult(r);
}

async function scenario_rateLimiter() {
  console.log('\n=== in-memory rate limiter ===');
  const rl = new ei.InMemoryRateLimiter({ sweepIntervalMs: 0, maxKeys: 100_000 });
  const actor = { subject: 'user-1234', authenticated: true, authMethod: 'oauth2', authRequirement: 'required', roles: [], scopes: [], claims: {}, authenticatedAt: 1_000_000 };
  const spec = {
    namespace: 'payment',
    max: 100,
    windowMs: 60_000,
    scope: 'actor',
    action: 'payment.create',
    actor,
    ip: '203.0.113.7',
    now: 1_000_000,
  };
  const r = await benchAsync('InMemoryRateLimiter.consume (warm)', async () => rl.consume(spec), 100_000);
  printResult(r);
  await rl.shutdown();
}

async function scenario_idempotency() {
  console.log('\n=== idempotency (in-memory) ===');
  const provider = new ei.InMemoryIdempotencyProvider({ maxEntries: 10_000 });
  let n = 0;
  const r = await benchAsync('InMemoryIdempotencyProvider.acquire+complete', async () => {
    n++;
    const key = `k${(n % 200)}`;
    const fp = `fp${n % 5}`;
    const acq = await provider.acquire(key, fp, 60_000, 1_000_000 + n);
    if (acq.acquired) {
      await provider.complete(key, { status: 200, headers: {}, body: 'ok' }, 60_000, 1_000_000 + n);
    }
    return acq;
  }, 5_000);
  printResult(r);
  await provider.shutdown();
}

function listen(app, port) {
  return new Promise((resolve) => {
    const server = app.listen(port, () => {
      const addr = server.address();
      const p = typeof addr === 'object' && addr !== null ? addr.port : port;
      resolve({ server, port: p });
    });
  });
}

function close(s) {
  return new Promise((resolve) => s.server.close(() => resolve()));
}

async function benchHttp(name, port, p, iters, method = 'GET', extraHeaders = {}, body = '') {
  for (let i = 0; i < 200; i++) await sendOne(port, p, method, extraHeaders, body);
  if (global.gc) global.gc();
  const memBefore = process.memoryUsage();
  const samples = new Float64Array(iters);
  const t0 = performance.now();
  for (let i = 0; i < iters; i++) {
    const s = performance.now();
    await sendOne(port, p, method, extraHeaders, body);
    samples[i] = performance.now() - s;
  }
  const total = performance.now() - t0;
  if (global.gc) global.gc();
  const memAfter = process.memoryUsage();
  const sorted = Array.from(samples).sort((a, b) => a - b);
  const sum = sorted.reduce((s, v) => s + v, 0);
  const mean = (sum / iters) * 1_000_000;
  const p50 = sorted[Math.floor(iters * 0.5)] * 1_000_000;
  const p99 = sorted[Math.floor(iters * 0.99)] * 1_000_000;
  const min = sorted[0] * 1_000_000;
  const max = sorted[iters - 1] * 1_000_000;
  const opsPerSec = 1000 / ((sum / iters) || 1e-9);
  const heapDelta = memAfter.heapUsed - memBefore.heapUsed;
  return { name, iters, totalMs: total, mean, p50, p99, min, max, opsPerSec, heapDelta };
}

let BENCH_AGENT = null;
function getBenchAgent() {
  if (BENCH_AGENT) return BENCH_AGENT;
  BENCH_AGENT = new http.Agent({ keepAlive: true, maxSockets: 32 });
  return BENCH_AGENT;
}
function sendOne(port, p, method, extraHeaders, body) {
  return new Promise((resolve, reject) => {
    const req = http.request(
      {
        method,
        host: '127.0.0.1',
        port,
        path: p,
        headers: { 'content-length': Buffer.byteLength(body), ...extraHeaders },
        agent: getBenchAgent(),
      },
      (res) => {
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => resolve({ status: res.statusCode, bytes: chunks.reduce((s, c) => s + c.length, 0) }));
      },
    );
    req.on('error', reject);
    if (body) req.write(body);
    req.end();
  });
}

async function scenario_expressMiddleware() {
  console.log('\n=== express middleware: baseline vs express-intent ===');
  const baselineApp = express();
  baselineApp.get('/items/:id', (req, res) => res.status(200).json({ id: req.params.id }));

  const noopApp = express();
  noopApp.use((req, res, next) => next());
  noopApp.get('/items/:id', (req, res) => res.status(200).json({ id: req.params.id }));

  const intentApp = express();
  intentApp.use(ei.intent({ action: 'items.read' }));
  intentApp.get('/items/:id', (req, res) => res.status(200).json({ id: req.params.id, requestId: req.intent?.requestId }));

  const auditApp = express();
  const sink = new ei.InMemoryAuditSink();
  auditApp.use(ei.attachAudit({ sink, decisionResolver: () => ({ kind: 'allow' }) }));
  auditApp.get('/items/:id', (req, res) => res.status(200).json({ id: req.params.id }));

  const idemApp = express();
  const provider = new ei.InMemoryIdempotencyProvider({ maxEntries: 10_000 });
  idemApp.use(express.json());
  idemApp.post('/charge', ei.createIdempotencyMiddleware({ provider }), (req, res) => res.status(201).json({ ok: true }));

  const baselineServer = await listen(baselineApp, 0);
  const noopServer = await listen(noopApp, 0);
  const intentServer = await listen(intentApp, 0);
  const auditServer = await listen(auditApp, 0);
  const idemServer = await listen(idemApp, 0);

  try {
    const REQS = 3_000;
    const r0 = await benchHttp('GET /items/42 (baseline Express)', baselineServer.port, '/items/42', REQS);
    printResult(r0);
    const r1 = await benchHttp('GET /items/42 (no-op middleware)', noopServer.port, '/items/42', REQS);
    printResult(r1);
    const r2 = await benchHttp('GET /items/42 (express-intent)', intentServer.port, '/items/42', REQS);
    printResult(r2);
    const r3 = await benchHttp('GET /items/42 (audit middleware)', auditServer.port, '/items/42', REQS);
    printResult(r3);
    const r4 = await benchHttp('POST /charge (idempotency)', idemServer.port, '/charge', REQS, 'POST', { 'idempotency-key': 'bench-key-1', 'content-type': 'application/json' }, '{}');
    printResult(r4);
  } finally {
    await close(baselineServer);
    await close(noopServer);
    await close(intentServer);
    await close(auditServer);
    await close(idemServer);
  }
}

async function main() {
  console.log(`Node ${process.version}`);
  console.log(`Iterations: ${ITER.toLocaleString()}`);
  console.log(`GC exposed: ${typeof global.gc === 'function'}`);

  scenario_riskEvaluation();
  scenario_decision();
  scenario_policyEvaluation();
  await scenario_anomalyDetection();
  await scenario_rateLimiter();
  await scenario_idempotency();
  await scenario_expressMiddleware();

  console.log('\nDone.');
}

main().catch((e) => { console.error(e); process.exit(1); });
