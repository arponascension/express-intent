import { describe, it, expect, beforeEach } from 'vitest';
import {
  NoopMetricsProvider,
  NoopCounter,
  NoopGauge,
  NoopHistogram,
  GuardedMetricsProvider,
  DEFAULT_CARDINALITY_GUARD,
  createCoreMetrics,
  confidenceBucket,
  toPrometheusText,
  createPrometheusMetricsProvider,
  type Counter,
  type Histogram,
} from './metrics/index.js';

describe('NoopMetricsProvider', () => {
  it('returns noop counters/gauges/histograms that do not throw', () => {
    const p = new NoopMetricsProvider();
    const c = p.counter('a', 'b', ['x']);
    const g = p.gauge('a', 'b', ['x']);
    const h = p.histogram('a', 'b', ['x'], [1, 5, 10]);
    expect(c).toBeInstanceOf(NoopCounter);
    expect(g).toBeInstanceOf(NoopGauge);
    expect(h).toBeInstanceOf(NoopHistogram);
    c.inc({ x: '1' });
    c.inc({ x: '1' }, 5);
    c.reset();
    g.set({ x: '1' }, 1);
    g.inc({ x: '1' });
    g.dec({ x: '1' }, 2);
    g.reset();
    h.observe({ x: '1' }, 3);
    h.reset();
    expect(c.collect()).toEqual([]);
    expect(g.collect()).toEqual([]);
    expect(h.collect()).toEqual([]);
  });
});

describe('GuardedMetricsProvider — label allowlist', () => {
  let p: GuardedMetricsProvider;
  beforeEach(() => {
    p = new GuardedMetricsProvider('test');
  });

  it('drops labels whose key is not in the allowlist', () => {
    const c = p.counter('m', 'h', ['action', 'user_id']);
    c.inc({ action: 'a.b', user_id: 'u-1' });
    const s = c.collect()[0]!;
    expect(s.labels).toEqual({ action: 'a.b' });
    expect(s.labels['user_id']).toBeUndefined();
  });

  it('truncates label values longer than maxLabelValueLength', () => {
    const c = p.counter('m', 'h', ['action']);
    c.inc({ action: 'x'.repeat(500) });
    const s = c.collect()[0]!;
    expect(s.labels['action']!.length).toBe(64);
  });

  it('drops empty label values', () => {
    const c = p.counter('m', 'h', ['action']);
    c.inc({ action: '' });
    expect(c.collect()).toEqual([]);
  });

  it('drops non-string label values', () => {
    const c = p.counter('m', 'h', ['action']);
    c.inc({ action: 1 as unknown as string });
    expect(c.collect()).toEqual([]);
  });

  it('allows custom allowlist via constructor', () => {
    const q = new GuardedMetricsProvider('q', { allowedLabels: ['tenant'] });
    const c = q.counter('m', 'h', ['tenant']);
    c.inc({ tenant: 't1', action: 'a' });
    expect(c.collect()[0]?.labels).toEqual({ tenant: 't1' });
  });
});

describe('GuardedMetricsProvider — counter', () => {
  let p: GuardedMetricsProvider;
  beforeEach(() => {
    p = new GuardedMetricsProvider('test');
  });

  it('increments by 1 by default', () => {
    const c = p.counter('m', 'h', ['action']);
    c.inc({ action: 'a' });
    c.inc({ action: 'a' });
    expect(c.collect()[0]?.value).toBe(2);
  });

  it('increments by value when provided', () => {
    const c = p.counter('m', 'h', ['action']);
    c.inc({ action: 'a' }, 5);
    expect(c.collect()[0]?.value).toBe(5);
  });

  it('keeps separate series per label set', () => {
    const c = p.counter('m', 'h', ['action']);
    c.inc({ action: 'a' });
    c.inc({ action: 'b' });
    c.inc({ action: 'a' });
    const samples = c.collect();
    const byAction: Record<string, number> = {};
    for (const s of samples) byAction[s.labels['action']!] = s.value;
    expect(byAction['a']).toBe(2);
    expect(byAction['b']).toBe(1);
  });

  it('same metric name returns the same counter instance', () => {
    const c1 = p.counter('m', 'h', ['action']);
    const c2 = p.counter('m', 'h', ['action']);
    expect(c1).toBe(c2);
    c1.inc({ action: 'a' });
    expect(c2.collect()[0]?.value).toBe(1);
  });

  it('reset() clears all series', () => {
    const c = p.counter('m', 'h', ['action']);
    c.inc({ action: 'a' });
    c.reset();
    expect(c.collect()).toEqual([]);
  });

  it('caps distinct label-set cardinality and counts dropped values', () => {
    const q = new GuardedMetricsProvider('test', { maxDistinctLabelSetsPerMetric: 3 });
    const c = q.counter('m', 'h', ['action']);
    c.inc({ action: 'a' });
    c.inc({ action: 'b' });
    c.inc({ action: 'c' });
    c.inc({ action: 'd' });
    c.inc({ action: 'e' }, 10);
    expect(c.collect()).toHaveLength(3);
    expect(q.droppedCounters()).toBe(11);
  });

  it('cardinality cap is per-metric, not global', () => {
    const q = new GuardedMetricsProvider('test', { maxDistinctLabelSetsPerMetric: 2 });
    const a = q.counter('a', '', ['action']);
    const b = q.counter('b', '', ['action']);
    a.inc({ action: 'a1' });
    a.inc({ action: 'a2' });
    a.inc({ action: 'a3' });
    b.inc({ action: 'b1' });
    b.inc({ action: 'b2' });
    expect(a.collect()).toHaveLength(2);
    expect(b.collect()).toHaveLength(2);
  });
});

describe('GuardedMetricsProvider — gauge', () => {
  it('set/inc/dec work', () => {
    const p = new GuardedMetricsProvider('test');
    const g = p.gauge('m', 'h', ['action']);
    g.set({ action: 'a' }, 10);
    expect(g.collect()[0]?.value).toBe(10);
    g.inc({ action: 'a' }, 5);
    expect(g.collect()[0]?.value).toBe(15);
    g.dec({ action: 'a' }, 3);
    expect(g.collect()[0]?.value).toBe(12);
  });

  it('caps distinct label-set cardinality', () => {
    const q = new GuardedMetricsProvider('q', { maxDistinctLabelSetsPerMetric: 1 });
    const g = q.gauge('m', '', ['action']);
    g.set({ action: 'a' }, 1);
    g.set({ action: 'b' }, 1);
    expect(g.collect()).toHaveLength(1);
  });
});

describe('GuardedMetricsProvider — histogram', () => {
  it('observe counts into buckets and updates sum/count', () => {
    const p = new GuardedMetricsProvider('test');
    const h = p.histogram('m', 'h', ['action'], [10, 50, 100]);
    h.observe({ action: 'a' }, 5);
    h.observe({ action: 'a' }, 25);
    h.observe({ action: 'a' }, 75);
    const s = h.collect()[0]!;
    expect(s.count).toBe(3);
    expect(s.sum).toBe(105);
    expect(s.buckets[0]?.count).toBe(1);
    expect(s.buckets[1]?.count).toBe(2);
    expect(s.buckets[2]?.count).toBe(3);
  });

  it('rejects empty bucket list', () => {
    const p = new GuardedMetricsProvider('test');
    expect(() => p.histogram('m', '', [], [])).toThrow(/at least one bucket/);
  });

  it('rejects non-strictly-increasing buckets', () => {
    const p = new GuardedMetricsProvider('test');
    expect(() => p.histogram('m', '', [], [10, 10, 100])).toThrow(/strictly increasing/);
    expect(() => p.histogram('m', '', [], [10, 5])).toThrow(/strictly increasing/);
  });

  it('caps distinct label-set cardinality', () => {
    const q = new GuardedMetricsProvider('q', { maxDistinctLabelSetsPerMetric: 1 });
    const h = q.histogram('m', '', ['action'], [10]);
    h.observe({ action: 'a' }, 1);
    h.observe({ action: 'b' }, 1);
    expect(h.collect()).toHaveLength(1);
  });

  it('drops observations with no allowed labels', () => {
    const p = new GuardedMetricsProvider('test');
    const h = p.histogram('m', '', ['action'], [10]);
    h.observe({}, 1);
    expect(h.collect()).toEqual([]);
  });

  it('reset clears all series', () => {
    const p = new GuardedMetricsProvider('test');
    const h = p.histogram('m', '', ['action'], [10]);
    h.observe({ action: 'a' }, 1);
    h.reset();
    expect(h.collect()).toEqual([]);
  });
});

describe('GuardedMetricsProvider.collect()', () => {
  it('returns a frozen snapshot of all metrics with type/help/samples', () => {
    const p = new GuardedMetricsProvider('test');
    const c = p.counter('requests', 'h', ['action']);
    const g = p.gauge('inflight', 'h', ['action']);
    const h = p.histogram('latency', 'h', ['action'], [1, 5]);
    c.inc({ action: 'a' });
    g.set({ action: 'a' }, 2);
    h.observe({ action: 'a' }, 3);
    const snap = p.collect();
    expect(snap).toHaveLength(3);
    const counter = snap.find((s) => s.name === 'requests')!;
    const gauge = snap.find((s) => s.name === 'inflight')!;
    const hist = snap.find((s) => s.name === 'latency')!;
    expect(counter.type).toBe('counter');
    expect(gauge.type).toBe('gauge');
    expect(hist.type).toBe('histogram');
    expect(counter.samples[0]?.value).toBe(1);
    expect(gauge.samples[0]?.value).toBe(2);
    expect(hist.samples[0]?.count).toBe(1);
  });
});

describe('createCoreMetrics', () => {
  it('registers the seven core metrics with correct label names and help', () => {
    const p = new GuardedMetricsProvider('test');
    const m = createCoreMetrics(p);
    const snap = p.collect();
    const names = snap.map((s) => s.name);
    expect(names).toContain('express_intent_requests_total');
    expect(names).toContain('express_intent_decisions_total');
    expect(names).toContain('express_intent_risk_evaluations_total');
    expect(names).toContain('express_intent_risk_score');
    expect(names).toContain('express_intent_anomalies_total');
    expect(names).toContain('express_intent_rate_limits_total');
    expect(names).toContain('express_intent_evaluation_duration_ms');
    void m;
  });

  it('is safe with NoopMetricsProvider (no throws)', () => {
    const m = createCoreMetrics(new NoopMetricsProvider());
    m.requests.inc({
      action: 'a',
      intent_key: 'k',
      http_method: 'POST',
      http_route: '/x',
      outcome: 'allow',
    });
    m.decisions.inc({ action: 'a', intent_key: 'k', decision: 'allow', severity: 'low' });
    m.riskEvaluations.inc({ action: 'a', intent_key: 'k', severity: 'low' });
    m.riskScore.observe({ action: 'a', intent_key: 'k' }, 50);
    m.anomalies.inc({ action: 'a', anomaly_type: 'velocity', anomaly_confidence_bucket: '50_75' });
    m.rateLimits.inc({ action: 'a', intent_key: 'k', scope: 'actor', outcome: 'allowed' });
    m.evaluationDuration.observe({ action: 'a', intent_key: 'k', decision: 'allow' }, 12);
  });

  it('records real increments on a GuardedMetricsProvider', () => {
    const p = new GuardedMetricsProvider('test');
    const m = createCoreMetrics(p);
    m.requests.inc({
      action: 'users.create',
      intent_key: 'k',
      http_method: 'POST',
      http_route: '/users',
      outcome: 'allow',
    });
    m.requests.inc({
      action: 'users.create',
      intent_key: 'k',
      http_method: 'POST',
      http_route: '/users',
      outcome: 'allow',
    });
    m.decisions.inc({
      action: 'users.create',
      intent_key: 'k',
      decision: 'allow',
      severity: 'low',
    });
    m.riskScore.observe({ action: 'users.create', intent_key: 'k' }, 25);
    const snap = p.collect();
    const req = snap.find((s) => s.name === 'express_intent_requests_total')!;
    expect(req.samples[0]?.value).toBe(2);
    const risk = snap.find((s) => s.name === 'express_intent_risk_score')!;
    expect(risk.samples[0]?.count).toBe(1);
    expect(risk.samples[0]?.sum).toBe(25);
  });
});

describe('confidenceBucket', () => {
  it('buckets 0-1 floats into 4 ranges', () => {
    expect(confidenceBucket(0)).toBe('0_25');
    expect(confidenceBucket(0.1)).toBe('0_25');
    expect(confidenceBucket(0.25)).toBe('25_50');
    expect(confidenceBucket(0.5)).toBe('50_75');
    expect(confidenceBucket(0.75)).toBe('75_100');
    expect(confidenceBucket(1)).toBe('75_100');
    expect(confidenceBucket(-1)).toBe('0');
    expect(confidenceBucket(2)).toBe('over');
  });
});

describe('Prometheus exposition format', () => {
  it('renders counters, gauges, and histograms with HELP and TYPE lines', () => {
    const p = createPrometheusMetricsProvider();
    const m = createCoreMetrics(p);
    m.requests.inc({
      action: 'a',
      intent_key: 'k',
      http_method: 'GET',
      http_route: '/x',
      outcome: 'allow',
    });
    m.requests.inc({
      action: 'a',
      intent_key: 'k',
      http_method: 'GET',
      http_route: '/x',
      outcome: 'allow',
    });
    m.evaluationDuration.observe({ action: 'a', intent_key: 'k', decision: 'allow' }, 25);
    const text = toPrometheusText(p);
    expect(text).toMatch(/# HELP express_intent_requests_total/);
    expect(text).toMatch(/# TYPE express_intent_requests_total counter/);
    expect(text).toMatch(/^express_intent_requests_total\{[^}]+\} 2$/m);
    expect(text).toMatch(/# TYPE express_intent_evaluation_duration_ms histogram/);
    expect(text).toMatch(/^express_intent_evaluation_duration_ms_bucket\{[^}]*le="25"[^}]*\} 1$/m);
    expect(text).toMatch(/^express_intent_evaluation_duration_ms_count\{[^}]*\} 1$/m);
    expect(text).toMatch(/^express_intent_evaluation_duration_ms_sum\{[^}]*\} 25$/m);
  });

  it('escapes label values containing quotes and newlines', () => {
    const p = new GuardedMetricsProvider('test');
    const c = p.counter('m', 'h', ['action']);
    c.inc({ action: 'has "quote" and \\ backslash' });
    const text = toPrometheusText(p);
    expect(text).toContain('action="has \\"quote\\" and \\\\ backslash"');
  });

  it('returns empty string for an unknown provider', () => {
    const text = toPrometheusText(new NoopMetricsProvider());
    expect(text).toBe('');
  });
});

describe('Cardinality safety under attack', () => {
  it('does not blow up when many distinct (but capped) label values arrive', () => {
    const p = new GuardedMetricsProvider('test', { maxDistinctLabelSetsPerMetric: 100 });
    const c = p.counter('m', '', ['action']);
    for (let i = 0; i < 10_000; i++) c.inc({ action: 'a' + i });
    expect(c.collect().length).toBeLessThanOrEqual(100);
    expect(p.droppedCounters()).toBeGreaterThan(0);
  });

  it('truncates huge values rather than emit them', () => {
    const p = new GuardedMetricsProvider('test', { maxLabelValueLength: 32 });
    const c = p.counter('m', '', ['action']);
    c.inc({ action: 'x'.repeat(10_000) });
    expect(c.collect()[0]?.labels['action']!.length).toBe(32);
  });
});

describe('Default cardinality guard', () => {
  it('exposes a sensible allowlist', () => {
    expect(DEFAULT_CARDINALITY_GUARD.allowedLabels).toContain('action');
    expect(DEFAULT_CARDINALITY_GUARD.allowedLabels).toContain('decision');
    expect(DEFAULT_CARDINALITY_GUARD.allowedLabels).toContain('severity');
    expect(DEFAULT_CARDINALITY_GUARD.allowedLabels).toContain('outcome');
    expect(DEFAULT_CARDINALITY_GUARD.allowedLabels).toContain('anomaly_type');
    expect(DEFAULT_CARDINALITY_GUARD.allowedLabels).toContain('http_method');
    expect(DEFAULT_CARDINALITY_GUARD.allowedLabels).toContain('http_route');
    expect(DEFAULT_CARDINALITY_GUARD.allowedLabels).toContain('http_status');
    expect(DEFAULT_CARDINALITY_GUARD.maxLabelValueLength).toBe(64);
    expect(DEFAULT_CARDINALITY_GUARD.maxDistinctLabelSetsPerMetric).toBe(1000);
  });
});

describe('Frozen snapshots', () => {
  it('counter collect() returns frozen labels', () => {
    const p = new GuardedMetricsProvider('test');
    const c: Counter = p.counter('m', '', ['action']);
    c.inc({ action: 'a' });
    const s = c.collect()[0]!;
    expect(Object.isFrozen(s.labels)).toBe(true);
  });

  it('histogram collect() returns frozen bucket arrays', () => {
    const p = new GuardedMetricsProvider('test');
    const h: Histogram = p.histogram('m', '', ['action'], [1, 5, 10]);
    h.observe({ action: 'a' }, 3);
    const s = h.collect()[0]!;
    expect(Object.isFrozen(s.buckets)).toBe(true);
    expect(Object.isFrozen(s.buckets[0])).toBe(true);
  });
});

describe('Same metric shared across callers', () => {
  it('increment from one call shows up in another', () => {
    const p = new GuardedMetricsProvider('test');
    const a = p.counter('shared', '', ['action']);
    const b = p.counter('shared', '', ['action']);
    a.inc({ action: 'x' });
    expect(b.collect()[0]?.value).toBe(1);
  });
});
