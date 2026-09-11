import { describe, it, expect } from 'vitest';
import fc from 'fast-check';

import { evaluateRisk, compareSeverity } from './risk-engine.js';
import { DEFAULT_RISK_CONFIG, DEFAULT_THRESHOLDS, SEVERITY_ORDER } from './risk-config.js';
import type { RiskConfig } from './risk-config.js';
import type { RiskSignal, Severity } from './types.js';

const NOW = 1_700_000_000_000;

function makeSignal(
  partial: Partial<RiskSignal> & {
    name: string;
    value: RiskSignal['value'];
    kind: RiskSignal['kind'];
  },
): RiskSignal {
  return {
    confidence: 1,
    source: 'test',
    computedAt: NOW,
    ttlMs: 60_000,
    ...partial,
  } as RiskSignal;
}

describe('evaluateRisk — normalization primitives', () => {
  it('clamps numeric signals with no range to [0,1]', () => {
    const r = evaluateRisk(
      [makeSignal({ name: 'x', kind: 'numeric', value: 0.42 })],
      { missing: [] },
      {},
      { now: NOW },
    );
    expect(r.score).toBe(42);
    expect(r.severity).toBe<Severity>('low');
  });

  it('linear-interpolates numeric signals with range', () => {
    const cfg: RiskConfig = { signals: { velocity: { weight: 1, range: { min: 0, max: 100 } } } };
    const r = evaluateRisk(
      [makeSignal({ name: 'velocity', kind: 'numeric', value: 25 })],
      { missing: [] },
      cfg,
      { now: NOW },
    );
    expect(r.score).toBe(25);
  });

  it('clamps numeric values to range bounds', () => {
    const cfg: RiskConfig = { signals: { v: { weight: 1, range: { min: 0, max: 10 } } } };
    const r = evaluateRisk(
      [makeSignal({ name: 'v', kind: 'numeric', value: 999 })],
      { missing: [] },
      cfg,
      { now: NOW },
    );
    expect(r.score).toBe(100);
    expect(r.breakdown[0]?.reason).toBe('above-range');
  });

  it('inverts numeric range when invert=true', () => {
    const cfg: RiskConfig = {
      signals: { trust: { weight: 1, range: { min: 0, max: 100, invert: true } } },
    };
    const high = evaluateRisk(
      [makeSignal({ name: 'trust', kind: 'numeric', value: 80 })],
      { missing: [] },
      cfg,
      { now: NOW },
    );
    expect(high.score).toBeLessThan(50);
    const low = evaluateRisk(
      [makeSignal({ name: 'trust', kind: 'numeric', value: 10 })],
      { missing: [] },
      cfg,
      { now: NOW },
    );
    expect(low.score).toBeGreaterThan(50);
  });

  it('categorical lookup maps known values to configured scores', () => {
    const cfg: RiskConfig = {
      signals: { device: { weight: 1, categorical: { trusted: 0, unknown: 1, blocked: 1 } } },
    };
    const r = evaluateRisk(
      [makeSignal({ name: 'device', kind: 'categorical', value: 'blocked' })],
      { missing: [] },
      cfg,
      { now: NOW },
    );
    expect(r.score).toBe(100);
  });

  it('categorical miss contributes zero', () => {
    const cfg: RiskConfig = { signals: { device: { weight: 1, categorical: { trusted: 0 } } } };
    const r = evaluateRisk(
      [makeSignal({ name: 'device', kind: 'categorical', value: 'rogue' })],
      { missing: [] },
      cfg,
      { now: NOW },
    );
    expect(r.score).toBe(0);
    expect(r.breakdown[0]?.reason).toBe('categorical-miss');
  });

  it('boolean signals map to {false:0, true:1}', () => {
    const cfg: RiskConfig = { signals: { mfa: { weight: 1 } } };
    const no = evaluateRisk(
      [makeSignal({ name: 'mfa', kind: 'boolean', value: false })],
      { missing: [] },
      cfg,
      { now: NOW },
    );
    const yes = evaluateRisk(
      [makeSignal({ name: 'mfa', kind: 'boolean', value: true })],
      { missing: [] },
      cfg,
      { now: NOW },
    );
    expect(no.score).toBe(0);
    expect(yes.score).toBe(100);
  });

  it('null-valued signals are treated as missing', () => {
    const cfg: RiskConfig = { signals: { geo: { weight: 1 } } };
    const r = evaluateRisk(
      [makeSignal({ name: 'geo', kind: 'categorical', value: null })],
      { missing: [] },
      cfg,
      { now: NOW },
    );
    expect(r.score).toBe(0);
    expect(r.breakdown[0]?.reason).toBe('missing');
  });
});

describe('evaluateRisk — aggregation', () => {
  it('weighted average across multiple signals', () => {
    const cfg: RiskConfig = {
      signals: {
        a: { weight: 1 },
        b: { weight: 3 },
      },
    };
    const r = evaluateRisk(
      [
        makeSignal({ name: 'a', kind: 'numeric', value: 1 }), // 100
        makeSignal({ name: 'b', kind: 'numeric', value: 0 }), // 0
      ],
      { missing: [] },
      cfg,
      { now: NOW },
    );
    expect(r.score).toBe(25);
  });

  it('confidence multiplies contribution', () => {
    const cfg: RiskConfig = { signals: { a: { weight: 1 } } };
    const r = evaluateRisk(
      [makeSignal({ name: 'a', kind: 'numeric', value: 1, confidence: 0.5 })],
      { missing: [] },
      cfg,
      { now: NOW },
    );
    expect(r.score).toBe(50);
  });

  it('expired signals (age > ttlMs) contribute zero', () => {
    const cfg: RiskConfig = { signals: { a: { weight: 1 } } };
    const r = evaluateRisk(
      [makeSignal({ name: 'a', kind: 'numeric', value: 1, ttlMs: 100, computedAt: NOW - 1000 })],
      { missing: [] },
      cfg,
      { now: NOW },
    );
    expect(r.score).toBe(0);
    expect(r.breakdown[0]?.reason).toBe('expired');
  });

  it('time decay reduces contribution', () => {
    const cfg: RiskConfig = {
      signals: { a: { weight: 1, decay: { halfLifeMs: 1000, floor: 0 } } },
    };
    const fresh = evaluateRisk(
      [makeSignal({ name: 'a', kind: 'numeric', value: 1, computedAt: NOW, ttlMs: 60_000 })],
      { missing: [] },
      cfg,
      { now: NOW },
    );
    const aged = evaluateRisk(
      [makeSignal({ name: 'a', kind: 'numeric', value: 1, computedAt: NOW - 1000, ttlMs: 60_000 })],
      { missing: [] },
      cfg,
      { now: NOW },
    );
    expect(fresh.score).toBe(100);
    expect(aged.score).toBe(50);
  });

  it('time decay respects the floor', () => {
    const cfg: RiskConfig = {
      signals: { a: { weight: 1, decay: { halfLifeMs: 100, floor: 0.5 } } },
    };
    const r = evaluateRisk(
      [
        makeSignal({
          name: 'a',
          kind: 'numeric',
          value: 1,
          computedAt: NOW - 10_000,
          ttlMs: 60_000,
        }),
      ],
      { missing: [] },
      cfg,
      { now: NOW },
    );
    expect(r.score).toBe(50);
  });

  it('zero-weighted signals contribute zero and reduce total weight', () => {
    const cfg: RiskConfig = {
      signals: {
        a: { weight: 1 },
        b: { weight: 0 },
      },
    };
    const r = evaluateRisk(
      [
        makeSignal({ name: 'a', kind: 'numeric', value: 1 }),
        makeSignal({ name: 'b', kind: 'numeric', value: 1 }),
      ],
      { missing: [] },
      cfg,
      { now: NOW },
    );
    expect(r.score).toBe(100);
    expect(r.breakdown.find((b) => b.name === 'b')?.reason).toBe('no-weight');
  });

  it('missing signals are accounted for with weight but zero contribution', () => {
    const cfg: RiskConfig = {
      signals: {
        a: { weight: 1 },
        missing1: { weight: 1 },
      },
    };
    const r = evaluateRisk(
      [makeSignal({ name: 'a', kind: 'numeric', value: 1 })],
      { missing: ['missing1'] },
      cfg,
      { now: NOW },
    );
    expect(r.score).toBe(50);
    expect(r.breakdown.some((b) => b.name === 'missing1' && b.reason === 'missing')).toBe(true);
  });

  it('no signals yields zero score and low severity', () => {
    const r = evaluateRisk([], { missing: [] }, {}, { now: NOW });
    expect(r.score).toBe(0);
    expect(r.severity).toBe('low');
  });
});

describe('evaluateRisk — severity thresholds', () => {
  const cfg: RiskConfig = { signals: { a: { weight: 1 } } };

  it('classifies by configured thresholds', () => {
    const low = evaluateRisk(
      [makeSignal({ name: 'a', kind: 'numeric', value: 0.2 })],
      { missing: [] },
      cfg,
      { now: NOW },
    );
    const med = evaluateRisk(
      [makeSignal({ name: 'a', kind: 'numeric', value: 0.5 })],
      { missing: [] },
      cfg,
      { now: NOW },
    );
    const high = evaluateRisk(
      [makeSignal({ name: 'a', kind: 'numeric', value: 0.8 })],
      { missing: [] },
      cfg,
      { now: NOW },
    );
    const crit = evaluateRisk(
      [makeSignal({ name: 'a', kind: 'numeric', value: 1 })],
      { missing: [] },
      cfg,
      { now: NOW },
    );
    expect(low.severity).toBe('low');
    expect(med.severity).toBe('medium');
    expect(high.severity).toBe('high');
    expect(crit.severity).toBe('critical');
  });

  it('uses default thresholds when none configured', () => {
    expect(DEFAULT_THRESHOLDS).toEqual({ low: 25, medium: 50, high: 75, critical: 90 });
  });

  it('honours custom thresholds', () => {
    const cfg: RiskConfig = {
      thresholds: { low: 10, medium: 20, high: 30, critical: 40 },
      signals: { a: { weight: 1 } },
    };
    const r = evaluateRisk(
      [makeSignal({ name: 'a', kind: 'numeric', value: 0.45 })],
      { missing: [] },
      cfg,
      { now: NOW },
    );
    expect(r.severity).toBe('critical');
  });

  it('compareSeverity matches SEVERITY_ORDER', () => {
    expect(SEVERITY_ORDER).toEqual(['low', 'medium', 'high', 'critical']);
    expect(compareSeverity('critical', 'low')).toBeGreaterThan(0);
    expect(compareSeverity('low', 'critical')).toBeLessThan(0);
    expect(compareSeverity('high', 'high')).toBe(0);
  });
});

describe('evaluateRisk — determinism', () => {
  it('produces identical outputs for identical inputs', () => {
    const cfg: RiskConfig = {
      signals: {
        a: { weight: 2, range: { min: 0, max: 100 } },
        b: { weight: 1, categorical: { yes: 1, no: 0 } },
      },
    };
    const signals = [
      makeSignal({ name: 'b', kind: 'categorical', value: 'yes' }),
      makeSignal({ name: 'a', kind: 'numeric', value: 80 }),
    ];
    const r1 = evaluateRisk(signals, { missing: ['c'] }, cfg, { now: NOW });
    const r2 = evaluateRisk(signals, { missing: ['c'] }, cfg, { now: NOW });
    expect(r1.score).toBe(r2.score);
    expect(r1.severity).toBe(r2.severity);
    expect(r1.breakdown).toEqual(r2.breakdown);
    expect(r1.risk.aggregationHash).toBe(r2.risk.aggregationHash);
  });

  it('produces identical outputs regardless of signal order', () => {
    const cfg: RiskConfig = { signals: { a: { weight: 1 }, b: { weight: 1 } } };
    const s1 = [makeSignal({ name: 'b', kind: 'numeric', value: 0.5 })];
    const s2 = [makeSignal({ name: 'a', kind: 'numeric', value: 0.5 })];
    const r1 = evaluateRisk(
      [s1[0]!, makeSignal({ name: 'a', kind: 'numeric', value: 0.5 })],
      { missing: [] },
      cfg,
      { now: NOW },
    );
    const r2 = evaluateRisk(
      [s1[0]!, makeSignal({ name: 'a', kind: 'numeric', value: 0.5 })].reverse(),
      { missing: [] },
      cfg,
      { now: NOW },
    );
    expect(r1.score).toBe(r2.score);
    expect(r1.breakdown).toEqual(r2.breakdown);
    void s2;
  });

  it('breakdown is sorted by signal name', () => {
    const cfg: RiskConfig = { signals: { a: { weight: 1 }, z: { weight: 1 }, m: { weight: 1 } } };
    const r = evaluateRisk(
      [
        makeSignal({ name: 'z', kind: 'numeric', value: 1 }),
        makeSignal({ name: 'a', kind: 'numeric', value: 0 }),
        makeSignal({ name: 'm', kind: 'numeric', value: 0.5 }),
      ],
      { missing: [] },
      cfg,
      { now: NOW },
    );
    const names = r.breakdown.map((b) => b.name);
    expect(names).toEqual([...names].sort());
  });

  it('risk.aggregationHash is stable length', () => {
    const r = evaluateRisk([], { missing: [] }, {}, { now: NOW });
    expect(r.risk.aggregationHash).toHaveLength(16);
  });
});

describe('evaluateRisk — boundedness', () => {
  it('score is always within [0, 100]', () => {
    fc.assert(
      fc.property(
        fc.array(
          fc.record({
            name: fc
              .string({ minLength: 1, maxLength: 20 })
              .map((s) => `s${Math.abs(fc.hash(s)) % 10}`),
            kind: fc.constantFrom<'numeric' | 'categorical' | 'boolean'>(
              'numeric',
              'categorical',
              'boolean',
            ),
            value: fc.oneof(
              fc.double({ min: -1000, max: 1000, noNaN: true }),
              fc.string({ maxLength: 10 }),
              fc.boolean(),
            ),
            confidence: fc.double({ min: 0, max: 1, noNaN: true }),
            computedAt: fc.integer({ min: NOW - 100_000, max: NOW }),
            ttlMs: fc.integer({ min: 1, max: 60_000 }),
          }),
          { maxLength: 6 },
        ),
        (signals) => {
          const sigs = signals.map((s) => makeSignal(s));
          const r = evaluateRisk(sigs, { missing: [] }, {}, { now: NOW });
          expect(r.score).toBeGreaterThanOrEqual(0);
          expect(r.score).toBeLessThanOrEqual(100);
          expect(Number.isFinite(r.score)).toBe(true);
        },
      ),
      { numRuns: 200 },
    );
  });

  it('score is monotonic in the normalized value of a single signal', () => {
    const cfg: RiskConfig = { signals: { a: { weight: 1 } } };
    fc.assert(
      fc.property(
        fc.double({ min: 0, max: 1, noNaN: true }),
        fc.double({ min: 0, max: 1, noNaN: true }),
        (a, b) => {
          const ra = evaluateRisk(
            [makeSignal({ name: 'a', kind: 'numeric', value: a })],
            { missing: [] },
            cfg,
            { now: NOW },
          );
          const rb = evaluateRisk(
            [makeSignal({ name: 'a', kind: 'numeric', value: b })],
            { missing: [] },
            cfg,
            { now: NOW },
          );
          if (a < b) expect(ra.score).toBeLessThanOrEqual(rb.score);
          else if (a > b) expect(ra.score).toBeGreaterThanOrEqual(rb.score);
          else expect(ra.score).toBe(rb.score);
        },
      ),
      { numRuns: 100 },
    );
  });

  it('idempotent: re-running with the same data yields the same output', () => {
    fc.assert(
      fc.property(
        fc.array(
          fc.record({
            name: fc.constantFrom('a', 'b', 'c'),
            kind: fc.constantFrom<'numeric'>('numeric'),
            value: fc.double({ min: 0, max: 1, noNaN: true }),
          }),
          { maxLength: 3 },
        ),
        (items) => {
          const sigs = items.map((i) => makeSignal(i));
          const r1 = evaluateRisk(
            sigs,
            { missing: [] },
            { signals: { a: { weight: 1 }, b: { weight: 1 }, c: { weight: 1 } } },
            { now: NOW },
          );
          const r2 = evaluateRisk(
            sigs,
            { missing: [] },
            { signals: { a: { weight: 1 }, b: { weight: 1 }, c: { weight: 1 } } },
            { now: NOW },
          );
          expect(r1.score).toBe(r2.score);
          expect(r1.severity).toBe(r2.severity);
          expect(r1.breakdown).toEqual(r2.breakdown);
        },
      ),
      { numRuns: 100 },
    );
  });

  it('severity is always one of the four values', () => {
    const sig = makeSignal({ name: 'a', kind: 'numeric', value: 0.5 });
    const allowed = new Set(['low', 'medium', 'high', 'critical']);
    fc.assert(
      fc.property(fc.double({ min: 0, max: 1, noNaN: true }), (v) => {
        const r = evaluateRisk(
          [makeSignal({ name: 'a', kind: 'numeric', value: v })],
          { missing: [] },
          {},
          { now: NOW },
        );
        expect(allowed.has(r.severity)).toBe(true);
      }),
      { numRuns: 50 },
    );
    void sig;
  });
});

describe('evaluateRisk — NaN/Infinity safety', () => {
  it('treats NaN as zero', () => {
    const cfg: RiskConfig = { signals: { a: { weight: 1 } } };
    const r = evaluateRisk(
      [makeSignal({ name: 'a', kind: 'numeric', value: NaN })],
      { missing: [] },
      cfg,
      { now: NOW },
    );
    expect(r.score).toBe(0);
  });

  it('clamps out-of-range numeric values to range bounds', () => {
    const cfg: RiskConfig = { signals: { a: { weight: 1, range: { min: 0, max: 1 } } } };
    const r1 = evaluateRisk(
      [makeSignal({ name: 'a', kind: 'numeric', value: 5 })],
      { missing: [] },
      cfg,
      { now: NOW },
    );
    const r2 = evaluateRisk(
      [makeSignal({ name: 'a', kind: 'numeric', value: -5 })],
      { missing: [] },
      cfg,
      { now: NOW },
    );
    expect(r1.score).toBe(100);
    expect(r2.score).toBe(0);
  });
});

describe('evaluateRisk — default config sanity', () => {
  it('defaultWeight = 1 and thresholds = DEFAULT_THRESHOLDS', () => {
    expect(DEFAULT_RISK_CONFIG.defaultWeight).toBe(1);
    expect(DEFAULT_RISK_CONFIG.thresholds).toEqual(DEFAULT_THRESHOLDS);
  });

  it('returns frozen evaluation result', () => {
    const r = evaluateRisk([], { missing: [] }, {}, { now: NOW });
    expect(Object.isFrozen(r)).toBe(true);
    expect(Object.isFrozen(r.breakdown)).toBe(true);
    expect(Object.isFrozen(r.risk)).toBe(true);
  });
});
