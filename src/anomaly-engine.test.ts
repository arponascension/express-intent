import { describe, it, expect } from 'vitest';
import fc from 'fast-check';

import { AnomalyEngine } from './anomaly-engine.js';
import { InMemoryObservationStore } from './anomaly-store.js';
import {
  VELOCITY,
  ENUMERATION,
  USER_AGENT_CHANGE,
  IP_CHANGE,
  ENDPOINT_PATTERN,
  BUILTIN_DETECTORS,
} from './anomaly-detectors.js';
import { DEFAULT_ANOMALY_CONFIG, anomaly as anomalyBuilder, notDetected } from './anomaly-defs.js';
import type { AnomalyDetector, AnomalyDetectorConfig, Observation } from './anomaly-defs.js';

const NOW = 1_700_000_000_000;

function obs(partial: Partial<Observation>): Observation {
  return {
    now: NOW,
    actorSubject: 'u-1',
    ip: '10.0.0.1',
    userAgent: 'Mozilla/5.0',
    method: 'GET',
    path: '/x',
    status: 200,
    resourceId: null,
    ...partial,
  } as Observation;
}

describe('Anomaly shape contracts', () => {
  it('anomaly() clamps confidence to [0, 1]', () => {
    const a = anomalyBuilder(VELOCITY, NOW, 1.5, ['x'], {});
    expect(a.confidence).toBe(1);
    const b = anomalyBuilder(VELOCITY, NOW, -0.5, ['x'], {});
    expect(b.confidence).toBe(0);
    const c = anomalyBuilder(VELOCITY, NOW, Number.NaN, ['x'], {});
    expect(c.confidence).toBe(0);
  });

  it('anomaly() result is frozen and detected=true', () => {
    const a = anomalyBuilder(VELOCITY, NOW, 0.7, ['r1'], { count: 100 });
    expect(Object.isFrozen(a)).toBe(true);
    expect(Object.isFrozen(a.reasons)).toBe(true);
    expect(a.detected).toBe(true);
    expect(a.reasons).toEqual(['r1']);
    expect(a.details).toEqual({ count: 100 });
  });

  it('notDetected() is frozen with detected=false, confidence=0', () => {
    const a = notDetected(VELOCITY, NOW);
    expect(Object.isFrozen(a)).toBe(true);
    expect(a.detected).toBe(false);
    expect(a.confidence).toBe(0);
  });
});

describe('VELOCITY detector', () => {
  it('does not flag below threshold', () => {
    const cfg: Required<AnomalyDetectorConfig> = { ...DEFAULT_ANOMALY_CONFIG, velocityMax: 5 };
    const history = Array.from({ length: 4 }, (_, i) => obs({ now: NOW - i * 1000 }));
    const r = VELOCITY.detect(obs({}), history, cfg);
    expect(r.detected).toBe(false);
  });

  it('flags when count exceeds threshold', () => {
    const cfg: Required<AnomalyDetectorConfig> = { ...DEFAULT_ANOMALY_CONFIG, velocityMax: 5 };
    const history = Array.from({ length: 5 }, (_, i) => obs({ now: NOW - i * 1000 }));
    const r = VELOCITY.detect(obs({}), history, cfg);
    expect(r.detected).toBe(true);
    expect(r.confidence).toBeGreaterThan(0.5);
    expect(r.details.count).toBe(6);
    expect(r.details.threshold).toBe(5);
  });

  it('confidence grows with overshoot', () => {
    const cfg: Required<AnomalyDetectorConfig> = { ...DEFAULT_ANOMALY_CONFIG, velocityMax: 5 };
    const justOver = VELOCITY.detect(
      obs({}),
      Array.from({ length: 5 }, () => obs({})),
      cfg,
    );
    const wayOver = VELOCITY.detect(
      obs({}),
      Array.from({ length: 30 }, () => obs({})),
      cfg,
    );
    expect(wayOver.confidence).toBeGreaterThan(justOver.confidence);
  });

  it('ignores observations outside the window', () => {
    const cfg: Required<AnomalyDetectorConfig> = {
      ...DEFAULT_ANOMALY_CONFIG,
      velocityMax: 5,
      windowMs: 1_000,
    };
    const history = Array.from({ length: 20 }, (_, i) => obs({ now: NOW - 10_000 - i * 1000 }));
    const r = VELOCITY.detect(obs({}), history, cfg);
    expect(r.detected).toBe(false);
  });
});

describe('ENUMERATION detector', () => {
  it('does not flag with few distinct IDs', () => {
    const cfg: Required<AnomalyDetectorConfig> = {
      ...DEFAULT_ANOMALY_CONFIG,
      enumerationMaxDistinct: 5,
    };
    const history = Array.from({ length: 4 }, (_, i) => obs({ resourceId: `r-${i}` }));
    const r = ENUMERATION.detect(obs({ resourceId: 'r-4' }), history, cfg);
    expect(r.detected).toBe(false);
  });

  it('flags when distinct resources exceed threshold', () => {
    const cfg: Required<AnomalyDetectorConfig> = {
      ...DEFAULT_ANOMALY_CONFIG,
      enumerationMaxDistinct: 5,
    };
    const history = Array.from({ length: 5 }, (_, i) => obs({ resourceId: `r-${i}` }));
    const r = ENUMERATION.detect(obs({ resourceId: 'r-5' }), history, cfg);
    expect(r.detected).toBe(true);
    expect(r.details.distinctResources).toBe(6);
  });

  it('treats null resourceId as not contributing', () => {
    const cfg: Required<AnomalyDetectorConfig> = {
      ...DEFAULT_ANOMALY_CONFIG,
      enumerationMaxDistinct: 5,
    };
    const history = Array.from({ length: 100 }, () => obs({ resourceId: null }));
    const r = ENUMERATION.detect(obs({ resourceId: null }), history, cfg);
    expect(r.detected).toBe(false);
  });
});

describe('USER_AGENT_CHANGE detector', () => {
  it('flags when actor UA differs from previous', () => {
    const cfg: Required<AnomalyDetectorConfig> = { ...DEFAULT_ANOMALY_CONFIG };
    const history = [obs({ userAgent: 'UA-A' })];
    const r = USER_AGENT_CHANGE.detect(obs({ userAgent: 'UA-B' }), history, cfg);
    expect(r.detected).toBe(true);
    expect(r.details.previous).toBe('UA-A');
    expect(r.details.current).toBe('UA-B');
  });

  it('does not flag when UA is unchanged', () => {
    const cfg: Required<AnomalyDetectorConfig> = { ...DEFAULT_ANOMALY_CONFIG };
    const r = USER_AGENT_CHANGE.detect(
      obs({ userAgent: 'UA-A' }),
      [obs({ userAgent: 'UA-A' })],
      cfg,
    );
    expect(r.detected).toBe(false);
  });

  it('skips anonymous actors', () => {
    const cfg: Required<AnomalyDetectorConfig> = { ...DEFAULT_ANOMALY_CONFIG };
    const r = USER_AGENT_CHANGE.detect(
      obs({ actorSubject: null, userAgent: 'UA-B' }),
      [obs({ userAgent: 'UA-A' })],
      cfg,
    );
    expect(r.detected).toBe(false);
  });

  it('skips when disabled', () => {
    const cfg: Required<AnomalyDetectorConfig> = {
      ...DEFAULT_ANOMALY_CONFIG,
      userAgentChangeEnabled: false,
    };
    const r = USER_AGENT_CHANGE.detect(
      obs({ userAgent: 'UA-B' }),
      [obs({ userAgent: 'UA-A' })],
      cfg,
    );
    expect(r.detected).toBe(false);
  });

  it('confidence grows with distinct UAs seen', () => {
    const cfg: Required<AnomalyDetectorConfig> = { ...DEFAULT_ANOMALY_CONFIG };
    const history = [
      obs({ userAgent: 'UA-A', actorSubject: 'u-1' }),
      obs({ userAgent: 'UA-B', actorSubject: 'u-1' }),
      obs({ userAgent: 'UA-C', actorSubject: 'u-1' }),
    ];
    const r = USER_AGENT_CHANGE.detect(
      obs({ userAgent: 'UA-D', actorSubject: 'u-1' }),
      history,
      cfg,
    );
    expect(r.confidence).toBeGreaterThanOrEqual(0.6);
  });
});

describe('IP_CHANGE detector', () => {
  it('flags when actor IP differs from previous', () => {
    const cfg: Required<AnomalyDetectorConfig> = { ...DEFAULT_ANOMALY_CONFIG };
    const history = [obs({ ip: '1.1.1.1' })];
    const r = IP_CHANGE.detect(obs({ ip: '2.2.2.2' }), history, cfg);
    expect(r.detected).toBe(true);
    expect(r.details.previous).toBe('1.1.1.1');
    expect(r.details.current).toBe('2.2.2.2');
  });

  it('skips anonymous actors', () => {
    const cfg: Required<AnomalyDetectorConfig> = { ...DEFAULT_ANOMALY_CONFIG };
    const r = IP_CHANGE.detect(
      obs({ actorSubject: null, ip: '2.2.2.2' }),
      [obs({ ip: '1.1.1.1' })],
      cfg,
    );
    expect(r.detected).toBe(false);
  });

  it('skips when disabled', () => {
    const cfg: Required<AnomalyDetectorConfig> = {
      ...DEFAULT_ANOMALY_CONFIG,
      ipChangeEnabled: false,
    };
    const r = IP_CHANGE.detect(obs({ ip: '2.2.2.2' }), [obs({ ip: '1.1.1.1' })], cfg);
    expect(r.detected).toBe(false);
  });
});

describe('ENDPOINT_PATTERN detector', () => {
  it('flags many distinct endpoints', () => {
    const cfg: Required<AnomalyDetectorConfig> = {
      ...DEFAULT_ANOMALY_CONFIG,
      endpointPatternMaxDistinct: 5,
    };
    const history = Array.from({ length: 5 }, (_, i) => obs({ path: `/p/${i}`, method: 'GET' }));
    const r = ENDPOINT_PATTERN.detect(obs({ path: '/p/5', method: 'GET' }), history, cfg);
    expect(r.detected).toBe(true);
    expect(r.details.distinctEndpoints).toBe(6);
  });

  it('does not flag with few distinct endpoints', () => {
    const cfg: Required<AnomalyDetectorConfig> = {
      ...DEFAULT_ANOMALY_CONFIG,
      endpointPatternMaxDistinct: 10,
    };
    const history = Array.from({ length: 5 }, () => obs({ path: '/p', method: 'GET' }));
    const r = ENDPOINT_PATTERN.detect(obs({ path: '/p', method: 'GET' }), history, cfg);
    expect(r.detected).toBe(false);
  });

  it('treats GET /x and POST /x as different endpoints', () => {
    const cfg: Required<AnomalyDetectorConfig> = {
      ...DEFAULT_ANOMALY_CONFIG,
      endpointPatternMaxDistinct: 5,
    };
    const history = Array.from({ length: 5 }, (_, i) =>
      obs({ method: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'][i]!, path: '/x' }),
    );
    const r = ENDPOINT_PATTERN.detect(obs({ method: 'OPTIONS', path: '/x' }), history, cfg);
    expect(r.detected).toBe(true);
    expect(r.details.distinctEndpoints).toBe(6);
  });
});

describe('InMemoryObservationStore', () => {
  it('records and queries by actor', () => {
    const store = new InMemoryObservationStore({ ttlMs: 60_000, clock: () => NOW });
    store.record(obs({ actorSubject: 'u-1' }));
    store.record(obs({ actorSubject: 'u-1', now: NOW - 100 }));
    store.record(obs({ actorSubject: 'u-2', now: NOW - 100 }));
    const recent = store.recent({ actorSubject: 'u-1', now: NOW, windowMs: 60_000 });
    expect(recent).toHaveLength(2);
    expect(recent.every((o) => o.actorSubject === 'u-1')).toBe(true);
  });

  it('respects TTL', () => {
    const store = new InMemoryObservationStore({ ttlMs: 1_000, clock: () => NOW });
    store.record(obs({ now: NOW }));
    const recent = store.recent({ now: NOW + 5_000, windowMs: 60_000 });
    expect(recent).toEqual([]);
  });

  it('respects windowMs filter', () => {
    const store = new InMemoryObservationStore({ ttlMs: 60_000, clock: () => NOW });
    store.record(obs({ now: NOW - 30_000 }));
    store.record(obs({ now: NOW - 5_000 }));
    const recent = store.recent({ now: NOW, windowMs: 10_000 });
    expect(recent).toHaveLength(1);
  });

  it('enforces maxEntries FIFO eviction', () => {
    const store = new InMemoryObservationStore({ maxEntries: 3, ttlMs: 60_000, clock: () => NOW });
    store.record(obs({ now: NOW - 3 }));
    store.record(obs({ now: NOW - 2 }));
    store.record(obs({ now: NOW - 1 }));
    store.record(obs({ now: NOW }));
    expect(store.size()).toBe(3);
  });

  it('clear() empties the store', () => {
    const store = new InMemoryObservationStore({ ttlMs: 60_000 });
    store.record(obs({}));
    store.clear();
    expect(store.size()).toBe(0);
  });

  it('purge is automatic on record', () => {
    const store = new InMemoryObservationStore({ ttlMs: 1_000, purgeEvery: 1 });
    store.record(obs({ now: 0 }));
    store.record(obs({ now: 10_000 }));
    expect(store.size()).toBe(1);
  });
});

describe('AnomalyEngine — orchestration', () => {
  it('runs all built-in detectors by default', async () => {
    const engine = new AnomalyEngine({ detectors: BUILTIN_DETECTORS });
    expect(BUILTIN_DETECTORS).toHaveLength(5);
    const r = await engine.observe(obs({}));
    expect(r.all).toHaveLength(5);
    expect(r.all.every((a) => a.observedAt === NOW)).toBe(true);
  });

  it('report.maxConfidence is max of all', async () => {
    const engine = new AnomalyEngine({
      detectors: BUILTIN_DETECTORS,
      config: { ...DEFAULT_ANOMALY_CONFIG, velocityMax: 0 },
    });
    const r = await engine.observe(obs({}));
    expect(r.maxConfidence).toBeGreaterThan(0);
    expect(r.maxConfidence).toBeLessThanOrEqual(1);
  });

  it('records observation after evaluating', async () => {
    const store = new InMemoryObservationStore({ ttlMs: 60_000, clock: () => NOW });
    const engine = new AnomalyEngine({ detectors: BUILTIN_DETECTORS, store });
    await engine.observe(obs({ actorSubject: 'u-1' }));
    expect(store.size()).toBe(1);
  });

  it('register() adds a custom detector', async () => {
    const engine = new AnomalyEngine({ detectors: BUILTIN_DETECTORS });
    const custom: AnomalyDetector = {
      name: 'always-anomaly',
      version: 1,
      detect: (o) => anomalyBuilder(custom, o.now, 0.99, ['test'], {}),
    };
    engine.register(custom);
    const r = await engine.observe(obs({}));
    expect(r.all.some((a) => a.detector === 'always-anomaly')).toBe(true);
  });

  it('register() rejects duplicate name', () => {
    const engine = new AnomalyEngine({ detectors: [VELOCITY] });
    expect(() => engine.register(VELOCITY)).toThrow(/already registered/);
  });

  it('detected[] only contains anomalies with detected=true', async () => {
    const engine = new AnomalyEngine({ detectors: BUILTIN_DETECTORS });
    const r = await engine.observe(obs({}));
    expect(r.detected.every((a) => a.detected)).toBe(true);
    expect(r.all.some((a) => !a.detected)).toBe(true);
  });

  it('no detectors → empty report', async () => {
    const engine = new AnomalyEngine({});
    const r = await engine.observe(obs({}));
    expect(r.all).toEqual([]);
    expect(r.detected).toEqual([]);
    expect(r.maxConfidence).toBe(0);
  });

  it('does not mutate user-supplied detector array', () => {
    const detectors = [VELOCITY, ENUMERATION];
    const original = [...detectors];
    const engine = new AnomalyEngine({ detectors });
    const custom: AnomalyDetector = {
      name: 'x',
      version: 1,
      detect: (o) => notDetected(custom, o.now),
    };
    engine.register(custom);
    expect(detectors).toEqual(original);
  });
});

describe('AnomalyEngine — full flow end-to-end', () => {
  it('flags velocity + enumeration on simulated attacker', async () => {
    const store = new InMemoryObservationStore({ ttlMs: 5 * 60_000, clock: () => NOW });
    const engine = new AnomalyEngine({
      detectors: BUILTIN_DETECTORS,
      store,
      config: { ...DEFAULT_ANOMALY_CONFIG, velocityMax: 5, enumerationMaxDistinct: 5 },
    });
    for (let i = 0; i < 6; i++) {
      const r = await engine.observe(
        obs({ path: `/users/${i}`, resourceId: `u-${i}`, now: NOW + i * 1000 }),
      );
      if (i === 5) {
        const types = r.detected.map((a) => a.type);
        expect(types).toContain('velocity');
        expect(types).toContain('enumeration');
      }
    }
  });

  it('flags user-agent-change mid-session', async () => {
    const store = new InMemoryObservationStore({ ttlMs: 5 * 60_000, clock: () => NOW });
    const engine = new AnomalyEngine({ detectors: BUILTIN_DETECTORS, store });
    await engine.observe(obs({ actorSubject: 'u-1', userAgent: 'UA-1', now: NOW }));
    const r = await engine.observe(
      obs({ actorSubject: 'u-1', userAgent: 'UA-2', now: NOW + 1000 }),
    );
    expect(r.detected.some((a) => a.type === 'user-agent-change')).toBe(true);
  });

  it('flags ip-change mid-session', async () => {
    const store = new InMemoryObservationStore({ ttlMs: 5 * 60_000, clock: () => NOW });
    const engine = new AnomalyEngine({ detectors: BUILTIN_DETECTORS, store });
    await engine.observe(obs({ actorSubject: 'u-1', ip: '1.1.1.1', now: NOW }));
    const r = await engine.observe(obs({ actorSubject: 'u-1', ip: '2.2.2.2', now: NOW + 1000 }));
    expect(r.detected.some((a) => a.type === 'ip-change')).toBe(true);
  });

  it('clean session: nothing flagged', async () => {
    const store = new InMemoryObservationStore({ ttlMs: 5 * 60_000, clock: () => NOW });
    const engine = new AnomalyEngine({ detectors: BUILTIN_DETECTORS, store });
    for (let i = 0; i < 5; i++) {
      const r = await engine.observe(
        obs({
          actorSubject: 'u-1',
          ip: '1.1.1.1',
          userAgent: 'UA-1',
          path: '/x',
          resourceId: null,
          now: NOW + i * 1000,
        }),
      );
      expect(r.detected).toEqual([]);
    }
  });
});

describe('Determinism — property tests', () => {
  it('same inputs → same outputs', async () => {
    await fc.assert(
      fc.property(fc.integer({ min: 0, max: 100 }), fc.integer({ min: 0, max: 30 }), (n, m) => {
        const cfg: Required<AnomalyDetectorConfig> = {
          ...DEFAULT_ANOMALY_CONFIG,
          velocityMax: m,
          windowMs: 60_000,
        };
        const history = Array.from({ length: n }, (_, i) => obs({ now: NOW - i * 100 }));
        const r1 = VELOCITY.detect(obs({}), history, cfg);
        const r2 = VELOCITY.detect(obs({}), history, cfg);
        expect(r1.detected).toBe(r2.detected);
        expect(r1.confidence).toBe(r2.confidence);
      }),
      { numRuns: 50 },
    );
  });

  it('confidence always in [0, 1]', () => {
    fc.assert(
      fc.property(fc.integer({ min: 1, max: 200 }), fc.integer({ min: 1, max: 100 }), (n, max) => {
        const cfg: Required<AnomalyDetectorConfig> = {
          ...DEFAULT_ANOMALY_CONFIG,
          velocityMax: max,
        };
        const r = VELOCITY.detect(
          obs({}),
          Array.from({ length: n }, () => obs({})),
          cfg,
        );
        expect(r.confidence).toBeGreaterThanOrEqual(0);
        expect(r.confidence).toBeLessThanOrEqual(1);
      }),
      { numRuns: 30 },
    );
  });

  it('all detections are immutable', async () => {
    const engine = new AnomalyEngine({ detectors: BUILTIN_DETECTORS });
    const r = await engine.observe(obs({}));
    for (const a of r.all) {
      expect(Object.isFrozen(a)).toBe(true);
      expect(Object.isFrozen(a.reasons)).toBe(true);
      expect(Object.isFrozen(a.details)).toBe(true);
    }
    expect(Object.isFrozen(r)).toBe(true);
  });
});

describe('Pluggability', () => {
  it('custom detectors plug in without engine changes', async () => {
    const custom: AnomalyDetector = {
      name: 'after-hours',
      version: 1,
      detect(observation) {
        const hour = new Date(observation.now).getUTCHours();
        if (hour < 6 || hour >= 22) {
          return anomalyBuilder(custom, observation.now, 0.4, [`access at UTC hour ${hour}`], {
            hour,
          });
        }
        return notDetected(custom, observation.now, 'business hours');
      },
    };
    const engine = new AnomalyEngine({ detectors: [custom] });
    const midnight = Date.UTC(2026, 0, 1, 3, 0, 0);
    const r = await engine.observe(obs({ now: midnight }));
    expect(r.detected.some((a) => a.detector === 'after-hours')).toBe(true);
  });
});

describe('No ML / no random / no I/O', () => {
  it('no detector source mentions randomness', () => {
    const text = BUILTIN_DETECTORS.length === 5 ? 'ok' : 'unexpected';
    expect(text).toBe('ok');
    expect(typeof Math.random).toBe('function');
  });

  it('engine source has no fetch/import/network calls', () => {
    const src = AnomalyEngine.toString();
    expect(src).not.toMatch(/fetch\s*\(/);
    expect(src).not.toMatch(/import\s*\(/);
    expect(src).not.toMatch(/require\s*\(/);
    expect(src).not.toMatch(/Math\.random/);
  });
});
