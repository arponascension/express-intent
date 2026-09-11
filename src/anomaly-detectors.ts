import type { AnomalyDetector, Observation } from './anomaly-defs.js';
import { DEFAULT_ANOMALY_CONFIG, anomaly, notDetected } from './anomaly-defs.js';

function clip(value: number, min: number, max: number): number {
  return value < min ? min : value > max ? max : value;
}

function filterInWindow(
  history: ReadonlyArray<Observation>,
  now: number,
  windowMs: number,
): Observation[] {
  const out: Observation[] = [];
  for (const o of history) {
    if (now - o.now <= windowMs && now - o.now >= 0) out.push(o);
  }
  return out;
}

const VELOCITY: AnomalyDetector = {
  name: 'velocity',
  version: 1,
  detect(observation, history, config) {
    const cfg = { ...DEFAULT_ANOMALY_CONFIG, ...config };
    const windowMs = cfg.windowMs;
    const max = cfg.velocityMax;
    const win = filterInWindow(history, observation.now, windowMs);
    const count = win.length + 1;
    if (count <= max) {
      return notDetected(this, observation.now, `count ${count} within ${max} for ${windowMs}ms`);
    }
    const overshoot = (count - max) / max;
    const confidence = clip(0.5 + overshoot * 0.5, 0.5, 1);
    return anomaly(
      this,
      observation.now,
      confidence,
      [`count ${count} exceeds ${max} in ${windowMs}ms`],
      { count, windowMs, threshold: max },
    );
  },
};

const ENUMERATION: AnomalyDetector = {
  name: 'enumeration',
  version: 1,
  detect(observation, history, config) {
    const cfg = { ...DEFAULT_ANOMALY_CONFIG, ...config };
    const windowMs = cfg.windowMs;
    const max = cfg.enumerationMaxDistinct;
    const win = filterInWindow(history, observation.now, windowMs);
    const ids = new Set<string>();
    for (const o of win) if (o.resourceId !== null) ids.add(o.resourceId);
    if (observation.resourceId !== null) ids.add(observation.resourceId);
    const distinct = ids.size;
    if (distinct <= max) {
      return notDetected(this, observation.now, `distinct resources ${distinct} within ${max}`);
    }
    const overshoot = (distinct - max) / max;
    const confidence = clip(0.5 + overshoot * 0.5, 0.5, 1);
    return anomaly(
      this,
      observation.now,
      confidence,
      [`distinct resources ${distinct} exceeds ${max} in ${windowMs}ms`],
      { distinctResources: distinct, windowMs, threshold: max },
    );
  },
};

const USER_AGENT_CHANGE: AnomalyDetector = {
  name: 'user-agent-change',
  version: 1,
  detect(observation, history, config) {
    const cfg = { ...DEFAULT_ANOMALY_CONFIG, ...config };
    if (!cfg.userAgentChangeEnabled || observation.actorSubject === null) {
      return notDetected(this, observation.now, 'disabled or anonymous');
    }
    const win = filterInWindow(history, observation.now, cfg.windowMs).filter(
      (o) => o.actorSubject === observation.actorSubject && o.userAgent !== null,
    );
    if (win.length === 0) {
      return notDetected(this, observation.now, 'no prior UA for actor');
    }
    const last = win[win.length - 1]!;
    if (last.userAgent === observation.userAgent) {
      return notDetected(this, observation.now, 'user agent unchanged');
    }
    const distinctUA = new Set<string>();
    for (const o of win) if (o.userAgent !== null) distinctUA.add(o.userAgent);
    distinctUA.add(observation.userAgent ?? '');
    const jumpiness = Math.min(1, (distinctUA.size - 1) / 3);
    const confidence = clip(0.6 + jumpiness * 0.4, 0.6, 1);
    return anomaly(
      this,
      observation.now,
      confidence,
      [`user agent changed from "${last.userAgent}" to "${observation.userAgent ?? ''}"`],
      { previous: last.userAgent, current: observation.userAgent },
    );
  },
};

const IP_CHANGE: AnomalyDetector = {
  name: 'ip-change',
  version: 1,
  detect(observation, history, config) {
    const cfg = { ...DEFAULT_ANOMALY_CONFIG, ...config };
    if (!cfg.ipChangeEnabled || observation.actorSubject === null) {
      return notDetected(this, observation.now, 'disabled or anonymous');
    }
    const win = filterInWindow(history, observation.now, cfg.windowMs).filter(
      (o) => o.actorSubject === observation.actorSubject && o.ip !== null,
    );
    if (win.length === 0) {
      return notDetected(this, observation.now, 'no prior IP for actor');
    }
    const last = win[win.length - 1]!;
    if (last.ip === observation.ip) {
      return notDetected(this, observation.now, 'ip unchanged');
    }
    const distinctIPs = new Set<string>();
    for (const o of win) if (o.ip !== null) distinctIPs.add(o.ip);
    distinctIPs.add(observation.ip ?? '');
    const spread = Math.min(1, (distinctIPs.size - 1) / 3);
    const confidence = clip(0.6 + spread * 0.4, 0.6, 1);
    return anomaly(
      this,
      observation.now,
      confidence,
      [`ip changed from "${last.ip}" to "${observation.ip ?? ''}"`],
      { previous: last.ip, current: observation.ip },
    );
  },
};

const ENDPOINT_PATTERN: AnomalyDetector = {
  name: 'endpoint-pattern',
  version: 1,
  detect(observation, history, config) {
    const cfg = { ...DEFAULT_ANOMALY_CONFIG, ...config };
    const windowMs = cfg.windowMs;
    const max = cfg.endpointPatternMaxDistinct;
    const win = filterInWindow(history, observation.now, windowMs);
    const paths = new Set<string>();
    for (const o of win) paths.add(`${o.method} ${o.path}`);
    paths.add(`${observation.method} ${observation.path}`);
    const distinct = paths.size;
    if (distinct <= max) {
      return notDetected(this, observation.now, `distinct endpoints ${distinct} within ${max}`);
    }
    const overshoot = (distinct - max) / max;
    const confidence = clip(0.4 + overshoot * 0.5, 0.4, 1);
    return anomaly(
      this,
      observation.now,
      confidence,
      [`distinct endpoints ${distinct} exceeds ${max} in ${windowMs}ms`],
      { distinctEndpoints: distinct, windowMs, threshold: max },
    );
  },
};

export const BUILTIN_DETECTORS: ReadonlyArray<AnomalyDetector> = Object.freeze([
  VELOCITY,
  ENUMERATION,
  USER_AGENT_CHANGE,
  IP_CHANGE,
  ENDPOINT_PATTERN,
]);

export { VELOCITY, ENUMERATION, USER_AGENT_CHANGE, IP_CHANGE, ENDPOINT_PATTERN };
