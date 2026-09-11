import type { RiskSignal, RiskSignalValue } from './types.js';
import type { Severity } from './types.js';
import type {
  NumericRange,
  RiskConfig,
  SignalWeightConfig,
  SeverityThresholds,
} from './risk-config.js';
import { DEFAULT_RISK_CONFIG, SEVERITY_ORDER } from './risk-config.js';
import { hashRisk } from './domain/hash.js';
import type { Risk } from './types.js';

export type BreakdownReason =
  | 'in-range'
  | 'below-range'
  | 'above-range'
  | 'categorical-hit'
  | 'categorical-miss'
  | 'boolean'
  | 'missing'
  | 'expired'
  | 'no-weight';

export interface RiskBreakdownEntry {
  readonly name: string;
  readonly raw: RiskSignalValue;
  readonly normalized: number;
  readonly weight: number;
  readonly confidence: number;
  readonly ageMs: number;
  readonly effective: number;
  readonly contribution: number;
  readonly reason: BreakdownReason;
}

export interface RiskEvaluation {
  readonly score: number;
  readonly severity: Severity;
  readonly breakdown: ReadonlyArray<RiskBreakdownEntry>;
  readonly risk: Risk;
}

const ZERO_BREAKDOWN: RiskBreakdownEntry = {
  name: '',
  raw: null,
  normalized: 0,
  weight: 0,
  confidence: 0,
  ageMs: 0,
  effective: 0,
  contribution: 0,
  reason: 'missing',
};

function clamp01(n: number): number {
  if (Number.isNaN(n)) return 0;
  if (n < 0) return 0;
  if (n > 1) return 1;
  return n;
}

function normalizeNumeric(
  raw: number,
  range: NumericRange | undefined,
): { normalized: number; reason: BreakdownReason } {
  if (range === undefined) {
    return { normalized: clamp01(raw), reason: 'in-range' };
  }
  if (raw < range.min) return { normalized: range.invert === true ? 1 : 0, reason: 'below-range' };
  if (raw > range.max) return { normalized: range.invert === true ? 0 : 1, reason: 'above-range' };
  const span = range.max - range.min;
  if (span <= 0) return { normalized: 0, reason: 'in-range' };
  const linear = (raw - range.min) / span;
  return { normalized: clamp01(range.invert === true ? 1 - linear : linear), reason: 'in-range' };
}

function normalizeCategorical(
  raw: string,
  table: Readonly<Record<string, number>> | undefined,
): { normalized: number; reason: BreakdownReason } {
  if (table === undefined) return { normalized: 0, reason: 'categorical-miss' };
  const hit = Object.prototype.hasOwnProperty.call(table, raw);
  if (!hit) return { normalized: 0, reason: 'categorical-miss' };
  return { normalized: clamp01(table[raw] ?? 0), reason: 'categorical-hit' };
}

function normalizeBoolean(raw: boolean): { normalized: number; reason: BreakdownReason } {
  return { normalized: raw ? 1 : 0, reason: 'boolean' };
}

function decayFactor(ageMs: number, cfg: SignalWeightConfig['decay']): number {
  if (cfg === undefined) return 1;
  if (ageMs <= 0) return 1;
  const ratio = ageMs / cfg.halfLifeMs;
  const decayed = Math.pow(0.5, ratio);
  return Math.max(cfg.floor, decayed);
}

function severityForScore(score: number, thresholds: SeverityThresholds): Severity {
  if (score >= thresholds.critical) return 'critical';
  if (score >= thresholds.high) return 'high';
  if (score >= thresholds.medium) return 'medium';
  if (score >= thresholds.low) return 'low';
  return 'low';
}

function compareSignals(a: RiskSignal, b: RiskSignal): number {
  if (a.name < b.name) return -1;
  if (a.name > b.name) return 1;
  return a.computedAt - b.computedAt;
}

export interface EvaluateOptions {
  readonly now: number;
}

export function evaluateRisk(
  signals: ReadonlyArray<RiskSignal>,
  context: { readonly missing?: ReadonlyArray<string> },
  config: RiskConfig,
  options: EvaluateOptions,
): RiskEvaluation {
  const thresholds = { ...DEFAULT_RISK_CONFIG.thresholds, ...(config.thresholds ?? {}) };
  const defaultWeight = config.defaultWeight ?? DEFAULT_RISK_CONFIG.defaultWeight;
  const signalMap = config.signals ?? {};
  const missing = new Set(context.missing ?? []);

  const ordered = [...signals].sort(compareSignals);

  let weightedSum = 0;
  let totalWeight = 0;
  const breakdown: RiskBreakdownEntry[] = [];

  for (const sig of ordered) {
    const sigCfg = signalMap[sig.name];
    const weight = sigCfg?.weight ?? defaultWeight;
    const ageMs = Math.max(0, options.now - sig.computedAt);
    const ttlExpired = ageMs > sig.ttlMs;

    if (weight <= 0) {
      breakdown.push({
        name: sig.name,
        raw: sig.value,
        normalized: 0,
        weight,
        confidence: sig.confidence,
        ageMs,
        effective: 0,
        contribution: 0,
        reason: 'no-weight',
      });
      continue;
    }

    if (ttlExpired) {
      breakdown.push({
        name: sig.name,
        raw: sig.value,
        normalized: 0,
        weight,
        confidence: sig.confidence,
        ageMs,
        effective: 0,
        contribution: 0,
        reason: 'expired',
      });
      continue;
    }

    let normalized: number;
    let reason: BreakdownReason;
    if (sig.value === null) {
      normalized = 0;
      reason = 'missing';
    } else if (sig.kind === 'numeric') {
      const r = normalizeNumeric(sig.value as number, sigCfg?.range);
      normalized = r.normalized;
      reason = r.reason;
    } else if (sig.kind === 'categorical') {
      const r = normalizeCategorical(sig.value as string, sigCfg?.categorical);
      normalized = r.normalized;
      reason = r.reason;
    } else {
      const r = normalizeBoolean(sig.value as boolean);
      normalized = r.normalized;
      reason = r.reason;
    }

    const confidence = clamp01(sig.confidence);
    const decay = decayFactor(ageMs, sigCfg?.decay);
    const effective = clamp01(normalized * confidence * decay);
    const contribution = effective * weight;

    weightedSum += contribution;
    totalWeight += weight;

    breakdown.push({
      name: sig.name,
      raw: sig.value,
      normalized,
      weight,
      confidence,
      ageMs,
      effective,
      contribution,
      reason,
    });
  }

  for (const name of [...missing].sort()) {
    const sigCfg = signalMap[name];
    const weight = sigCfg?.weight ?? defaultWeight;
    if (weight <= 0) continue;
    breakdown.push({ ...ZERO_BREAKDOWN, name, weight });
    totalWeight += weight;
  }

  const score = totalWeight > 0 ? Math.max(0, Math.min(100, (weightedSum / totalWeight) * 100)) : 0;
  const severity = severityForScore(score, thresholds);

  const risk: Risk = Object.freeze({
    signals: Object.freeze([...ordered]),
    missing: Object.freeze([...missing].sort()),
    aggregationHash: hashRisk({
      signals: ordered,
      missing: [...missing].sort(),
      aggregationHash: '',
      computedAt: options.now,
    }),
    computedAt: options.now,
  });

  return Object.freeze({
    score,
    severity,
    breakdown: Object.freeze(breakdown),
    risk,
  }) as RiskEvaluation;
}

export function compareSeverity(a: Severity, b: Severity): number {
  return SEVERITY_ORDER.indexOf(a) - SEVERITY_ORDER.indexOf(b);
}
