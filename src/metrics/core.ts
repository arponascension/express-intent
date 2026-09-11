import type { Counter, Histogram, MetricsProvider } from './defs.js';
import { DEFAULT_HISTOGRAM_BUCKETS_MS, DEFAULT_RISK_BUCKETS } from './defs.js';

export interface CoreMetrics {
  readonly requests: Counter;
  readonly decisions: Counter;
  readonly riskEvaluations: Counter;
  readonly riskScore: Histogram;
  readonly anomalies: Counter;
  readonly rateLimits: Counter;
  readonly evaluationDuration: Histogram;
}

export function createCoreMetrics(provider: MetricsProvider): CoreMetrics {
  return {
    requests: provider.counter(
      'express_intent_requests_total',
      'Number of intent-evaluated requests by outcome.',
      ['action', 'intent_key', 'http_method', 'http_route', 'outcome'],
    ),
    decisions: provider.counter(
      'express_intent_decisions_total',
      'Number of decisions by kind and severity.',
      ['action', 'intent_key', 'decision', 'severity'],
    ),
    riskEvaluations: provider.counter(
      'express_intent_risk_evaluations_total',
      'Number of risk evaluations by severity.',
      ['action', 'intent_key', 'severity'],
    ),
    riskScore: provider.histogram(
      'express_intent_risk_score',
      'Distribution of computed risk scores (0-100).',
      ['action', 'intent_key'],
      DEFAULT_RISK_BUCKETS,
    ),
    anomalies: provider.counter(
      'express_intent_anomalies_total',
      'Detected anomalies by type and confidence bucket.',
      ['action', 'anomaly_type', 'anomaly_confidence_bucket'],
    ),
    rateLimits: provider.counter(
      'express_intent_rate_limits_total',
      'Rate limit consumption by outcome (allowed/limited).',
      ['action', 'intent_key', 'scope', 'outcome'],
    ),
    evaluationDuration: provider.histogram(
      'express_intent_evaluation_duration_ms',
      'Duration of intent evaluation in milliseconds.',
      ['action', 'intent_key', 'decision'],
      DEFAULT_HISTOGRAM_BUCKETS_MS,
    ),
  };
}

export function confidenceBucket(c: number): string {
  if (c < 0) return '0';
  if (c < 0.25) return '0_25';
  if (c < 0.5) return '25_50';
  if (c < 0.75) return '50_75';
  if (c <= 1) return '75_100';
  return 'over';
}
