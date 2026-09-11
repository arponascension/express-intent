import type { Counter, Gauge, Histogram, MetricsProvider } from './defs.js';
import { NoopMetricsProvider } from './defs.js';

export interface CardinalityGuardOptions {
  readonly allowedLabels?: ReadonlyArray<string>;
  readonly maxLabelValueLength?: number;
  readonly maxDistinctLabelSetsPerMetric?: number;
}

export const DEFAULT_CARDINALITY_GUARD: Required<CardinalityGuardOptions> = {
  allowedLabels: [
    'action',
    'intent_key',
    'decision',
    'outcome',
    'severity',
    'anomaly_type',
    'policy_id',
    'policy_outcome',
    'http_method',
    'http_route',
    'http_status',
  ],
  maxLabelValueLength: 64,
  maxDistinctLabelSetsPerMetric: 1000,
};

function sanitizeLabels(
  raw: Readonly<Record<string, string>>,
  allowed: ReadonlyArray<string>,
  maxLen: number,
): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(raw)) {
    if (!allowed.includes(k)) continue;
    if (typeof v !== 'string') continue;
    if (v.length === 0) continue;
    if (v.length > maxLen) {
      out[k] = v.slice(0, maxLen);
    } else {
      out[k] = v;
    }
  }
  return out;
}

function keyOf(labels: Readonly<Record<string, string>>): string {
  return Object.keys(labels)
    .sort()
    .map((k) => `${k}=${labels[k]}`)
    .join(';');
}

class GuardedCounter implements Counter {
  private readonly values = new Map<string, { labels: Record<string, string>; value: number }>();
  private dropped = 0;
  constructor(
    public readonly name: string,
    public readonly help: string,
    public readonly labelNames: ReadonlyArray<string>,
    private readonly guard: CardinalityGuardOptions,
  ) {}
  inc(labels: Readonly<Record<string, string>> = {}, value = 1): void {
    const clean = sanitizeLabels(
      labels,
      this.guard.allowedLabels ?? DEFAULT_CARDINALITY_GUARD.allowedLabels,
      this.guard.maxLabelValueLength ?? DEFAULT_CARDINALITY_GUARD.maxLabelValueLength,
    );
    const k = keyOf(clean);
    if (k === '') {
      this.dropped += value;
      return;
    }
    if (
      !this.values.has(k) &&
      this.values.size >=
        (this.guard.maxDistinctLabelSetsPerMetric ??
          DEFAULT_CARDINALITY_GUARD.maxDistinctLabelSetsPerMetric)
    ) {
      this.dropped += value;
      return;
    }
    const existing = this.values.get(k);
    if (existing) existing.value += value;
    else this.values.set(k, { labels: clean, value });
  }
  reset(): void {
    this.values.clear();
    this.dropped = 0;
  }
  collect() {
    const out: { labels: Readonly<Record<string, string>>; value: number }[] = [];
    for (const v of this.values.values())
      out.push({ labels: Object.freeze(v.labels), value: v.value });
    return Object.freeze(out);
  }
  droppedCount(): number {
    return this.dropped;
  }
}

class GuardedGauge implements Gauge {
  private readonly values = new Map<string, { labels: Record<string, string>; value: number }>();
  constructor(
    public readonly name: string,
    public readonly help: string,
    public readonly labelNames: ReadonlyArray<string>,
    private readonly guard: CardinalityGuardOptions,
  ) {}
  private ensure(
    labels: Readonly<Record<string, string>>,
    delta: number,
    mode: 'set' | 'inc' | 'dec',
  ): number | null {
    const clean = sanitizeLabels(
      labels,
      this.guard.allowedLabels ?? DEFAULT_CARDINALITY_GUARD.allowedLabels,
      this.guard.maxLabelValueLength ?? DEFAULT_CARDINALITY_GUARD.maxLabelValueLength,
    );
    const k = keyOf(clean);
    if (k === '') return null;
    if (
      !this.values.has(k) &&
      this.values.size >=
        (this.guard.maxDistinctLabelSetsPerMetric ??
          DEFAULT_CARDINALITY_GUARD.maxDistinctLabelSetsPerMetric)
    ) {
      return null;
    }
    const existing = this.values.get(k);
    if (existing) {
      if (mode === 'set') existing.value = delta;
      else if (mode === 'inc') existing.value += delta;
      else existing.value -= delta;
    } else {
      const v = mode === 'set' ? delta : mode === 'inc' ? delta : -delta;
      this.values.set(k, { labels: clean, value: v });
    }
    return 1;
  }
  set(labels: Readonly<Record<string, string>>, value: number): void {
    this.ensure(labels, value, 'set');
  }
  inc(labels: Readonly<Record<string, string>> = {}, value = 1): void {
    this.ensure(labels, value, 'inc');
  }
  dec(labels: Readonly<Record<string, string>> = {}, value = 1): void {
    this.ensure(labels, value, 'dec');
  }
  reset(): void {
    this.values.clear();
  }
  collect() {
    const out: { labels: Readonly<Record<string, string>>; value: number }[] = [];
    for (const v of this.values.values())
      out.push({ labels: Object.freeze(v.labels), value: v.value });
    return Object.freeze(out);
  }
}

class GuardedHistogram implements Histogram {
  private readonly series = new Map<
    string,
    { labels: Record<string, string>; count: number; sum: number; bucketCounts: number[] }
  >();
  constructor(
    public readonly name: string,
    public readonly help: string,
    public readonly labelNames: ReadonlyArray<string>,
    public readonly buckets: ReadonlyArray<number>,
    private readonly guard: CardinalityGuardOptions,
  ) {
    if (buckets.length === 0) throw new Error('Histogram requires at least one bucket');
    for (let i = 1; i < buckets.length; i++) {
      if (buckets[i]! <= buckets[i - 1]!)
        throw new Error('Histogram buckets must be strictly increasing');
    }
  }
  observe(labels: Readonly<Record<string, string>>, value: number): void {
    const clean = sanitizeLabels(
      labels,
      this.guard.allowedLabels ?? DEFAULT_CARDINALITY_GUARD.allowedLabels,
      this.guard.maxLabelValueLength ?? DEFAULT_CARDINALITY_GUARD.maxLabelValueLength,
    );
    const k = keyOf(clean);
    if (k === '') return;
    if (
      !this.series.has(k) &&
      this.series.size >=
        (this.guard.maxDistinctLabelSetsPerMetric ??
          DEFAULT_CARDINALITY_GUARD.maxDistinctLabelSetsPerMetric)
    ) {
      return;
    }
    const existing = this.series.get(k);
    if (existing) {
      existing.count++;
      existing.sum += value;
      for (let i = 0; i < this.buckets.length; i++) {
        if (value <= this.buckets[i]!) existing.bucketCounts[i]!++;
      }
    } else {
      const counts = new Array<number>(this.buckets.length).fill(0);
      for (let i = 0; i < this.buckets.length; i++) {
        if (value <= this.buckets[i]!) counts[i]!++;
      }
      this.series.set(k, { labels: clean, count: 1, sum: value, bucketCounts: counts });
    }
  }
  reset(): void {
    this.series.clear();
  }
  collect() {
    const out: {
      labels: Readonly<Record<string, string>>;
      count: number;
      sum: number;
      buckets: ReadonlyArray<{ le: number; count: number }>;
    }[] = [];
    for (const s of this.series.values()) {
      out.push({
        labels: Object.freeze(s.labels),
        count: s.count,
        sum: s.sum,
        buckets: Object.freeze(
          this.buckets.map((le, i) => Object.freeze({ le, count: s.bucketCounts[i]! })),
        ) as ReadonlyArray<{ le: number; count: number }>,
      });
    }
    return Object.freeze(out);
  }
}

export type CollectedSample =
  | { readonly labels: Readonly<Record<string, string>>; readonly value: number }
  | {
      readonly labels: Readonly<Record<string, string>>;
      readonly buckets: ReadonlyArray<{ le: number; count: number }>;
      readonly count: number;
      readonly sum: number;
    };
export type CollectedMetric = {
  readonly name: string;
  readonly type: 'counter' | 'gauge' | 'histogram';
  readonly help: string;
  readonly samples: ReadonlyArray<CollectedSample>;
};

export class GuardedMetricsProvider implements MetricsProvider {
  private readonly counters = new Map<string, GuardedCounter>();
  private readonly gauges = new Map<string, GuardedGauge>();
  private readonly histograms = new Map<string, GuardedHistogram>();

  constructor(
    public readonly name: string,
    private readonly guard: CardinalityGuardOptions = {},
  ) {}

  counter(name: string, help: string, labelNames: ReadonlyArray<string> = []): Counter {
    let c = this.counters.get(name);
    if (c === undefined) {
      c = new GuardedCounter(name, help, labelNames, this.guard);
      this.counters.set(name, c);
    }
    return c;
  }
  gauge(name: string, help: string, labelNames: ReadonlyArray<string> = []): Gauge {
    let g = this.gauges.get(name);
    if (g === undefined) {
      g = new GuardedGauge(name, help, labelNames, this.guard);
      this.gauges.set(name, g);
    }
    return g;
  }
  histogram(
    name: string,
    help: string,
    labelNames: ReadonlyArray<string> = [],
    buckets: ReadonlyArray<number> = [],
  ): Histogram {
    let h = this.histograms.get(name);
    if (h === undefined) {
      h = new GuardedHistogram(name, help, labelNames, buckets, this.guard);
      this.histograms.set(name, h);
    }
    return h;
  }

  collect(): ReadonlyArray<CollectedMetric> {
    const out: CollectedMetric[] = [];
    for (const c of this.counters.values()) {
      const samples: CollectedSample[] = c
        .collect()
        .map((s) => ({ labels: s.labels, value: s.value }));
      out.push({ name: c.name, type: 'counter', help: c.help, samples });
    }
    for (const g of this.gauges.values()) {
      const samples: CollectedSample[] = g
        .collect()
        .map((s) => ({ labels: s.labels, value: s.value }));
      out.push({ name: g.name, type: 'gauge', help: g.help, samples });
    }
    for (const h of this.histograms.values()) {
      const samples: CollectedSample[] = h
        .collect()
        .map((s) => ({ labels: s.labels, buckets: s.buckets, count: s.count, sum: s.sum }));
      out.push({ name: h.name, type: 'histogram', help: h.help, samples });
    }
    return Object.freeze(out);
  }

  reset(): void {
    for (const c of this.counters.values()) c.reset();
    for (const g of this.gauges.values()) g.reset();
    for (const h of this.histograms.values()) h.reset();
  }

  droppedCounters(): number {
    let n = 0;
    for (const c of this.counters.values()) n += (c as GuardedCounter).droppedCount();
    return n;
  }
}

export function noopOrGuarded(p?: MetricsProvider | null): MetricsProvider {
  return p ?? new NoopMetricsProvider();
}
