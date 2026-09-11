export interface Counter {
  readonly name: string;
  readonly help: string;
  readonly labelNames: ReadonlyArray<string>;
  inc(labels?: Readonly<Record<string, string>>, value?: number): void;
  reset(): void;
  collect(): ReadonlyArray<{
    readonly labels: Readonly<Record<string, string>>;
    readonly value: number;
  }>;
}

export interface Gauge {
  readonly name: string;
  readonly help: string;
  readonly labelNames: ReadonlyArray<string>;
  set(labels: Readonly<Record<string, string>>, value: number): void;
  inc(labels?: Readonly<Record<string, string>>, value?: number): void;
  dec(labels?: Readonly<Record<string, string>>, value?: number): void;
  reset(): void;
  collect(): ReadonlyArray<{
    readonly labels: Readonly<Record<string, string>>;
    readonly value: number;
  }>;
}

export interface Histogram {
  readonly name: string;
  readonly help: string;
  readonly labelNames: ReadonlyArray<string>;
  readonly buckets: ReadonlyArray<number>;
  observe(labels: Readonly<Record<string, string>>, value: number): void;
  reset(): void;
  collect(): ReadonlyArray<{
    readonly labels: Readonly<Record<string, string>>;
    readonly count: number;
    readonly sum: number;
    readonly buckets: ReadonlyArray<{ readonly le: number; readonly count: number }>;
  }>;
}

export interface MetricsProvider {
  readonly name: string;
  counter(name: string, help: string, labelNames?: ReadonlyArray<string>): Counter;
  gauge(name: string, help: string, labelNames?: ReadonlyArray<string>): Gauge;
  histogram(
    name: string,
    help: string,
    labelNames?: ReadonlyArray<string>,
    buckets?: ReadonlyArray<number>,
  ): Histogram;
  collect?(): ReadonlyArray<unknown>;
  reset?(): void;
}

export const DEFAULT_HISTOGRAM_BUCKETS_MS: ReadonlyArray<number> = [
  1, 5, 10, 25, 50, 100, 250, 500, 1_000, 2_500, 5_000, 10_000,
];
export const DEFAULT_RISK_BUCKETS: ReadonlyArray<number> = [0, 10, 25, 50, 75, 90, 100];

export class NoopCounter implements Counter {
  constructor(
    public readonly name: string,
    public readonly help: string,
    public readonly labelNames: ReadonlyArray<string> = [],
  ) {}
  inc(): void {
    /* noop */
  }
  reset(): void {
    /* noop */
  }
  collect(): ReadonlyArray<{ labels: Readonly<Record<string, string>>; value: number }> {
    return [];
  }
}

export class NoopGauge implements Gauge {
  constructor(
    public readonly name: string,
    public readonly help: string,
    public readonly labelNames: ReadonlyArray<string> = [],
  ) {}
  set(): void {
    /* noop */
  }
  inc(): void {
    /* noop */
  }
  dec(): void {
    /* noop */
  }
  reset(): void {
    /* noop */
  }
  collect(): ReadonlyArray<{ labels: Readonly<Record<string, string>>; value: number }> {
    return [];
  }
}

export class NoopHistogram implements Histogram {
  constructor(
    public readonly name: string,
    public readonly help: string,
    public readonly labelNames: ReadonlyArray<string> = [],
    public readonly buckets: ReadonlyArray<number> = [],
  ) {}
  observe(): void {
    /* noop */
  }
  reset(): void {
    /* noop */
  }
  collect(): ReadonlyArray<{
    labels: Readonly<Record<string, string>>;
    count: number;
    sum: number;
    buckets: ReadonlyArray<{ le: number; count: number }>;
  }> {
    return [];
  }
}

export class NoopMetricsProvider implements MetricsProvider {
  readonly name = 'noop';
  counter(name: string, help: string, labelNames?: ReadonlyArray<string>): Counter {
    return new NoopCounter(name, help, labelNames ?? []);
  }
  gauge(name: string, help: string, labelNames?: ReadonlyArray<string>): Gauge {
    return new NoopGauge(name, help, labelNames ?? []);
  }
  histogram(
    name: string,
    help: string,
    labelNames?: ReadonlyArray<string>,
    buckets?: ReadonlyArray<number>,
  ): Histogram {
    return new NoopHistogram(name, help, labelNames ?? [], buckets ?? []);
  }
  reset(): void {
    /* noop */
  }
}
