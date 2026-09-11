import type { Histogram, MetricsProvider } from './defs.js';
import { GuardedMetricsProvider } from './guarded.js';

function escapeLabelValue(v: string): string {
  return v.replace(/\\/g, '\\\\').replace(/\n/g, '\\n').replace(/"/g, '\\"');
}

function formatLabels(labels: Readonly<Record<string, string>>): string {
  const keys = Object.keys(labels);
  if (keys.length === 0) return '';
  keys.sort();
  return '{' + keys.map((k) => `${k}="${escapeLabelValue(labels[k]!)}"`).join(',') + '}';
}

export function toPrometheusText(provider: MetricsProvider): string {
  if (
    typeof (provider as GuardedMetricsProvider).collect !== 'function' ||
    !('counters' in provider)
  ) {
    return '';
  }
  const g = provider as unknown as GuardedMetricsProvider;
  const lines: string[] = [];
  for (const entry of g.collect()) {
    lines.push(`# HELP ${entry.name} ${entry.help}`);
    lines.push(`# TYPE ${entry.name} ${entry.type}`);
    if (entry.type === 'histogram') {
      for (const s of entry.samples) {
        if (!('buckets' in s)) continue;
        for (const b of s.buckets) {
          const lbls: Record<string, string> = { ...s.labels, le: String(b.le) };
          lines.push(`${entry.name}_bucket${formatLabels(lbls)} ${b.count}`);
        }
        lines.push(`${entry.name}_sum${formatLabels(s.labels)} ${s.sum}`);
        lines.push(`${entry.name}_count${formatLabels(s.labels)} ${s.count}`);
      }
    } else {
      for (const s of entry.samples) {
        if (!('value' in s)) continue;
        lines.push(`${entry.name}${formatLabels(s.labels)} ${s.value}`);
      }
    }
  }
  return lines.join('\n') + (lines.length > 0 ? '\n' : '');
}

export function createPrometheusMetricsProvider(): MetricsProvider {
  return new GuardedMetricsProvider('prometheus');
}

export interface HistogramFromBuckets {
  readonly name: string;
  readonly help: string;
  readonly labelNames: ReadonlyArray<string>;
  readonly buckets: ReadonlyArray<number>;
}

export function isHistogram(m: { readonly buckets?: ReadonlyArray<number> }): m is Histogram {
  return Array.isArray((m as Histogram).buckets);
}
