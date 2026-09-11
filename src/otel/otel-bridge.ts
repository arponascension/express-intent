import type { SpanContext, SpanHandle, SpanRecorder, SpanStatusCode } from './recorder.js';
import { AttributeRedactor, type RedactionConfig } from './redact.js';
import { createIntentTelemetry, NoopTelemetry, type TelemetryHooks } from './telemetry.js';

export interface OTelTracerLike {
  startSpan(
    name: string,
    opts?: { attributes?: Record<string, string | number | boolean> },
  ): OTelSpanLike;
}
export interface OTelSpanLike {
  setAttribute(key: string, value: string | number | boolean): void;
  setAttributes(attributes: Record<string, string | number | boolean>): void;
  addEvent(name: string, attributes?: Record<string, string | number | boolean>): void;
  setStatus(status: { code: number; message?: string }): void;
  recordException(err: unknown): void;
  end(): void;
  spanContext(): { traceId: string; spanId: string };
}

export interface OTelBridgeOptions {
  readonly tracer: OTelTracerLike;
  readonly redaction?: RedactionConfig;
}

const OTEL_STATUS_UNSET = 0;
const OTEL_STATUS_OK = 1;
const OTEL_STATUS_ERROR = 2;

function toOtelStatus(code: SpanStatusCode): number {
  if (code === 'ok') return OTEL_STATUS_OK;
  if (code === 'error') return OTEL_STATUS_ERROR;
  return OTEL_STATUS_UNSET;
}

export class OTelSpanRecorder implements SpanRecorder {
  private readonly redactor: AttributeRedactor;

  constructor(private readonly options: OTelBridgeOptions) {
    this.redactor = new AttributeRedactor(options.redaction ?? {});
  }

  startSpan(
    name: string,
    attributes?: Readonly<Record<string, string | number | boolean>>,
  ): SpanHandle {
    const safe = this.redactor.filter(attributes ?? {});
    const otelSpan = this.options.tracer.startSpan(name, { attributes: safe });
    return new OTelSpanHandle(otelSpan);
  }
}

class OTelSpanHandle implements SpanHandle {
  constructor(private readonly span: OTelSpanLike) {}
  setAttribute(k: string, v: string | number | boolean): void {
    this.span.setAttribute(k, v);
  }
  setAttributes(a: Readonly<Record<string, string | number | boolean>>): void {
    this.span.setAttributes({ ...a });
  }
  addEvent(name: string, a?: Readonly<Record<string, string | number | boolean>>): void {
    this.span.addEvent(name, a ? { ...a } : undefined);
  }
  setStatus(code: SpanStatusCode, message?: string): void {
    this.span.setStatus({
      code: toOtelStatus(code),
      ...(message !== undefined ? { message } : {}),
    });
  }
  recordError(err: unknown): void {
    this.span.recordException(err);
  }
  end(): void {
    this.span.end();
  }
  context(): SpanContext {
    const sc = this.span.spanContext();
    return Object.freeze({
      traceId: sc.traceId,
      spanId: sc.spanId,
      name: '',
      startTime: 0,
      endTime: null,
      attributes: Object.freeze({}) as Readonly<Record<string, string | number | boolean>>,
      events: Object.freeze([]) as ReadonlyArray<{
        name: string;
        time: number;
        attributes: Readonly<Record<string, string | number | boolean>>;
      }>,
      status: Object.freeze({ code: 'unset' as const, message: null }) as Readonly<{
        code: SpanStatusCode;
        message: string | null;
      }>,
      parent: null,
    }) as SpanContext;
  }
}

export interface OTelAPI {
  readonly trace: { getTracer(name: string): OTelTracerLike };
}

export async function tryLoadOTelAPI(): Promise<OTelAPI | null> {
  const dynamicImport = new Function('s', 'return import(s)') as (s: string) => Promise<unknown>;
  try {
    const mod = (await dynamicImport('@opentelemetry/api')) as {
      trace?: { getTracer?: (n: string) => OTelTracerLike };
      default?: { trace?: { getTracer?: (n: string) => OTelTracerLike } };
    };
    const trace = mod.trace ?? mod.default?.trace;
    if (typeof trace?.getTracer !== 'function') return null;
    return { trace: { getTracer: trace.getTracer.bind(trace) } };
  } catch {
    return null;
  }
}

export interface CreateOTelTelemetryOptions {
  readonly api?: OTelAPI;
  readonly tracerName?: string;
  readonly redaction?: RedactionConfig;
}

export async function createOTelTelemetry(
  options: CreateOTelTelemetryOptions = {},
): Promise<TelemetryHooks> {
  const api = options.api ?? (await tryLoadOTelAPI());
  if (api === null) return new NoopTelemetry();
  const tracer = api.trace.getTracer(options.tracerName ?? 'express-intent');
  return createIntentTelemetry({
    recorder: new OTelSpanRecorder({
      tracer,
      ...(options.redaction ? { redaction: options.redaction } : {}),
    }),
  });
}
