export type SpanStatusCode = 'ok' | 'error' | 'unset';

export interface SpanContext {
  readonly traceId: string;
  readonly spanId: string;
  readonly name: string;
  readonly startTime: number;
  readonly endTime: number | null;
  readonly attributes: Readonly<Record<string, string | number | boolean>>;
  readonly events: ReadonlyArray<{
    readonly name: string;
    readonly time: number;
    readonly attributes: Readonly<Record<string, string | number | boolean>>;
  }>;
  readonly status: { readonly code: SpanStatusCode; readonly message: string | null };
  readonly parent: SpanContext | null;
}

export interface SpanRecorder {
  startSpan(
    name: string,
    attributes?: Readonly<Record<string, string | number | boolean>>,
  ): SpanHandle;
}

export interface SpanHandle {
  setAttribute(key: string, value: string | number | boolean): void;
  setAttributes(attributes: Readonly<Record<string, string | number | boolean>>): void;
  addEvent(name: string, attributes?: Readonly<Record<string, string | number | boolean>>): void;
  setStatus(code: SpanStatusCode, message?: string): void;
  recordError(err: unknown): void;
  end(): void;
  context(): SpanContext;
}

export class NoopSpanHandle implements SpanHandle {
  private readonly ctx: SpanContext;
  constructor(name: string) {
    this.ctx = Object.freeze({
      traceId: '0',
      spanId: '0',
      name,
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
  setAttribute(): void {
    /* noop */
  }
  setAttributes(): void {
    /* noop */
  }
  addEvent(): void {
    /* noop */
  }
  setStatus(): void {
    /* noop */
  }
  recordError(): void {
    /* noop */
  }
  end(): void {
    /* noop */
  }
  context(): SpanContext {
    return this.ctx;
  }
}

export class NoopSpanRecorder implements SpanRecorder {
  startSpan(name: string): SpanHandle {
    return new NoopSpanHandle(name);
  }
}

export class SpySpanRecorder implements SpanRecorder {
  readonly spans: SpanContext[] = [];
  private readonly now: () => number;

  constructor(options: { clock?: () => number } = {}) {
    this.now = options.clock ?? (() => Date.now());
  }

  startSpan(
    name: string,
    attributes: Readonly<Record<string, string | number | boolean>> = {},
  ): SpanHandle {
    const spanId = Math.random().toString(16).slice(2, 10).padStart(8, '0');
    const traceId = Math.random().toString(16).slice(2, 18).padStart(16, '0');
    const state: {
      attributes: Record<string, string | number | boolean>;
      events: {
        name: string;
        time: number;
        attributes: Record<string, string | number | boolean>;
      }[];
      status: { code: SpanStatusCode; message: string | null };
      startTime: number;
      endTime: number | null;
      ended: boolean;
    } = {
      attributes: { ...attributes },
      events: [],
      status: { code: 'unset', message: null },
      startTime: this.now(),
      endTime: null,
      ended: false,
    };
    const handle: SpanHandle & { _parent: SpanContext | null } = {
      _parent: null,
      setAttribute: (k, v) => {
        state.attributes[k] = v;
      },
      setAttributes: (a) => {
        Object.assign(state.attributes, a);
      },
      addEvent: (n, a = {}) => {
        state.events.push({ name: n, time: this.now(), attributes: { ...a } });
      },
      setStatus: (c, m) => {
        state.status = { code: c, message: m ?? null };
      },
      recordError: (err) => {
        const message = err instanceof Error ? err.message : String(err);
        state.events.push({
          name: 'exception',
          time: this.now(),
          attributes: { 'exception.message': message },
        });
        state.status = { code: 'error', message };
      },
      end: () => {
        if (state.ended) return;
        state.ended = true;
        state.endTime = this.now();
        const ctx: SpanContext = Object.freeze({
          traceId,
          spanId,
          name,
          startTime: state.startTime,
          endTime: state.endTime,
          attributes: Object.freeze({ ...state.attributes }) as Readonly<
            Record<string, string | number | boolean>
          >,
          events: Object.freeze(
            state.events.map((e) =>
              Object.freeze({
                ...e,
                attributes: Object.freeze({ ...e.attributes }) as Readonly<
                  Record<string, string | number | boolean>
                >,
              }),
            ),
          ),
          status: Object.freeze({ ...state.status }) as Readonly<{
            code: SpanStatusCode;
            message: string | null;
          }>,
          parent: null,
        }) as SpanContext;
        this.spans.push(ctx);
      },
      context: () => {
        const ctx: SpanContext = Object.freeze({
          traceId,
          spanId,
          name,
          startTime: state.startTime,
          endTime: state.endTime,
          attributes: Object.freeze({ ...state.attributes }) as Readonly<
            Record<string, string | number | boolean>
          >,
          events: Object.freeze(
            state.events.map((e) =>
              Object.freeze({
                ...e,
                attributes: Object.freeze({ ...e.attributes }) as Readonly<
                  Record<string, string | number | boolean>
                >,
              }),
            ),
          ),
          status: Object.freeze({ ...state.status }) as Readonly<{
            code: SpanStatusCode;
            message: string | null;
          }>,
          parent: null,
        }) as SpanContext;
        return ctx;
      },
    };
    return handle;
  }
}
