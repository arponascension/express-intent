import { AttributeRedactor, type RedactionConfig } from './redact.js';
import type { SpanHandle, SpanRecorder } from './recorder.js';
import { NoopSpanRecorder } from './recorder.js';

export interface IntentEvaluationInput {
  readonly requestId: string;
  readonly action: string;
  readonly intentKey: string;
  readonly actor: {
    readonly subject: string | null;
    readonly authenticated: boolean;
    readonly roles: ReadonlyArray<string>;
  };
  readonly request: {
    readonly method: string;
    readonly path: string;
    readonly userAgent: string | null;
    readonly ip: string | null;
  };
  readonly signalsPresent: ReadonlyArray<string>;
  readonly signalsMissing: ReadonlyArray<string>;
}

export interface RiskEvaluationInput extends IntentEvaluationInput {
  readonly score: number;
  readonly severity: string;
  readonly breakdownCount: number;
  readonly breakdownTopReasons: ReadonlyArray<string>;
}

export interface PolicyEvaluationInput extends IntentEvaluationInput {
  readonly policiesEvaluated: ReadonlyArray<string>;
  readonly policiesMatched: ReadonlyArray<string>;
}

export interface DecisionMadeInput extends IntentEvaluationInput {
  readonly decisionKind: 'allow' | 'monitor' | 'challenge' | 'rate_limit' | 'deny' | 'error';
  readonly decisionReason: string | null;
  readonly riskScore: number | null;
  readonly riskSeverity: string | null;
  readonly durationMs: number;
}

export interface TelemetryHooks {
  onIntentStart(input: IntentEvaluationInput): SpanHandle;
  onRiskEvaluated(input: RiskEvaluationInput): SpanHandle;
  onPoliciesEvaluated(input: PolicyEvaluationInput): SpanHandle;
  onDecisionMade(input: DecisionMadeInput): SpanHandle;
}

export interface CreateTelemetryOptions {
  readonly recorder?: SpanRecorder;
  readonly redaction?: RedactionConfig;
  readonly serviceName?: string;
}

export class NoopTelemetry implements TelemetryHooks {
  onIntentStart(): SpanHandle {
    return NOOP_SPAN;
  }
  onRiskEvaluated(): SpanHandle {
    return NOOP_SPAN;
  }
  onPoliciesEvaluated(): SpanHandle {
    return NOOP_SPAN;
  }
  onDecisionMade(): SpanHandle {
    return NOOP_SPAN;
  }
}
const NOOP_SPAN: SpanHandle = new (class {
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
  context(): never {
    throw new Error('Noop span has no context');
  }
})() as unknown as SpanHandle;

export function createIntentTelemetry(options: CreateTelemetryOptions = {}): TelemetryHooks {
  const recorder = options.recorder ?? new NoopSpanRecorder();
  const redactor = new AttributeRedactor(options.redaction ?? {});
  const serviceName = options.serviceName ?? 'express-intent';
  const MAX_ATTR_VALUE_LENGTH = 512;
  const MAX_LIST_ITEMS = 32;

  function clip(s: string): string {
    if (s.length <= MAX_ATTR_VALUE_LENGTH) return s;
    return s.slice(0, MAX_ATTR_VALUE_LENGTH) + '\u2026';
  }

  function clipList(list: ReadonlyArray<string>): string {
    return list.slice(0, MAX_LIST_ITEMS).map(clip).join(',');
  }

  function wrap(handle: SpanHandle): SpanHandle {
    return {
      setAttribute(k, v) {
        const filtered = redactor.filter({ [k]: v });
        if (k in filtered) {
          const out = filtered[k]!;
          if (typeof out === 'string') handle.setAttribute(k, clip(out));
          else handle.setAttribute(k, out);
        }
      },
      setAttributes(a) {
        const filtered = redactor.filter(a);
        for (const k of Object.keys(filtered)) {
          const v = filtered[k]!;
          if (typeof v === 'string') filtered[k] = clip(v);
        }
        handle.setAttributes(filtered);
      },
      addEvent(name, a) {
        const filtered = a === undefined ? undefined : redactor.filter(a);
        if (filtered !== undefined) {
          for (const k of Object.keys(filtered)) {
            const v = filtered[k]!;
            if (typeof v === 'string') filtered[k] = clip(v);
          }
        }
        handle.addEvent(name, filtered);
      },
      setStatus(code, message) {
        handle.setStatus(code, message);
      },
      recordError(err) {
        handle.recordError(err);
      },
      end() {
        handle.end();
      },
      context() {
        return handle.context();
      },
    };
  }

  function attrs(
    input: IntentEvaluationInput,
    prefix: 'intent' | 'risk' | 'policy' | 'decision',
  ): Record<string, string | number | boolean> {
    const base: Record<string, unknown> = {
      [`${prefix}.service`]: serviceName,
      [`${prefix}.request_id`]: input.requestId,
      [`${prefix}.action`]: input.action,
      [`${prefix}.intent_key`]: input.intentKey,
      [`${prefix}.actor.authenticated`]: input.actor.authenticated,
      [`${prefix}.request.method`]: input.request.method,
      [`${prefix}.request.path`]: clip(input.request.path),
    };
    if (input.actor.subject !== null) {
      const hash = pseudoId(input.actor.subject);
      base[`${prefix}.actor.pseudo`] = hash;
    }
    if (input.actor.roles.length > 0) {
      base[`${prefix}.actor.roles_count`] = input.actor.roles.length;
    }
    if (input.request.userAgent !== null)
      base[`${prefix}.request.user_agent_family`] = familyOf(input.request.userAgent);
    if (input.request.ip !== null) base[`${prefix}.request.ip_hash`] = pseudoId(input.request.ip);
    if (input.signalsPresent.length > 0)
      base[`${prefix}.signals.present_count`] = input.signalsPresent.length;
    if (input.signalsMissing.length > 0)
      base[`${prefix}.signals.missing_count`] = input.signalsMissing.length;
    return redactor.filter(base);
  }

  return {
    onIntentStart(input) {
      return wrap(recorder.startSpan('express_intent.intent_evaluate', attrs(input, 'intent')));
    },
    onRiskEvaluated(input) {
      return wrap(
        recorder.startSpan('express_intent.risk_evaluate', {
          ...attrs(input, 'risk'),
          'risk.score': input.score,
          'risk.severity': input.severity,
          'risk.breakdown_count': input.breakdownCount,
          'risk.top_reasons': clipList(input.breakdownTopReasons),
        }),
      );
    },
    onPoliciesEvaluated(input) {
      return wrap(
        recorder.startSpan('express_intent.policy_evaluate', {
          ...attrs(input, 'policy'),
          'policy.evaluated_count': input.policiesEvaluated.length,
          'policy.matched_count': input.policiesMatched.length,
          'policy.evaluated': clipList(input.policiesEvaluated),
          'policy.matched': clipList(input.policiesMatched),
        }),
      );
    },
    onDecisionMade(input) {
      const span = wrap(
        recorder.startSpan('express_intent.decision', {
          ...attrs(input, 'decision'),
          'decision.kind': input.decisionKind,
          'decision.duration_ms': input.durationMs,
          ...(input.decisionReason !== null
            ? { 'decision.reason': clip(input.decisionReason) }
            : {}),
          ...(input.riskScore !== null ? { 'decision.risk_score': input.riskScore } : {}),
          ...(input.riskSeverity !== null
            ? { 'decision.risk_severity': clip(input.riskSeverity) }
            : {}),
        }),
      );
      span.setStatus(
        input.decisionKind === 'deny' || input.decisionKind === 'error' ? 'error' : 'ok',
      );
      return span;
    },
  };
}

function pseudoId(value: string): string {
  if (value.length > 1024) value = value.slice(0, 1024);
  let h = 0;
  for (let i = 0; i < value.length; i++) h = (h * 31 + value.charCodeAt(i)) | 0;
  return 'p' + Math.abs(h).toString(36);
}

const RE_CURL = /curl/i;
const RE_POSTMAN = /Postman/i;
const RE_MOZILLA = /Mozilla/i;
const RE_NODE_HTTP = /node-fetch|undici/i;

function familyOf(ua: string): string {
  if (ua.length > 1024) ua = ua.slice(0, 1024);
  if (RE_CURL.test(ua)) return 'curl';
  if (RE_POSTMAN.test(ua)) return 'postman';
  if (RE_MOZILLA.test(ua)) return 'browser';
  if (RE_NODE_HTTP.test(ua)) return 'node-http';
  if (ua.length === 0) return 'unknown';
  return 'other';
}
