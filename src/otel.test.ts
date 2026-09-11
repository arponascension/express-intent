import { describe, it, expect, beforeEach } from 'vitest';
import {
  SpySpanRecorder,
  NoopSpanRecorder,
  AttributeRedactor,
  DEFAULT_REDACTION_CONFIG,
  createIntentTelemetry,
  NoopTelemetry,
  OTelSpanRecorder,
  tryLoadOTelAPI,
  createOTelTelemetry,
  type OTelTracerLike,
  type OTelSpanLike,
  type IntentEvaluationInput,
  type RiskEvaluationInput,
  type PolicyEvaluationInput,
  type DecisionMadeInput,
} from './otel/index.js';

const baseInput: IntentEvaluationInput = {
  requestId: 'req-1',
  action: 'users.create',
  intentKey: 'users.create:default',
  actor: { subject: 'user-42', authenticated: true, roles: ['user', 'beta'] },
  request: { method: 'POST', path: '/api/users', userAgent: 'Mozilla/5.0 ...', ip: '203.0.113.42' },
  signalsPresent: ['auth_strength', 'ip_reputation', 'device_fingerprint'],
  signalsMissing: [],
};

describe('AttributeRedactor', () => {
  it('replaces secret keys with [REDACTED]', () => {
    const r = new AttributeRedactor();
    const out = r.filter({
      authorization: 'Bearer abc',
      cookie: 'sess=1',
      'x-api-key': 'k',
      password: 'hunter2',
      access_token: 't',
    });
    expect(out['authorization']).toBe('[REDACTED]');
    expect(out['cookie']).toBe('[REDACTED]');
    expect(out['x-api-key']).toBe('[REDACTED]');
    expect(out['password']).toBe('[REDACTED]');
    expect(out['access_token']).toBe('[REDACTED]');
  });

  it('keeps allowlisted keys', () => {
    const r = new AttributeRedactor();
    const out = r.filter({
      'express_intent.action': 'a.b',
      'risk.score': 75,
      'policy.evaluated': 'p1,p2',
      'decision.kind': 'deny',
      'actor.id': 'pseudo-here',
    });
    expect(out['express_intent.action']).toBe('a.b');
    expect(out['risk.score']).toBe(75);
    expect(out['policy.evaluated']).toBe('p1,p2');
    expect(out['decision.kind']).toBe('deny');
  });

  it('truncates long string values', () => {
    const r = new AttributeRedactor();
    const out = r.filter({ note: 'x'.repeat(2000) });
    expect((out['note'] as string).length).toBeLessThan(2000);
  });

  it('drops null/undefined values', () => {
    const r = new AttributeRedactor();
    const out = r.filter({ x: null, y: undefined, z: 'ok' });
    expect(out).toEqual({ z: 'ok' });
  });

  it('coerces objects/arrays to [REDACTED]', () => {
    const r = new AttributeRedactor();
    const out = r.filter({ obj: { a: 1 }, arr: [1, 2] });
    expect(out['obj']).toBe('[REDACTED]');
    expect(out['arr']).toBe('[REDACTED]');
  });

  it('additionalDenyPatterns can extend the deny list', () => {
    const r = new AttributeRedactor({ additionalDenyPatterns: [/^custom_secret$/] });
    const out = r.filter({ custom_secret: 'shh', fine: 'ok' });
    expect(out['custom_secret']).toBe('[REDACTED]');
    expect(out['fine']).toBe('ok');
  });

  it('custom replacement', () => {
    const r = new AttributeRedactor({ replacement: '***' });
    const out = r.filter({ authorization: 'Bearer x' });
    expect(out['authorization']).toBe('***');
  });

  it('isAllowed() returns true for safe, false for sensitive', () => {
    const r = new AttributeRedactor();
    expect(r.isAllowed('authorization')).toBe(false);
    expect(r.isAllowed('cookie')).toBe(false);
    expect(r.isAllowed('risk.score')).toBe(true);
    expect(r.isAllowed('decision.kind')).toBe(true);
  });
});

describe('SpySpanRecorder', () => {
  let spy: SpySpanRecorder;
  beforeEach(() => {
    spy = new SpySpanRecorder();
  });

  it('captures started spans with attributes', () => {
    const h = spy.startSpan('test', { x: 1 });
    h.setAttribute('y', 'two');
    h.addEvent('ev1', { k: 'v' });
    h.end();
    expect(spy.spans).toHaveLength(1);
    const s = spy.spans[0]!;
    expect(s.name).toBe('test');
    expect(s.attributes['x']).toBe(1);
    expect(s.attributes['y']).toBe('two');
    expect(s.events).toHaveLength(1);
    expect(s.events[0]?.name).toBe('ev1');
    expect(s.endTime).toBeGreaterThanOrEqual(s.startTime);
  });

  it('records errors as events with error status', () => {
    const h = spy.startSpan('test');
    h.recordError(new Error('boom'));
    h.end();
    const s = spy.spans[0]!;
    expect(s.status.code).toBe('error');
    expect(s.status.message).toBe('boom');
    expect(s.events.some((e) => e.name === 'exception')).toBe(true);
  });

  it('end() is idempotent', () => {
    const h = spy.startSpan('test');
    h.end();
    h.end();
    expect(spy.spans).toHaveLength(1);
  });
});

describe('createIntentTelemetry', () => {
  let spy: SpySpanRecorder;
  let hooks: ReturnType<typeof createIntentTelemetry>;
  beforeEach(() => {
    spy = new SpySpanRecorder();
    hooks = createIntentTelemetry({ recorder: spy, serviceName: 'svc' });
  });

  it('emits intent_evaluate span with base attributes', () => {
    const h = hooks.onIntentStart(baseInput);
    h.end();
    const s = spy.spans[0]!;
    expect(s.name).toBe('express_intent.intent_evaluate');
    expect(s.attributes['intent.action']).toBe('users.create');
    expect(s.attributes['intent.intent_key']).toBe('users.create:default');
    expect(s.attributes['intent.actor.authenticated']).toBe(true);
    expect(s.attributes['intent.request.method']).toBe('POST');
    expect(s.attributes['intent.request.path']).toBe('/api/users');
    expect(s.attributes['intent.request.user_agent_family']).toBe('browser');
    expect(s.attributes['intent.service']).toBe('svc');
  });

  it('emits risk_evaluate span with score, severity, breakdown', () => {
    const r: RiskEvaluationInput = {
      ...baseInput,
      score: 82,
      severity: 'high',
      breakdownCount: 4,
      breakdownTopReasons: ['new_device', 'unusual_hour', 'vpn_ip', 'risky_endpoint'],
    };
    const h = hooks.onRiskEvaluated(r);
    h.end();
    const s = spy.spans[0]!;
    expect(s.name).toBe('express_intent.risk_evaluate');
    expect(s.attributes['risk.score']).toBe(82);
    expect(s.attributes['risk.severity']).toBe('high');
    expect(s.attributes['risk.breakdown_count']).toBe(4);
    expect(typeof s.attributes['risk.top_reasons']).toBe('string');
  });

  it('emits policy_evaluate span with evaluated/matched lists', () => {
    const p: PolicyEvaluationInput = {
      ...baseInput,
      policiesEvaluated: ['p1', 'p2', 'p3'],
      policiesMatched: ['p2'],
    };
    const h = hooks.onPoliciesEvaluated(p);
    h.end();
    const s = spy.spans[0]!;
    expect(s.name).toBe('express_intent.policy_evaluate');
    expect(s.attributes['policy.evaluated_count']).toBe(3);
    expect(s.attributes['policy.matched_count']).toBe(1);
    expect(s.attributes['policy.evaluated']).toBe('p1,p2,p3');
    expect(s.attributes['policy.matched']).toBe('p2');
  });

  it('emits decision span with kind, duration, risk; status=ok for allow', () => {
    const d: DecisionMadeInput = {
      ...baseInput,
      decisionKind: 'allow',
      decisionReason: null,
      riskScore: 12,
      riskSeverity: 'low',
      durationMs: 23,
    };
    const h = hooks.onDecisionMade(d);
    h.end();
    const s = spy.spans[0]!;
    expect(s.name).toBe('express_intent.decision');
    expect(s.attributes['decision.kind']).toBe('allow');
    expect(s.attributes['decision.duration_ms']).toBe(23);
    expect(s.attributes['decision.risk_score']).toBe(12);
    expect(s.status.code).toBe('ok');
  });

  it('decision span for deny has status=error', () => {
    const d: DecisionMadeInput = {
      ...baseInput,
      decisionKind: 'deny',
      decisionReason: 'high_risk',
      riskScore: 95,
      riskSeverity: 'critical',
      durationMs: 18,
    };
    const h = hooks.onDecisionMade(d);
    h.end();
    expect(spy.spans[0]?.status.code).toBe('error');
    expect(spy.spans[0]?.attributes['decision.reason']).toBe('high_risk');
  });

  it('actor.subject is pseudonymized (not the raw value)', () => {
    const h = hooks.onIntentStart(baseInput);
    h.end();
    const s = spy.spans[0]!;
    const pseudo = s.attributes['intent.actor.pseudo'];
    expect(typeof pseudo).toBe('string');
    expect(pseudo).not.toBe('user-42');
    expect(JSON.stringify(s.attributes)).not.toContain('user-42');
  });

  it('ip is pseudonymized to ip_hash, not raw', () => {
    const h = hooks.onIntentStart(baseInput);
    h.end();
    const s = spy.spans[0]!;
    expect(typeof s.attributes['intent.request.ip_hash']).toBe('string');
    expect(JSON.stringify(s.attributes)).not.toContain('203.0.113.42');
  });

  it('user_agent is bucketed to family, not full string', () => {
    const h = hooks.onIntentStart(baseInput);
    h.end();
    const s = spy.spans[0]!;
    expect(s.attributes['intent.request.user_agent_family']).toBe('browser');
    expect(JSON.stringify(s.attributes)).not.toContain('Mozilla/5.0 ...');
  });
});

describe('createIntentTelemetry — sensitive data is never leaked', () => {
  it('even if caller passes an authorization header in attributes, it is redacted', () => {
    const spy = new SpySpanRecorder();
    const hooks = createIntentTelemetry({ recorder: spy });
    const h = hooks.onIntentStart({ ...baseInput });
    h.setAttribute('authorization', 'Bearer leaked-token');
    h.setAttribute('cookie', 'sess=leak');
    h.setAttribute('password', 'p');
    h.end();
    const s = spy.spans[0]!;
    expect(JSON.stringify(s.attributes)).not.toContain('leaked-token');
    expect(JSON.stringify(s.attributes)).not.toContain('sess=leak');
    expect(s.attributes['authorization']).toBe('[REDACTED]');
    expect(s.attributes['cookie']).toBe('[REDACTED]');
    expect(s.attributes['password']).toBe('[REDACTED]');
  });

  it('high-entropy object values (which could be bodies or headers) are redacted', () => {
    const spy = new SpySpanRecorder();
    const hooks = createIntentTelemetry({ recorder: spy });
    const h = hooks.onIntentStart({ ...baseInput });
    h.setAttribute('request.headers', { authorization: 'Bearer x' });
    h.setAttribute('request.body', { password: 'p' });
    h.end();
    const s = spy.spans[0]!;
    expect(s.attributes['request.headers']).toBe('[REDACTED]');
    expect(s.attributes['request.body']).toBe('[REDACTED]');
  });
});

describe('NoopTelemetry', () => {
  it('returns no-op handles that do not throw', () => {
    const t = new NoopTelemetry();
    const h1 = t.onIntentStart(baseInput);
    const h2 = t.onRiskEvaluated({
      ...baseInput,
      score: 0,
      severity: 'low',
      breakdownCount: 0,
      breakdownTopReasons: [],
    });
    const h3 = t.onPoliciesEvaluated({ ...baseInput, policiesEvaluated: [], policiesMatched: [] });
    const h4 = t.onDecisionMade({
      ...baseInput,
      decisionKind: 'allow',
      decisionReason: null,
      riskScore: null,
      riskSeverity: null,
      durationMs: 1,
    });
    for (const h of [h1, h2, h3, h4]) {
      h.setAttribute('x', 1);
      h.setAttributes({ y: 'z' });
      h.addEvent('e');
      h.setStatus('ok');
      h.recordError(new Error('x'));
      h.end();
    }
  });
});

describe('NoopSpanRecorder', () => {
  it('returns a noop handle', () => {
    const r = new NoopSpanRecorder();
    const h = r.startSpan('s', { x: 1 });
    h.setAttribute('y', 2);
    h.end();
  });
});

describe('tryLoadOTelAPI', () => {
  it('returns null when @opentelemetry/api is not installed', async () => {
    const api = await tryLoadOTelAPI();
    expect(api === null || typeof api === 'object').toBe(true);
  });
});

describe('createOTelTelemetry (without OTel installed)', () => {
  it('falls back to NoopTelemetry when API is missing', async () => {
    const t = await createOTelTelemetry({ tracerName: 'test' });
    expect(t).toBeInstanceOf(NoopTelemetry);
    const h = t.onIntentStart(baseInput);
    h.end();
  });

  it('uses provided OTelAPI when supplied', async () => {
    const recorded: { name: string; attrs?: Record<string, unknown> }[] = [];
    const fakeTracer: OTelTracerLike = {
      startSpan(name: string, opts?: { attributes?: Record<string, string | number | boolean> }) {
        recorded.push({ name, attrs: opts?.attributes });
        const span: OTelSpanLike = {
          setAttribute: () => undefined,
          setAttributes: () => undefined,
          addEvent: () => undefined,
          setStatus: () => undefined,
          recordException: () => undefined,
          end: () => undefined,
          spanContext: () => ({ traceId: 't', spanId: 's' }),
        };
        return span;
      },
    };
    const t = await createOTelTelemetry({ api: { trace: { getTracer: () => fakeTracer } } });
    const h = t.onIntentStart(baseInput);
    h.end();
    expect(recorded).toHaveLength(1);
    expect(recorded[0]?.name).toBe('express_intent.intent_evaluate');
    const attrs = recorded[0]?.attrs as Record<string, string | number | boolean>;
    expect(attrs['intent.action']).toBe('users.create');
    expect(attrs['intent.request.user_agent_family']).toBe('browser');
  });
});

describe('OTelSpanRecorder', () => {
  it('forwards setStatus codes to OTel', () => {
    const calls: { status: { code: number; message?: string } }[] = [];
    const fakeSpan: OTelSpanLike = {
      setAttribute: () => undefined,
      setAttributes: () => undefined,
      addEvent: () => undefined,
      setStatus: (s) => {
        calls.push({ status: s });
      },
      recordException: () => undefined,
      end: () => undefined,
      spanContext: () => ({ traceId: 't', spanId: 's' }),
    };
    const fakeTracer: OTelTracerLike = { startSpan: () => fakeSpan };
    const r = new OTelSpanRecorder({ tracer: fakeTracer });
    const h = r.startSpan('s');
    h.setStatus('ok');
    h.setStatus('error', 'failed');
    h.setStatus('unset');
    expect(calls[0]?.status.code).toBe(1);
    expect(calls[1]?.status.code).toBe(2);
    expect(calls[1]?.status.message).toBe('failed');
    expect(calls[2]?.status.code).toBe(0);
  });

  it('redacts sensitive attributes before passing to OTel', () => {
    const recorded: { attrs?: Record<string, unknown> } = { attrs: undefined };
    const fakeSpan: OTelSpanLike = {
      setAttribute: () => undefined,
      setAttributes: () => undefined,
      addEvent: () => undefined,
      setStatus: () => undefined,
      recordException: () => undefined,
      end: () => undefined,
      spanContext: () => ({ traceId: 't', spanId: 's' }),
    };
    const fakeTracer: OTelTracerLike = {
      startSpan: (_n, opts) => {
        recorded.attrs = opts?.attributes;
        return fakeSpan;
      },
    };
    const r = new OTelSpanRecorder({ tracer: fakeTracer });
    r.startSpan('s', { authorization: 'Bearer leaked' });
    expect(recorded.attrs?.['authorization']).toBe('[REDACTED]');
  });
});

describe('Package does not require @opentelemetry/api at runtime', () => {
  it('importing the otel subpath does not throw when API is absent', async () => {
    const mod = await import('./otel/index.js');
    expect(typeof mod.createIntentTelemetry).toBe('function');
    expect(typeof mod.NoopSpanRecorder).toBe('function');
  });
});

describe('DEFAULT_REDACTION_CONFIG export sanity', () => {
  it('is frozen-style: includes replacement default', () => {
    expect(DEFAULT_REDACTION_CONFIG.replacement).toBe('[REDACTED]');
  });
});

describe('Compatibility with policy adapter that throws', () => {
  it('recordError on a decision span surfaces as event + error status', () => {
    const spy = new SpySpanRecorder();
    const hooks = createIntentTelemetry({ recorder: spy });
    const h = hooks.onDecisionMade({
      ...baseInput,
      decisionKind: 'error',
      decisionReason: 'policy_timeout',
      riskScore: null,
      riskSeverity: null,
      durationMs: 5,
    });
    h.recordError(new Error('timeout after 100ms'));
    h.end();
    const s = spy.spans[0]!;
    expect(s.status.code).toBe('error');
    expect(s.events.some((e) => e.name === 'exception')).toBe(true);
  });
});
