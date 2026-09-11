export type AuditSeverity = 'debug' | 'info' | 'warn' | 'error';

export type AuditOutcome = 'allow' | 'monitor' | 'challenge' | 'rate_limit' | 'deny' | 'error';

export type AuditEventType =
  | 'intent.evaluated'
  | 'security.denied'
  | 'security.challenged'
  | 'security.rate_limited'
  | 'security.anomaly'
  | 'security.error';

export interface AuditEvent {
  readonly type: AuditEventType;
  readonly severity: AuditSeverity;
  readonly requestId: string;
  readonly action: string;
  readonly intentKey: string;
  readonly outcome: 'allow' | 'monitor' | 'challenge' | 'rate_limit' | 'deny' | 'error';
  readonly decisionKind: 'allow' | 'monitor' | 'challenge' | 'rate_limit' | 'deny' | 'error';
  readonly actor: {
    readonly subject: string | null;
    readonly authenticated: boolean;
    readonly roles: ReadonlyArray<string>;
  };
  readonly request: {
    readonly method: string;
    readonly path: string;
    readonly ip: string | null;
    readonly userAgent: string | null;
    readonly headers: Readonly<Record<string, string>>;
    readonly query: Readonly<Record<string, string>>;
    readonly bodyKeys: ReadonlyArray<string>;
    readonly body: unknown;
  };
  readonly response: { readonly status: number | null; readonly durationMs: number };
  readonly risk: { readonly score: number | null; readonly severity: string | null };
  readonly signals: {
    readonly present: ReadonlyArray<string>;
    readonly missing: ReadonlyArray<string>;
  };
  readonly anomalies: ReadonlyArray<{
    readonly type: string;
    readonly confidence: number;
    readonly reasons: ReadonlyArray<string>;
  }>;
  readonly policy: {
    readonly evaluated: ReadonlyArray<string>;
    readonly matched: ReadonlyArray<string>;
  };
  readonly tags: Readonly<Record<string, string>>;
  readonly emittedAt: number;
}

export interface AuditSink {
  readonly name: string;
  emit(event: AuditEvent): void | Promise<void>;
  flush?(): void | Promise<void>;
  close?(): void | Promise<void>;
}

export class NullAuditSink implements AuditSink {
  readonly name = 'null';
  emit(): void {
    /* noop */
  }
}
