export type AuthRequirement = 'anonymous' | 'required' | 'mfa-required';

export type SensitivityClass = 'public' | 'internal' | 'pii' | 'critical';

export type MutationClass = 'none' | 'read' | 'create' | 'update' | 'destructive';

export type ChallengeKind = 'reauth' | 'captcha' | 'mfa';

export interface WindowSpec {
  readonly amount: number;
  readonly unit: 'ms' | 's' | 'm' | 'h' | 'd';
}

export interface VelocityTolerance {
  readonly window: WindowSpec;
  readonly max: number;
  readonly per: 'ip' | 'subject' | 'pair';
}

export interface AnomalyTolerance {
  readonly threshold: number;
  readonly window: WindowSpec;
}

export interface AuthFreshnessTolerance {
  readonly maxAgeMs: number;
  readonly requiredMethods?: ReadonlyArray<string>;
}

export interface QuotaHint {
  readonly per: 'subject' | 'ip' | 'pair';
  readonly window: WindowSpec;
  readonly max: number;
}

export interface DecisionOverrides {
  readonly rateLimitAt?: number;
  readonly challengeAt?: number;
  readonly denyAt?: number;
  readonly challengeKind?: ChallengeKind;
  readonly challengeTtlMs?: number | null;
  readonly denyStatus?: number;
  readonly limit?: number;
}

export interface IntentOptions {
  readonly auth?: AuthRequirement;
  readonly sensitivity?: SensitivityClass;
  readonly mutation?: MutationClass;
  readonly velocity?: VelocityTolerance;
  readonly anomaly?: AnomalyTolerance;
  readonly authFreshness?: AuthFreshnessTolerance;
  readonly quotas?: ReadonlyArray<QuotaHint>;
  readonly tags?: ReadonlyArray<string>;
  readonly decisionOverrides?: DecisionOverrides;
}

export interface Intent<TKey extends string = string> {
  readonly key: TKey;
  readonly auth: AuthRequirement;
  readonly sensitivity: SensitivityClass;
  readonly mutation: MutationClass;
  readonly velocity: VelocityTolerance | null;
  readonly anomaly: AnomalyTolerance | null;
  readonly authFreshness: AuthFreshnessTolerance | null;
  readonly quotas: ReadonlyArray<QuotaHint>;
  readonly tags: ReadonlyArray<string>;
  readonly decisionOverrides: DecisionOverrides;
}
