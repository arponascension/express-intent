export type RiskSignalKind = 'numeric' | 'categorical' | 'boolean';

export type RiskSignalValue = number | string | boolean | null;

export interface RiskSignal<
  TKind extends RiskSignalKind = RiskSignalKind,
  TValue = RiskSignalValue,
> {
  readonly name: string;
  readonly kind: TKind;
  readonly value: TValue;
  readonly confidence: number;
  readonly source: string;
  readonly computedAt: number;
  readonly ttlMs: number;
}

export interface Risk {
  readonly signals: ReadonlyArray<RiskSignal>;
  readonly missing: ReadonlyArray<string>;
  readonly aggregationHash: string;
  readonly computedAt: number;
}
