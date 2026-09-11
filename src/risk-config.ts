export type Severity = 'low' | 'medium' | 'high' | 'critical';

export interface SeverityThresholds {
  readonly low: number;
  readonly medium: number;
  readonly high: number;
  readonly critical: number;
}

export interface NumericRange {
  readonly min: number;
  readonly max: number;
  readonly invert?: boolean;
}

export interface SignalWeightConfig {
  readonly weight?: number;
  readonly range?: NumericRange;
  readonly categorical?: Readonly<Record<string, number>>;
  readonly decay?: {
    readonly halfLifeMs: number;
    readonly floor: number;
  };
}

export interface RiskConfig {
  readonly defaultWeight?: number;
  readonly thresholds?: SeverityThresholds;
  readonly signals?: Readonly<Record<string, SignalWeightConfig>>;
}

export const DEFAULT_THRESHOLDS: SeverityThresholds = {
  low: 25,
  medium: 50,
  high: 75,
  critical: 90,
};

export const DEFAULT_RISK_CONFIG: Required<Pick<RiskConfig, 'defaultWeight' | 'thresholds'>> = {
  defaultWeight: 1,
  thresholds: DEFAULT_THRESHOLDS,
};

export const SEVERITY_ORDER: ReadonlyArray<Severity> = ['low', 'medium', 'high', 'critical'];
