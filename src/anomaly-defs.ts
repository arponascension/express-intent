export interface Observation {
  readonly now: number;
  readonly actorSubject: string | null;
  readonly ip: string | null;
  readonly userAgent: string | null;
  readonly method: string;
  readonly path: string;
  readonly status: number | null;
  readonly resourceId: string | null;
}

export interface AnomalyDetails {
  readonly count?: number;
  readonly windowMs?: number;
  readonly distinctResources?: number;
  readonly distinctEndpoints?: number;
  readonly previous?: string | null;
  readonly current?: string | null;
  readonly threshold?: number;
}

export interface Anomaly {
  readonly type: string;
  readonly detected: boolean;
  readonly confidence: number;
  readonly reasons: ReadonlyArray<string>;
  readonly details: AnomalyDetails;
  readonly detector: string;
  readonly detectorVersion: number;
  readonly observedAt: number;
}

export interface AnomalyReport {
  readonly detected: ReadonlyArray<Anomaly>;
  readonly all: ReadonlyArray<Anomaly>;
  readonly maxConfidence: number;
}

export interface AnomalyDetectorConfig {
  readonly windowMs: number;
  readonly velocityMax?: number;
  readonly enumerationMaxDistinct?: number;
  readonly endpointPatternMaxDistinct?: number;
  readonly userAgentChangeEnabled?: boolean;
  readonly ipChangeEnabled?: boolean;
}

export const DEFAULT_ANOMALY_CONFIG: Required<AnomalyDetectorConfig> = {
  windowMs: 60_000,
  velocityMax: 50,
  enumerationMaxDistinct: 20,
  endpointPatternMaxDistinct: 30,
  userAgentChangeEnabled: true,
  ipChangeEnabled: true,
};

export interface AnomalyDetector {
  readonly name: string;
  readonly version: number;
  detect(
    observation: Observation,
    history: ReadonlyArray<Observation>,
    config: Required<AnomalyDetectorConfig>,
  ): Anomaly;
}

export function notDetected(
  detector: AnomalyDetector,
  observedAt: number,
  reason = 'no anomaly detected',
): Anomaly {
  return Object.freeze({
    type: detector.name,
    detected: false,
    confidence: 0,
    reasons: Object.freeze([reason]) as ReadonlyArray<string>,
    details: Object.freeze({}) as AnomalyDetails,
    detector: detector.name,
    detectorVersion: detector.version,
    observedAt,
  }) as Anomaly;
}

export function anomaly(
  detector: AnomalyDetector,
  observedAt: number,
  confidence: number,
  reasons: ReadonlyArray<string>,
  details: AnomalyDetails,
): Anomaly {
  const clamped = Math.max(0, Math.min(1, Number.isNaN(confidence) ? 0 : confidence));
  return Object.freeze({
    type: detector.name,
    detected: true,
    confidence: clamped,
    reasons: Object.freeze([...reasons]) as ReadonlyArray<string>,
    details: Object.freeze({ ...details }) as AnomalyDetails,
    detector: detector.name,
    detectorVersion: detector.version,
    observedAt,
  }) as Anomaly;
}
