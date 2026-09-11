import type {
  Anomaly,
  AnomalyDetector,
  AnomalyDetectorConfig,
  AnomalyReport,
  Observation,
} from './anomaly-defs.js';
import { DEFAULT_ANOMALY_CONFIG } from './anomaly-defs.js';
import type { ObservationStore } from './anomaly-store.js';

export interface AnomalyEngineOptions {
  readonly detectors?: ReadonlyArray<AnomalyDetector>;
  readonly store?: ObservationStore;
  readonly config?: AnomalyDetectorConfig;
}

export class AnomalyEngine {
  private readonly detectors: AnomalyDetector[];
  private readonly store: ObservationStore;
  private readonly config: Required<AnomalyDetectorConfig>;

  constructor(options: AnomalyEngineOptions = {}) {
    this.detectors = [...(options.detectors ?? [])];
    this.store = options.store ?? {
      record: () => undefined,
      recent: () => Object.freeze([]) as ReadonlyArray<Observation>,
      clear: () => undefined,
    };
    this.config = { ...DEFAULT_ANOMALY_CONFIG, ...(options.config ?? {}) };
  }

  register(detector: AnomalyDetector): void {
    if (this.detectors.some((d) => d.name === detector.name)) {
      throw new Error(`Detector with name "${detector.name}" is already registered`);
    }
    this.detectors.push(detector);
  }

  async observe(observation: Observation): Promise<AnomalyReport> {
    const cfg = this.config;
    const history = await Promise.resolve(
      this.store.recent({
        actorSubject: observation.actorSubject ?? undefined,
        now: observation.now,
        windowMs: cfg.windowMs,
      }),
    );
    const all: Anomaly[] = [];
    for (const d of this.detectors) {
      all.push(d.detect(observation, history, cfg));
    }
    await Promise.resolve(this.store.record(observation));

    const sorted = [...all].sort((a, b) =>
      a.detector < b.detector ? -1 : a.detector > b.detector ? 1 : 0,
    );
    const detected = sorted.filter((a) => a.detected);
    const maxConfidence = sorted.reduce((acc, a) => (a.confidence > acc ? a.confidence : acc), 0);

    return Object.freeze({
      detected: Object.freeze(detected) as ReadonlyArray<Anomaly>,
      all: Object.freeze(sorted) as ReadonlyArray<Anomaly>,
      maxConfidence,
    }) as AnomalyReport;
  }
}
