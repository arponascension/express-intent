export {
  NoopSpanRecorder,
  NoopSpanHandle,
  SpySpanRecorder,
  type SpanRecorder,
  type SpanHandle,
  type SpanContext,
  type SpanStatusCode,
} from './recorder.js';
export { AttributeRedactor, DEFAULT_REDACTION_CONFIG, type RedactionConfig } from './redact.js';
export {
  createIntentTelemetry,
  NoopTelemetry,
  type TelemetryHooks,
  type CreateTelemetryOptions,
  type IntentEvaluationInput,
  type RiskEvaluationInput,
  type PolicyEvaluationInput,
  type DecisionMadeInput,
} from './telemetry.js';
export {
  OTelSpanRecorder,
  tryLoadOTelAPI,
  createOTelTelemetry,
  type OTelTracerLike,
  type OTelSpanLike,
  type OTelAPI,
  type OTelBridgeOptions,
  type CreateOTelTelemetryOptions,
} from './otel-bridge.js';
