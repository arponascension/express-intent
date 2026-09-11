// ── Core ──────────────────────────────────────────────────────
export type {
  Intent,
  IntentOptions,
  AuthRequirement,
  SensitivityClass,
  MutationClass,
} from './domain/index.js';

export {
  intent,
  parseAction,
  defineAction,
  getIntent,
  getIntentContext,
  getRequestSnapshot,
} from './middleware.js';
export type {
  IntentMiddlewareOptions,
  IntentMiddleware,
  IntentMiddlewareCreator,
  IntentPayload,
  IntentRequest,
  IntentRequestHandler,
} from './middleware.js';

export { defineIntent } from './intent/builder.js';
export { buildRequestContext } from './context.js';
export { runWithRequest } from './als.js';
export { generateRequestId } from './request-id.js';

// ── Decision helpers ──────────────────────────────────────────
export { allow, deny, challenge, monitor, rateLimit } from './decision/helpers.js';
export type { RateLimitInit } from './decision/helpers.js';
export { evaluateDecision } from './types.js';
export type {
  DecisionInput,
  DecisionEvaluation,
  DecisionKind,
  AllowDecision,
  MonitorDecision,
  RateLimitDecision,
  ChallengeDecision,
  DenyDecision,
  Decision,
} from './types.js';

// ── Actor ─────────────────────────────────────────────────────
export {
  defaultActorProvider,
  normalizeActor,
  resolveActor,
  anonymousActor,
  ANONYMOUS_ACTOR,
} from './types.js';
export type {
  Actor,
  AuthMethod,
  AnonymousActor,
  ActorLike,
  ActorProvider,
  ActorProviderOptions,
  ResolveActorOptions,
} from './types.js';

// ── Errors ────────────────────────────────────────────────────
export {
  IntentError,
  IntentValidationError,
  IntentDeniedError,
  MalformedActorError,
} from './errors.js';

// ── Action ────────────────────────────────────────────────────
export type { ActionConfig, ActionDescriptor } from './action.js';

// ── Policy engine ─────────────────────────────────────────────
export {
  definePolicy,
  when,
  validatePolicyDefinition,
  compilePolicy,
  toBuiltPolicy,
  evaluatePolicies,
  sortPoliciesById,
  pAllow as policyAllow,
  pDeny as policyDeny,
  pChallenge as policyChallenge,
  pMonitor as policyMonitor,
  pRateLimit as policyRateLimit,
  NOOP,
  PolicyValidationError,
} from './types.js';
export type {
  Condition,
  PolicyDefinition,
  PolicyDefinitionInput,
  PolicyEffect,
  PolicyEffectInput,
  PolicySeverity,
  PolicyInputShape,
  PolicyEvaluationTrace,
  BuiltPolicy,
  CompiledPolicy,
  EngineOptions,
  EngineInput,
  EngineOutput,
  PolicyInput,
  PolicyResult,
  Policy,
} from './types.js';

// ── Risk / Anomaly ────────────────────────────────────────────
export { evaluateRisk, compareSeverity } from './types.js';
export {
  AnomalyEngine,
  InMemoryObservationStore,
  VELOCITY,
  ENUMERATION,
  USER_AGENT_CHANGE,
  IP_CHANGE,
  ENDPOINT_PATTERN,
  BUILTIN_DETECTORS,
  DEFAULT_ANOMALY_CONFIG,
} from './types.js';
export type {
  Observation,
  Anomaly,
  AnomalyReport,
  AnomalyDetails,
  AnomalyDetector,
  AnomalyDetectorConfig,
  ObservationStore,
  InMemoryObservationStoreOptions,
  AnomalyEngineOptions,
  RiskSignalKind,
  RiskSignalValue,
  RiskSignal,
  Risk,
} from './types.js';
export {
  DEFAULT_RISK_CONFIG,
  DEFAULT_THRESHOLDS,
  SEVERITY_ORDER,
  DEFAULT_DECISION_CONFIG,
  DEFAULT_CHALLENGE,
  DEFAULT_CHALLENGE_TTL_MS,
  DEFAULT_DENY_STATUS,
  DEFAULT_LIMIT,
  SEVERITY_TO_KIND,
} from './types.js';
export type {
  Severity,
  SeverityThresholds,
  NumericRange,
  SignalWeightConfig,
  RiskConfig,
  RiskBreakdownEntry,
  RiskEvaluation,
  EvaluateOptions,
  DecisionThresholds,
  DecisionConfig,
} from './types.js';

// ── Rate limiting ─────────────────────────────────────────────
export { InMemoryRateLimiter, buildRateLimitKey } from './types.js';
export type {
  InMemoryRateLimiterOptions,
  RateLimitScope,
  RateLimitSpec,
  RateLimitResult,
  RateLimiter,
} from './types.js';

// ── Context / ALS ─────────────────────────────────────────────
export { freezeContext, hashContext, hashDecision, hashRisk } from './types.js';
export { validateIntentOptions, validateWindowSpec, isIntentOptions } from './types.js';
export { isDecision, compareDecisions } from './types.js';
export type {
  IntentContext,
  RequestSnapshot,
  EnricherOutcome,
  ContextEnricher,
  SignalProvider,
  AdapterResult,
  PolicyAdapter,
  StoreEntry,
  SignalStore,
  DecisionSink,
  Logger,
  AuditOutcome,
  ValidationIssue,
} from './types.js';

// ── Idempotency ───────────────────────────────────────────────
export { createIdempotencyMiddleware, idempotency, getIdempotency } from './idempotency.js';
export type { IdempotencyMiddlewareOptions, IdempotencyContext } from './idempotency.js';
export { InMemoryIdempotencyProvider } from './idempotency-memory.js';
export type { InMemoryIdempotencyProviderOptions } from './idempotency-memory.js';
export {
  IDEMPOTENCY_KEY_PATTERN,
  DEFAULT_IDEMPOTENCY_TTL_MS,
  DEFAULT_WAIT_DEADLINE_MS,
  isValidIdempotencyKey,
} from './idempotency-defs.js';
export type {
  IdempotencyProvider,
  IdempotencyState,
  IdempotencySnapshot,
  AcquireResult,
  StoredResponse,
} from './idempotency-defs.js';

// ── Audit ─────────────────────────────────────────────────────
export { attachAudit, audit } from './audit.js';
export type { AttachAuditOptions } from './audit.js';
export { InMemoryAuditSink, ConsoleAuditSink } from './audit-sinks.js';
export type { ConsoleAuditSinkOptions } from './audit-sinks.js';
export {
  RedactionEngine,
  DEFAULT_REDACTION_CONFIG,
  isSensitiveHeader,
  isSensitiveQueryParam,
  isSensitiveBodyKey,
} from './redaction.js';
export type { RedactionConfig, RedactionReplacement } from './redaction.js';
export { NullAuditSink } from './audit-defs.js';
export type { AuditEvent, AuditEventType, AuditSeverity, AuditSink } from './audit-defs.js';
