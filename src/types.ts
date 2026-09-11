export type {
  AuthRequirement,
  SensitivityClass,
  MutationClass,
  ChallengeKind,
  WindowSpec,
  VelocityTolerance,
  AnomalyTolerance,
  AuthFreshnessTolerance,
  QuotaHint,
  IntentOptions,
  Intent,
  AuthMethod,
  Actor,
  RiskSignalKind,
  RiskSignalValue,
  RiskSignal,
  Risk,
  IntentContext,
  RequestSnapshot,
  DecisionKind,
  AllowDecision,
  MonitorDecision,
  RateLimitDecision,
  ChallengeDecision,
  DenyDecision,
  Decision,
  PolicyInput,
  PolicyResult,
  Policy,
  AuditOutcome,
  EnricherOutcome,
  ContextEnricher,
  SignalProvider,
  AdapterResult,
  PolicyAdapter,
  StoreEntry,
  SignalStore,
  DecisionSink,
  Logger,
  ValidationIssue,
} from './domain/index.js';

export { freezeContext } from './domain/index.js';
export { compareDecisions, isDecision } from './domain/index.js';
export { hashContext, hashDecision, hashRisk } from './domain/index.js';
export { validateIntentOptions, validateWindowSpec, isIntentOptions } from './domain/index.js';

export type { Severity } from './risk-config.js';
export type {
  SeverityThresholds,
  NumericRange,
  SignalWeightConfig,
  RiskConfig,
} from './risk-config.js';
export { DEFAULT_RISK_CONFIG, DEFAULT_THRESHOLDS, SEVERITY_ORDER } from './risk-config.js';
export type { RiskBreakdownEntry, RiskEvaluation, EvaluateOptions } from './risk-engine.js';
export { evaluateRisk, compareSeverity } from './risk-engine.js';

export type { DecisionThresholds, DecisionConfig } from './decision/config.js';
export {
  DEFAULT_DECISION_CONFIG,
  DEFAULT_CHALLENGE,
  DEFAULT_CHALLENGE_TTL_MS,
  DEFAULT_DENY_STATUS,
  DEFAULT_LIMIT,
  SEVERITY_TO_KIND,
} from './decision/config.js';
export type { DecisionInput, DecisionEvaluation } from './decision/engine.js';
export { evaluateDecision } from './decision/engine.js';

export type {
  AnonymousActor,
  ActorLike,
  ActorProvider,
  ActorExtractor,
  ActorProviderOptions,
  ResolveActorOptions,
} from './actor.js';
export {
  ANONYMOUS_ACTOR,
  anonymousActor,
  defaultActorProvider,
  defaultActorExtractor,
  normalizeActor,
  resolveActor,
} from './actor.js';

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
} from './policy-engine.js';
export {
  definePolicy,
  when,
  validatePolicyDefinition,
  compilePolicy,
  toBuiltPolicy,
  evaluatePolicies,
  sortPoliciesById,
  pAllow,
  pDeny,
  pChallenge,
  pMonitor,
  pRateLimit,
  NOOP,
} from './policy-engine.js';
export type { PolicyValidationError as PolicyValidationErrorType } from './policy-defs.js';
export { PolicyValidationError } from './policy-defs.js';

export type {
  RateLimitScope,
  RateLimitSpec,
  RateLimitResult,
  RateLimiter,
} from './rate-limit-defs.js';
export { InMemoryRateLimiter, buildRateLimitKey } from './rate-limit-memory.js';
export type { InMemoryRateLimiterOptions } from './rate-limit-memory.js';

export type {
  Observation,
  AnomalyDetails,
  Anomaly,
  AnomalyReport,
  AnomalyDetectorConfig,
  AnomalyDetector,
} from './anomaly-defs.js';
export { DEFAULT_ANOMALY_CONFIG, anomaly as anomalyBuilder, notDetected } from './anomaly-defs.js';
export {
  BUILTIN_DETECTORS,
  VELOCITY,
  ENUMERATION,
  USER_AGENT_CHANGE,
  IP_CHANGE,
  ENDPOINT_PATTERN,
} from './anomaly-detectors.js';
export type { ObservationStore, InMemoryObservationStoreOptions } from './anomaly-store.js';
export { InMemoryObservationStore } from './anomaly-store.js';
export { AnomalyEngine } from './anomaly-engine.js';
export type { AnomalyEngineOptions } from './anomaly-engine.js';
