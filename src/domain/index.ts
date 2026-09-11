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
} from './intent.js';

export type { AuthMethod, Actor } from './actor.js';

export type { RiskSignalKind, RiskSignalValue, RiskSignal, Risk } from './risk.js';

export type { IntentContext, RequestSnapshot } from './context.js';
export { freezeContext } from './context.js';

export type {
  DecisionKind,
  AllowDecision,
  MonitorDecision,
  RateLimitDecision,
  ChallengeDecision,
  DenyDecision,
  Decision,
} from './decision.js';
export { compareDecisions } from './decision.js';

export type { PolicyInput, PolicyResult, Policy } from './policy.js';
export { isDecision } from './policy.js';

export type { AuditOutcome } from '../audit-defs.js';

export type {
  EnricherOutcome,
  ContextEnricher,
  SignalProvider,
  AdapterResult,
  PolicyAdapter,
  StoreEntry,
  SignalStore,
  DecisionSink,
  Logger,
} from './providers.js';

export {
  validateIntentOptions,
  validateWindowSpec,
  isIntentOptions,
  type ValidationIssue,
} from './validate.js';
export { hashContext, hashDecision, hashRisk } from './hash.js';
