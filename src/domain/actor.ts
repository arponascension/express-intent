import type { AuthRequirement } from './intent.js';

export type AuthMethod = 'password' | 'oauth2' | 'sso' | 'api-key' | 'mfa' | 'passkey' | 'unknown';

export interface Actor {
  readonly subject: string | null;
  readonly authenticated: boolean;
  readonly authMethod: AuthMethod | null;
  readonly authRequirement: AuthRequirement;
  readonly roles: ReadonlyArray<string>;
  readonly scopes: ReadonlyArray<string>;
  readonly claims: Readonly<Record<string, unknown>>;
  readonly authenticatedAt: number | null;
}
