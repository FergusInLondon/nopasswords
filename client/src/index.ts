/**
 * NoPasswords WebAuthn Client Library
 *
 * A TypeScript library for WebAuthn/FIDO2 passwordless authentication
 *
 * @packageDocumentation
 */

// WebAuthN Exports

export { WebAuthnClient } from './webauthn/client';
export {
  WebAuthnConfig,
  BeginRegistrationOptions as WebAuthnBeginRegistrationOptions,
  BeginAuthenticationOptions as WebAuthnBeginAuthenticationOptions,
  RegistrationResult as WebAuthnRegistrationResult,
  AuthenticationResult as WebAuthnAuthenticationResult,
  BrowserCapabilities as WebAuthnBrowserCapabilities,
  WebAuthnError,
  WebAuthnErrorType,
} from './webauthn/types';

// Secure Remote Password (SRP) Exports

export { SRPClient } from './srp/client';
export { getGroup, computeK, bigIntToBytes, bytesToBigInt, padBytes } from './srp/groups';
export type {
  SRPConfig,
  SRPGroup,
  RegistrationRequest as SRPRegistrationRequest,
  RegistrationResponse as SRPRegistrationResponse,
  AuthenticationBeginRequest as SRPAuthenticationBeginRequest,
  AuthenticationBeginResponse as SRPAuthenticationBeginResponse,
  AuthenticationFinishRequest as SRPAuthenticationFinishRequest,
  AuthenticationFinishResponse as SRPAuthenticationFinishResponse,
  RegistrationResult as SRPRegistrationResult,
  AuthenticationResult as SRPAuthenticationResult,
} from './srp/types';
