/**
 * NoPasswords WebAuthn Client Library
 *
 * A TypeScript library for WebAuthn/FIDO2 passwordless authentication
 *
 * @packageDocumentation
 */

export { WebAuthnClient } from './client';
export {
  WebAuthnConfig,
  BeginRegistrationOptions,
  BeginAuthenticationOptions,
  RegistrationResult,
  AuthenticationResult,
  BrowserCapabilities,
  WebAuthnError,
  WebAuthnErrorType,
} from './types';
