/**
 * Types for NoPasswords WebAuthn Client Library
 */

/**
 * Configuration options for the WebAuthn client
 */
export interface WebAuthnConfig {
  /**
   * Base URL for the WebAuthn API endpoints
   * @example "https://example.com/api/webauthn"
   */
  apiBaseURL: string;

  /**
   * Optional custom fetch function for making HTTP requests
   * Useful for adding authentication headers or custom error handling
   */
  fetchFn?: typeof fetch;

  /**
   * Timeout for WebAuthn operations in milliseconds
   * @default 60000 (60 seconds)
   */
  timeout?: number;
}

/**
 * Options for beginning registration
 */
export interface BeginRegistrationOptions {
  /** User identifier */
  userID: string;
  /** Username */
  userName: string;
  /** Display name for the user */
  userDisplayName: string;
}

/**
 * Options for beginning authentication
 */
export interface BeginAuthenticationOptions {
  /** Optional user identifier (empty for discoverable credentials) */
  userID?: string;
}

/**
 * Result of a successful registration
 */
export interface RegistrationResult {
  /** Indicates if registration was successful */
  success: boolean;
  /** Optional error message */
  error?: string;
}

/**
 * Result of a successful authentication
 */
export interface AuthenticationResult {
  /** Indicates if authentication was successful */
  success: boolean;
  /** User identifier (if authentication succeeded) */
  userID?: string;
  /** Optional error message */
  error?: string;
}

/**
 * Browser capability information
 */
export interface BrowserCapabilities {
  /** Whether WebAuthn is supported */
  webauthn: boolean;
  /** Whether platform authenticator is available (Touch ID, Windows Hello) */
  platformAuthenticator: boolean | null;
  /** Browser name */
  browserName: string;
}

/**
 * Error types for WebAuthn operations
 */
export enum WebAuthnErrorType {
  NOT_SUPPORTED = 'NOT_SUPPORTED',
  NOT_ALLOWED = 'NOT_ALLOWED',
  TIMEOUT = 'TIMEOUT',
  NETWORK = 'NETWORK',
  INVALID_STATE = 'INVALID_STATE',
  UNKNOWN = 'UNKNOWN',
}

/**
 * Custom error class for WebAuthn operations
 */
export class WebAuthnError extends Error {
  constructor(
    public type: WebAuthnErrorType,
    message: string,
    public originalError?: Error
  ) {
    super(message);
    this.name = 'WebAuthnError';
  }
}
