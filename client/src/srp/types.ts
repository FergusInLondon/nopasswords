/**
 * SRP client library types.
 * These types match the server-side Go implementation for compatibility.
 */

/**
 * Configuration for the SRP client.
 * Must match server configuration.
 */
export interface SRPConfig {
  /** RFC5054 group ID (3, 4, or 5) */
  group: 3 | 4 | 5;
  /** Base URL for API endpoints */
  baseURL: string;
  /** Path to the Registration Endpoint */
  registrationPath: string;
  /** Path to initiate authentication. */
  initiateAuthPath: string;
  /** Path to complete authentication. */
  completeAuthPath: string;
}

/**
 * Registration request sent to the server.
 */
export interface RegistrationRequest {
  identifier: string;
  salt: string;  // Base64-encoded
  verifier: string;  // Base64-encoded
  group: number;
}

/**
 * Registration response from the server.
 */
export interface RegistrationResponse {
  success: boolean;
  identifier?: string;
  error?: string;
}

/**
 * Authentication begin request sent to the server.
 */
export interface AuthenticationBeginRequest {
  identifier: string;
  group?: number;
}

/**
 * Authentication begin response from the server.
 */
export interface AuthenticationBeginResponse {
  salt: string;  // Base64-encoded
  b: string;  // Base64-encoded (server's public ephemeral value B)
  group: number;
}

/**
 * Authentication finish request sent to the server.
 */
export interface AuthenticationFinishRequest {
  identifier: string;
  a: string;  // Base64-encoded (client's public ephemeral value A)
  m1: string;  // Base64-encoded (client's proof)
}

/**
 * Authentication finish response from the server.
 */
export interface AuthenticationFinishResponse {
  success: boolean;
  m2?: string;  // Base64-encoded (server's proof)
  error?: string;
}

/**
 * Result of a registration operation.
 */
export interface RegistrationResult {
  success: boolean;
  identifier?: string;
  error?: string;
}

/**
 * Result of an authentication operation.
 */
export interface AuthenticationResult {
  success: boolean;
  sessionKey?: Uint8Array;  // Shared session key (K)
  error?: string;
}

/**
 * SRP group parameters from RFC5054.
 */
export interface SRPGroup {
  /** Large safe prime N */
  N: bigint;
  /** Generator g */
  g: bigint;
  /** Bit length */
  bitLength: number;
}
