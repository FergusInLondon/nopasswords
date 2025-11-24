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
  /** Path to the attestation endpoint */
  attestationPath: string;
  /** Path to initiate assertion. */
  assertionInitiationPath: string;
  /** Path to complete assertion. */
  assertionCompletionPath: string;
}

/**
 * Attestation request sent to the server.
 */
export interface AttestationRequest {
  identifier: string;
  salt: string;  // Base64-encoded
  verifier: string;  // Base64-encoded
  group: number;
}

/**
 * Attestation response from the server.
 */
export interface AttestationResponse {
  success: boolean;
  identifier?: string;
  error?: string;
}

/**
 * Assertion begin request sent to the server.
 */
export interface AssertionBeginRequest { // TODO: These need renaming...!
  identifier: string;
  group?: number;
}

/**
 * Assertion begin response from the server.
 */
export interface AssertionBeginResponse {
  salt: string;  // Base64-encoded
  b: string;  // Base64-encoded (server's public ephemeral value B)
  group: number;
}

/**
 * Assertion finish request sent to the server.
 */
export interface AssertionFinishRequest {
  identifier: string;
  a: string;  // Base64-encoded (client's public ephemeral value A)
  m1: string;  // Base64-encoded (client's proof)
}

/**
 * Assertion finish response from the server.
 */
export interface AssertionFinishResponse {
  success: boolean;
  m2?: string;  // Base64-encoded (server's proof)
  error?: string;
}

/**
 * Result of a attesation operation.
 */
export interface AttestationResult {
  success: boolean;
  identifier?: string;
  error?: string;
}

/**
 * Result of an assertion operation.
 */
export interface AssertionResult {
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
