/**
 * NoPasswords SRP Client Library
 *
 * Secure Remote Password (SRP) protocol implementation for zero-knowledge password authentication.
 * Compatible with the NoPasswords Go server implementation.
 *
 * @packageDocumentation
 */

export { SRPClient } from './client';
export { getGroup, computeK, bigIntToBytes, bytesToBigInt, padBytes } from './groups';
export type {
  SRPConfig,
  SRPGroup,
  AttestationRequest,
  AttestationResponse,
  AssertionBeginRequest,
  AssertionBeginResponse,
  AssertionFinishRequest,
  AssertionFinishResponse,
  AttestationResult,
  AssertionResult,
} from './types';
