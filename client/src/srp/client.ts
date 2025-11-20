/**
 * SRP (Secure Remote Password) Client Library
 *
 * This implementation uses WebCrypto API for cryptographic operations and matches
 * the server-side Go implementation for compatibility.
 *
 * @mitigation Information Disclosure: Passwords are never transmitted to the server.
 * @mitigation Tampering: Cryptographic proofs ensure both parties have the correct password.
 */

import {
  SRPConfig,
  RegistrationRequest,
  RegistrationResponse,
  AuthenticationBeginRequest,
  AuthenticationBeginResponse,
  AuthenticationFinishRequest,
  AuthenticationFinishResponse,
  RegistrationResult,
  AuthenticationResult,
} from './types';
import { getGroup, computeK, bigIntToBytes, bytesToBigInt, padBytes } from './groups';

/**
 * SRP Client for registration and authentication.
 *
 * Example usage:
 * ```typescript
 * const client = new SRPClient({
 *   group: 3,
 *   baseURL: 'https://api.example.com'
 * });
 *
 * // Registration
 * const regResult = await client.register('user@example.com', 'password123');
 *
 * // Authentication
 * const authResult = await client.authenticate('user@example.com', 'password123');
 * ```
 */
export class SRPClient {
  private config: SRPConfig;

  constructor(config: SRPConfig) {
    this.config = config;
  }

  /**
   * Register a new user with SRP.
   *
   * This computes the verifier client-side and sends it to the server along with the salt.
   * The server stores the verifier but never sees the password.
   *
   * @param identifier - User identifier (e.g., email)
   * @param password - User's password
   * @returns Registration result
   *
   * @mitigation Information Disclosure: Password never leaves the client.
   * @mitigation Spoofing: Verifier cannot be used to recover the password.
   */
  async register(identifier: string, password: string): Promise<RegistrationResult> {
    try {
      // Get group parameters
      const group = getGroup(this.config.group);

      // Generate random salt (32 bytes = 256 bits)
      const salt = new Uint8Array(32);
      crypto.getRandomValues(salt);

      // Compute x = H(salt | H(identifier | ":" | password))
      const x = await this.computeX(identifier, password, salt);

      // Compute verifier v = g^x mod N
      const v = this.modPow(group.g, x, group.N);

      // Prepare registration request
      const request: RegistrationRequest = {
        identifier: identifier,
        salt: this.bytesToBase64(salt),
        verifier: this.bytesToBase64(bigIntToBytes(v)),
        group: this.config.group,
      };

      // Send registration request to server
      const response = await this.post<RegistrationResponse>(this.config.registrationPath, request);

      return {
        success: response.success,
        identifier: response.identifier,
        error: response.error,
      };
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error',
      };
    }
  }

  /**
   * Authenticate a user with SRP.
   *
   * This performs the SRP authentication protocol:
   * 1. Request salt and server's public ephemeral value (B)
   * 2. Compute client's public ephemeral value (A) and proof (M1)
   * 3. Send A and M1 to server
   * 4. Verify server's proof (M2)
   * 5. Derive session key (K)
   *
   * @param identifier - User identifier
   * @param password - User's password
   * @returns Authentication result with session key
   *
   * @mitigation Tampering: Protocol ensures both parties have the correct password.
   * @mitigation Information Disclosure: Session key is derived, not transmitted.
   */
  async authenticate(identifier: string, password: string): Promise<AuthenticationResult> {
    try {
      // Step 1: Begin authentication - get salt and B from server
      const beginRequest: AuthenticationBeginRequest = {
        identifier: identifier,
        group: this.config.group,
      };

      const beginResponse = await this.post<AuthenticationBeginResponse>(
        this.config.initiateAuthPath, beginRequest
      );

      const salt = this.base64ToBytes(beginResponse.salt);
      const B = bytesToBigInt(this.base64ToBytes(beginResponse.b));

      // Get group parameters
      const group = getGroup(beginResponse.group);

      // Compute x = H(salt | H(identifier | ":" | password))
      const x = await this.computeX(identifier, password, salt);

      // Generate client's private ephemeral value a (256 bits)
      // @mitigation Elevation of Privilege: Cryptographically random a prevents prediction
      const aBytes = new Uint8Array(32);
      crypto.getRandomValues(aBytes);
      const a = bytesToBigInt(aBytes);

      // Compute A = g^a mod N
      const A = this.modPow(group.g, a, group.N);

      // Compute u = H(A | B)
      const u = await this.computeU(A, B, group);

      // Compute k = H(N | g)
      const k = await computeK(group);

      // Compute S = (B - kg^x)^(a + ux) mod N
      const gx = this.modPow(group.g, x, group.N);
      const kgx = (k * gx) % group.N;
      let diff = (B - kgx) % group.N;
      if (diff < 0n) {
        diff += group.N;
      }

      const ux = u * x;
      const aux = a + ux;
      const S = this.modPow(diff, aux, group.N);

      // Compute session key K = H(S)
      const K = await this.hashSHA256(bigIntToBytes(S));

      // Compute M1 = H(A | B | K)
      const M1 = await this.computeM1(A, B, K);

      // Step 2: Send A and M1 to server
      const finishRequest: AuthenticationFinishRequest = {
        identifier: identifier,
        a: this.bytesToBase64(bigIntToBytes(A)),
        m1: this.bytesToBase64(M1),
      };

      const finishResponse = await this.post<AuthenticationFinishResponse>(
        this.config.completeAuthPath, finishRequest
      );

      if (!finishResponse.success) {
        return {
          success: false,
          error: finishResponse.error || 'Authentication failed',
        };
      }

      // Step 3: Verify server's proof M2
      if (finishResponse.m2) {
        const expectedM2 = await this.computeM2(A, M1, K);
        const serverM2 = this.base64ToBytes(finishResponse.m2);

        // @mitigation Tampering: Verify server's proof to prevent man-in-the-middle
        if (!this.constantTimeCompare(expectedM2, serverM2)) {
          return {
            success: false,
            error: 'Server proof verification failed',
          };
        }
      }

      return {
        success: true,
        sessionKey: K,
      };
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error',
      };
    }
  }

  /**
   * Compute x = H(salt | H(identifier | ":" | password))
   *
   * This is the private key derivation from the password.
   */
  private async computeX(identifier: string, password: string, salt: Uint8Array): Promise<bigint> {
    // Inner hash: H(identifier | ":" | password)
    const innerText = identifier + ':' + password;
    const innerBytes = new TextEncoder().encode(innerText);
    const innerHash = await this.hashSHA256(innerBytes);

    // Outer hash: H(salt | innerHash)
    const combined = new Uint8Array(salt.length + innerHash.length);
    combined.set(salt, 0);
    combined.set(innerHash, salt.length);
    const xHash = await this.hashSHA256(combined);

    return bytesToBigInt(xHash);
  }

  /**
   * Compute u = H(A | B)
   */
  private async computeU(A: bigint, B: bigint, group: { N: bigint }): Promise<bigint> {
    const NBytes = bigIntToBytes(group.N);
    const ABytes = padBytes(bigIntToBytes(A), NBytes.length);
    const BBytes = padBytes(bigIntToBytes(B), NBytes.length);

    const combined = new Uint8Array(ABytes.length + BBytes.length);
    combined.set(ABytes, 0);
    combined.set(BBytes, ABytes.length);

    const hash = await this.hashSHA256(combined);
    return bytesToBigInt(hash);
  }

  /**
   * Compute M1 = H(A | B | K)
   * Client's proof of session key possession.
   */
  private async computeM1(A: bigint, B: bigint, K: Uint8Array): Promise<Uint8Array> {
    const ABytes = bigIntToBytes(A);
    const BBytes = bigIntToBytes(B);

    const combined = new Uint8Array(ABytes.length + BBytes.length + K.length);
    combined.set(ABytes, 0);
    combined.set(BBytes, ABytes.length);
    combined.set(K, ABytes.length + BBytes.length);

    return this.hashSHA256(combined);
  }

  /**
   * Compute M2 = H(A | M1 | K)
   * Server's proof of session key possession.
   */
  private async computeM2(A: bigint, M1: Uint8Array, K: Uint8Array): Promise<Uint8Array> {
    const ABytes = bigIntToBytes(A);

    const combined = new Uint8Array(ABytes.length + M1.length + K.length);
    combined.set(ABytes, 0);
    combined.set(M1, ABytes.length);
    combined.set(K, ABytes.length + M1.length);

    return this.hashSHA256(combined);
  }

  /**
   * SHA-256 hash function using WebCrypto.
   */
  private async hashSHA256(data: Uint8Array): Promise<Uint8Array> {
    // Yes, it accepts `new T(instance of T)` but doesn't accept `T`.
    // Make it make sense, Typescript!
    // TODO: Actually fix that abomination.
    const hashBuffer = await crypto.subtle.digest('SHA-256', new Uint8Array(data));
    return new Uint8Array(hashBuffer);
  }

  /**
   * Modular exponentiation: base^exp mod modulus
   *
   * Uses JavaScript's native BigInt which handles large numbers efficiently.
   */
  private modPow(base: bigint, exp: bigint, modulus: bigint): bigint {
    let result = 1n;
    base = base % modulus;

    while (exp > 0n) {
      if (exp % 2n === 1n) {
        result = (result * base) % modulus;
      }
      exp = exp / 2n;
      base = (base * base) % modulus;
    }

    return result;
  }

  /**
   * Constant-time comparison to prevent timing attacks.
   *
   * @mitigation Information Disclosure: Prevents timing attacks that could leak password info.
   */
  private constantTimeCompare(a: Uint8Array, b: Uint8Array): boolean {
    if (a.length !== b.length) {
      return false;
    }

    let diff = 0;
    for (let i = 0; i < a.length; i++) {
      diff |= a[i] ^ b[i];
    }

    return diff === 0;
  }

  /**
   * Convert bytes to Base64 (URL-safe).
   */
  private bytesToBase64(bytes: Uint8Array): string {
    return btoa(String.fromCharCode(...bytes));
  }

  /**
   * Convert Base64 (URL-safe) to bytes.
   */
  private base64ToBytes(base64: string): Uint8Array {
    // Add padding if needed
    const padded = base64 + '===='.slice(0, (4 - (base64.length % 4)) % 4);
    const binary = atob(padded);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  }

  /**
   * HTTP POST helper.
   */
  private async post<T>(endpoint: string, body: any): Promise<T> {
    const url = this.config.baseURL + endpoint;
    const response = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(body),
    });

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}: ${response.statusText}`);
    }

    return response.json();
  }
}
