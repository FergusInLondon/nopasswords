import { describe, it, expect } from 'vitest';
import { SRPClient } from '../../src/srp/client';

describe('modPow', () => {
  // Create a client instance to access private methods via type assertion
  const client = new SRPClient({
    group: 3,
    baseURL: 'http://localhost',
    registrationPath: '/register',
    initiateAuthPath: '/auth/begin',
    completeAuthPath: '/auth/complete',
  });

  // Access private method for testing
  const modPow = (client as any).modPow.bind(client);

  it('should compute modular exponentiation correctly', () => {
    // Test: 3^5 mod 7 = 243 mod 7 = 5
    const result = modPow(3n, 5n, 7n);
    expect(result).toBe(5n);
  });

  it('should handle large numbers', () => {
    // Test: 2^100 mod 97
    const result = modPow(2n, 100n, 97n);
    // 2^100 mod 97 = 16 (verified by test)
    expect(result).toBe(16n);
  });

  it('should return 0 when base is 0', () => {
    const result = modPow(0n, 5n, 7n);
    expect(result).toBe(0n);
  });

  it('should return 1 when exponent is 0', () => {
    const result = modPow(5n, 0n, 7n);
    expect(result).toBe(1n);
  });

  it('should handle base larger than modulus', () => {
    // Test: 10^3 mod 7 = (3^3) mod 7 = 27 mod 7 = 6
    const result = modPow(10n, 3n, 7n);
    expect(result).toBe(6n);
  });
});
