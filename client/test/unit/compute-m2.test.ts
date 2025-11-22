import { describe, it, expect } from 'vitest';
import { SRPClient } from '../../src/srp/client';

describe('computeM2', () => {
  const client = new SRPClient({
    group: 3,
    baseURL: 'http://localhost',
    registrationPath: '/register',
    initiateAuthPath: '/auth/begin',
    completeAuthPath: '/auth/complete',
  });

  const computeM2 = (client as any).computeM2.bind(client);

  it('should compute M2 correctly', async () => {
    const A = 12345n;
    const M1 = new Uint8Array(32).fill(0x42);
    const K = new Uint8Array(32).fill(0x43);

    const M2 = await computeM2(A, M1, K);

    // M2 should be 32 bytes (SHA-256 output)
    expect(M2).toBeInstanceOf(Uint8Array);
    expect(M2.length).toBe(32);
  });

  it('should produce different M2 for different A values', async () => {
    const A1 = 12345n;
    const A2 = 54321n;
    const M1 = new Uint8Array(32).fill(0x42);
    const K = new Uint8Array(32).fill(0x43);

    const M2_1 = await computeM2(A1, M1, K);
    const M2_2 = await computeM2(A2, M1, K);

    expect(M2_1).not.toEqual(M2_2);
  });

  it('should produce different M2 for different M1 values', async () => {
    const A = 12345n;
    const M1_1 = new Uint8Array(32).fill(0x42);
    const M1_2 = new Uint8Array(32).fill(0x43);
    const K = new Uint8Array(32).fill(0x44);

    const M2_1 = await computeM2(A, M1_1, K);
    const M2_2 = await computeM2(A, M1_2, K);

    expect(M2_1).not.toEqual(M2_2);
  });

  it('should produce different M2 for different K values', async () => {
    const A = 12345n;
    const M1 = new Uint8Array(32).fill(0x42);
    const K1 = new Uint8Array(32).fill(0x43);
    const K2 = new Uint8Array(32).fill(0x44);

    const M2_1 = await computeM2(A, M1, K1);
    const M2_2 = await computeM2(A, M1, K2);

    expect(M2_1).not.toEqual(M2_2);
  });

  it('should be deterministic', async () => {
    const A = 12345n;
    const M1 = new Uint8Array(32).fill(0x42);
    const K = new Uint8Array(32).fill(0x43);

    const M2_1 = await computeM2(A, M1, K);
    const M2_2 = await computeM2(A, M1, K);

    expect(M2_1).toEqual(M2_2);
  });
});
