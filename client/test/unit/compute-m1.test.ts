import { describe, it, expect } from 'vitest';
import { SRPClient } from '../../src/srp/client';

describe('computeM1', () => {
  const client = new SRPClient({
    group: 3,
    baseURL: 'http://localhost',
    registrationPath: '/register',
    initiateAuthPath: '/auth/begin',
    completeAuthPath: '/auth/complete',
  });

  const computeM1 = (client as any).computeM1.bind(client);

  it('should compute M1 correctly', async () => {
    const A = 12345n;
    const B = 67890n;
    const K = new Uint8Array(32).fill(0x42);

    const M1 = await computeM1(A, B, K);

    // M1 should be 32 bytes (SHA-256 output)
    expect(M1).toBeInstanceOf(Uint8Array);
    expect(M1.length).toBe(32);
  });

  it('should produce different M1 for different A values', async () => {
    const A1 = 12345n;
    const A2 = 54321n;
    const B = 67890n;
    const K = new Uint8Array(32).fill(0x42);

    const M1_1 = await computeM1(A1, B, K);
    const M1_2 = await computeM1(A2, B, K);

    expect(M1_1).not.toEqual(M1_2);
  });

  it('should produce different M1 for different B values', async () => {
    const A = 12345n;
    const B1 = 67890n;
    const B2 = 98765n;
    const K = new Uint8Array(32).fill(0x42);

    const M1_1 = await computeM1(A, B1, K);
    const M1_2 = await computeM1(A, B2, K);

    expect(M1_1).not.toEqual(M1_2);
  });

  it('should produce different M1 for different K values', async () => {
    const A = 12345n;
    const B = 67890n;
    const K1 = new Uint8Array(32).fill(0x42);
    const K2 = new Uint8Array(32).fill(0x43);

    const M1_1 = await computeM1(A, B, K1);
    const M1_2 = await computeM1(A, B, K2);

    expect(M1_1).not.toEqual(M1_2);
  });

  it('should be deterministic', async () => {
    const A = 12345n;
    const B = 67890n;
    const K = new Uint8Array(32).fill(0x42);

    const M1_1 = await computeM1(A, B, K);
    const M1_2 = await computeM1(A, B, K);

    expect(M1_1).toEqual(M1_2);
  });
});
