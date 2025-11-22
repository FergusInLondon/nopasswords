import { describe, it, expect } from 'vitest';
import { SRPClient } from '../../src/srp/client';
import { getGroup } from '../../src/srp/groups';

describe('computeU', () => {
  const client = new SRPClient({
    group: 3,
    baseURL: 'http://localhost',
    registrationPath: '/register',
    initiateAuthPath: '/auth/begin',
    completeAuthPath: '/auth/complete',
  });

  const computeU = (client as any).computeU.bind(client);
  const group = getGroup(3);

  it('should compute u correctly', async () => {
    const A = 12345n;
    const B = 67890n;

    const u = await computeU(A, B, group);

    // u should be a bigint
    expect(typeof u).toBe('bigint');
    expect(u).toBeGreaterThan(0n);
  });

  it('should produce different u for different A values', async () => {
    const A1 = 12345n;
    const A2 = 54321n;
    const B = 67890n;

    const u1 = await computeU(A1, B, group);
    const u2 = await computeU(A2, B, group);

    expect(u1).not.toEqual(u2);
  });

  it('should produce different u for different B values', async () => {
    const A = 12345n;
    const B1 = 67890n;
    const B2 = 98765n;

    const u1 = await computeU(A, B1, group);
    const u2 = await computeU(A, B2, group);

    expect(u1).not.toEqual(u2);
  });

  it('should be deterministic', async () => {
    const A = 12345n;
    const B = 67890n;

    const u1 = await computeU(A, B, group);
    const u2 = await computeU(A, B, group);

    expect(u1).toEqual(u2);
  });

  it('should handle large values', async () => {
    // Use values close to N
    const A = group.N - 1000n;
    const B = group.N - 2000n;

    const u = await computeU(A, B, group);

    expect(typeof u).toBe('bigint');
    expect(u).toBeGreaterThan(0n);
  });
});
