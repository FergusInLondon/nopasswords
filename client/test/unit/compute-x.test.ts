import { describe, it, expect } from 'vitest';
import { SRPClient } from '../../src/srp/client';

describe('computeX', () => {
  const client = new SRPClient({
    group: 3,
    baseURL: 'http://localhost',
    registrationPath: '/register',
    initiateAuthPath: '/auth/begin',
    completeAuthPath: '/auth/complete',
  });

  const computeX = (client as any).computeX.bind(client);

  it('should compute x correctly with known inputs', async () => {
    const identifier = 'user@example.com';
    const password = 'password123';
    const salt = new Uint8Array(32).fill(0x42); // Deterministic salt

    const x = await computeX(identifier, password, salt);

    // x should be a bigint
    expect(typeof x).toBe('bigint');
    expect(x).toBeGreaterThan(0n);
  });

  it('should produce different x for different passwords', async () => {
    const identifier = 'user@example.com';
    const salt = new Uint8Array(32).fill(0x42);

    const x1 = await computeX(identifier, 'password1', salt);
    const x2 = await computeX(identifier, 'password2', salt);

    expect(x1).not.toEqual(x2);
  });

  it('should produce different x for different salts', async () => {
    const identifier = 'user@example.com';
    const password = 'password123';
    const salt1 = new Uint8Array(32).fill(0x42);
    const salt2 = new Uint8Array(32).fill(0x43);

    const x1 = await computeX(identifier, password, salt1);
    const x2 = await computeX(identifier, password, salt2);

    expect(x1).not.toEqual(x2);
  });

  it('should produce different x for different identifiers', async () => {
    const password = 'password123';
    const salt = new Uint8Array(32).fill(0x42);

    const x1 = await computeX('user1@example.com', password, salt);
    const x2 = await computeX('user2@example.com', password, salt);

    expect(x1).not.toEqual(x2);
  });

  it('should be deterministic', async () => {
    const identifier = 'user@example.com';
    const password = 'password123';
    const salt = new Uint8Array(32).fill(0x42);

    const x1 = await computeX(identifier, password, salt);
    const x2 = await computeX(identifier, password, salt);

    expect(x1).toEqual(x2);
  });
});
