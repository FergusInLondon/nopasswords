import { describe, it, expect } from 'vitest';
import { SRPClient } from '../../src/srp/client';

describe('hashSHA256', () => {
  const client = new SRPClient({
    group: 3,
    baseURL: 'http://localhost',
    registrationPath: '/register',
    initiateAuthPath: '/auth/begin',
    completeAuthPath: '/auth/complete',
  });

  const hashSHA256 = (client as any).hashSHA256.bind(client);

  it('should compute SHA-256 hash correctly', async () => {
    // Test vector: "hello" -> SHA-256
    const input = new TextEncoder().encode('hello');
    const result = await hashSHA256(input);

    // Expected: 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
    const expected = new Uint8Array([
      0x2c, 0xf2, 0x4d, 0xba, 0x5f, 0xb0, 0xa3, 0x0e,
      0x26, 0xe8, 0x3b, 0x2a, 0xc5, 0xb9, 0xe2, 0x9e,
      0x1b, 0x16, 0x1e, 0x5c, 0x1f, 0xa7, 0x42, 0x5e,
      0x73, 0x04, 0x33, 0x62, 0x93, 0x8b, 0x98, 0x24,
    ]);

    expect(result).toEqual(expected);
  });

  it('should compute SHA-256 for empty input', async () => {
    // Test vector: "" -> SHA-256
    const input = new Uint8Array([]);
    const result = await hashSHA256(input);

    // Expected: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    const expected = new Uint8Array([
      0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
      0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
      0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
      0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
    ]);

    expect(result).toEqual(expected);
  });

  it('should return 32 bytes (256 bits)', async () => {
    const input = new TextEncoder().encode('test');
    const result = await hashSHA256(input);
    expect(result.length).toBe(32);
  });

  it('should produce different hashes for different inputs', async () => {
    const hash1 = await hashSHA256(new TextEncoder().encode('input1'));
    const hash2 = await hashSHA256(new TextEncoder().encode('input2'));
    expect(hash1).not.toEqual(hash2);
  });

  it('should be deterministic', async () => {
    const input = new TextEncoder().encode('deterministic');
    const hash1 = await hashSHA256(input);
    const hash2 = await hashSHA256(input);
    expect(hash1).toEqual(hash2);
  });
});
