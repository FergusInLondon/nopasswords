import { describe, it, expect } from 'vitest';
import { SRPClient } from '../../src/srp/client';

describe('constantTimeCompare', () => {
  const client = new SRPClient({
    group: 3,
    baseURL: 'http://localhost',
    registrationPath: '/register',
    initiateAuthPath: '/auth/begin',
    completeAuthPath: '/auth/complete',
  });

  const constantTimeCompare = (client as any).constantTimeCompare.bind(client);

  it('should return true for identical arrays', () => {
    const a = new Uint8Array([1, 2, 3, 4, 5]);
    const b = new Uint8Array([1, 2, 3, 4, 5]);
    expect(constantTimeCompare(a, b)).toBe(true);
  });

  it('should return false for different arrays with same length', () => {
    const a = new Uint8Array([1, 2, 3, 4, 5]);
    const b = new Uint8Array([1, 2, 3, 4, 6]);
    expect(constantTimeCompare(a, b)).toBe(false);
  });

  it('should return false for arrays with different lengths', () => {
    const a = new Uint8Array([1, 2, 3]);
    const b = new Uint8Array([1, 2, 3, 4]);
    expect(constantTimeCompare(a, b)).toBe(false);
  });

  it('should return true for empty arrays', () => {
    const a = new Uint8Array([]);
    const b = new Uint8Array([]);
    expect(constantTimeCompare(a, b)).toBe(true);
  });

  it('should return false when only one byte differs', () => {
    const a = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);
    const b = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 9]);
    expect(constantTimeCompare(a, b)).toBe(false);
  });
});
