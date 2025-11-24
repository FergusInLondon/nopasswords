import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { SRPClient } from '../../src/srp/client';

describe('SRPClient - Registration Integration', () => {
  let client: SRPClient;
  let fetchMock: any;

  beforeEach(() => {
    client = new SRPClient({
      group: 3,
      baseURL: 'http://localhost:8080',
      attestationPath: '/register',
      assertionInitiationPath: '/auth/begin',
      assertionCompletionPath: '/auth/complete',
    });

    // Mock global fetch
    fetchMock = vi.fn();
    global.fetch = fetchMock;
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('should successfully register a user', async () => {
    // Mock successful registration response
    fetchMock.mockResolvedValueOnce({
      ok: true,
      json: async () => ({
        success: true,
        identifier: 'user@example.com',
      }),
    });

    const result = await client.attest('user@example.com', 'password123');

    expect(result.success).toBe(true);
    expect(result.identifier).toBe('user@example.com');
    expect(result.error).toBeUndefined();

    // Verify fetch was called correctly
    expect(fetchMock).toHaveBeenCalledOnce();
    const [url, options] = fetchMock.mock.calls[0];
    expect(url).toBe('http://localhost:8080/register');
    expect(options.method).toBe('POST');
    expect(options.headers['Content-Type']).toBe('application/json');

    // Verify request body
    const body = JSON.parse(options.body);
    expect(body.identifier).toBe('user@example.com');
    expect(body.group).toBe(3);
    expect(body.salt).toBeDefined();
    expect(body.verifier).toBeDefined();
  });

  it('should handle registration failure from server', async () => {
    // Mock failed registration response
    fetchMock.mockResolvedValueOnce({
      ok: true,
      json: async () => ({
        success: false,
        identifier: 'user already exists',
        error: 'User already registered',
      }),
    });

    const result = await client.attest('existing@example.com', 'password123');

    expect(result.success).toBe(false);
    expect(result.error).toBe('User already registered');
  });

  it('should handle HTTP error responses', async () => {
    // Mock HTTP error
    fetchMock.mockResolvedValueOnce({
      ok: false,
      status: 500,
      statusText: 'Internal Server Error',
    });

    const result = await client.attest('user@example.com', 'password123');

    expect(result.success).toBe(false);
    expect(result.error).toContain('HTTP 500');
  });

  it('should handle network errors', async () => {
    // Mock network failure
    fetchMock.mockRejectedValueOnce(new Error('Network error'));

    const result = await client.attest('user@example.com', 'password123');

    expect(result.success).toBe(false);
    expect(result.error).toBe('Network error');
  });

  it('should generate different salts for different registrations', async () => {
    fetchMock.mockResolvedValue({
      ok: true,
      json: async () => ({ success: true, identifier: 'user@example.com' }),
    });

    await client.attest('user@example.com', 'password123');
    await client.attest('user@example.com', 'password123');

    // Get the salts from both calls
    const salt1 = JSON.parse(fetchMock.mock.calls[0][1].body).salt;
    const salt2 = JSON.parse(fetchMock.mock.calls[1][1].body).salt;

    // Salts should be different (random)
    expect(salt1).not.toEqual(salt2);
  });

  it('should generate different verifiers for different passwords', async () => {
    fetchMock.mockResolvedValue({
      ok: true,
      json: async () => ({ success: true, identifier: 'user@example.com' }),
    });

    await client.attest('user@example.com', 'password1');
    await client.attest('user@example.com', 'password2');

    // Get the verifiers from both calls
    const verifier1 = JSON.parse(fetchMock.mock.calls[0][1].body).verifier;
    const verifier2 = JSON.parse(fetchMock.mock.calls[1][1].body).verifier;

    // Verifiers should be different
    expect(verifier1).not.toEqual(verifier2);
  });
});
