import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawn, ChildProcess } from 'child_process';
import { SRPClient } from '../../src/srp/client';

/**
 * End-to-End Cross-Implementation Tests
 *
 * These tests verify that the TypeScript client correctly interacts with the Go server.
 * The Go server is started before tests and stopped after.
 */
describe('SRP Cross-Implementation E2E', () => {
  let serverProcess: ChildProcess;
  let client: SRPClient;

  const SERVER_PORT = 8081;
  const BASE_URL = `http://localhost:${SERVER_PORT}`;
  const SERVER_STARTUP_DELAY = 2000; // 2 seconds for server to start

  beforeAll(async () => {
    // Kill any existing process on port 8081
    try {
      const killProcess = spawn('bash', ['-c', 'lsof -ti:8081 | xargs kill -9 2>/dev/null || true']);
      await new Promise<void>((resolve) => {
        killProcess.on('close', () => {
          setTimeout(() => resolve(), 1500); // Wait for port to be freed
        });
        // Timeout fallback
        setTimeout(() => resolve(), 2000);
      });
    } catch (error) {
      // Ignore errors - process might not exist
    }

    // Build and start the Go server
    return new Promise<void>((resolve, reject) => {
      // Start the server from the project root
      serverProcess = spawn('go', ['run', './cmd/examples/srp-demo/main.go'], {
        cwd: '..',
        stdio: 'pipe',
      });

      let serverOutput = '';

      serverProcess.stdout?.on('data', (data) => {
        const output = data.toString();
        serverOutput += output;

        // Server is ready when we see "Server running on"
        if (output.includes('Server running on')) {
          console.log('Go SRP server started successfully');
          // Give it a moment to fully initialize
          setTimeout(() => resolve(), 500);
        }
      });

      serverProcess.stderr?.on('data', (data) => {
        console.error('Server error:', data.toString());
      });

      serverProcess.on('error', (error) => {
        reject(new Error(`Failed to start server: ${error.message}`));
      });

      serverProcess.on('exit', (code) => {
        if (code !== 0 && code !== null) {
          reject(new Error(`Server exited with code ${code}\n${serverOutput}`));
        }
      });

      // Timeout after 10 seconds if server doesn't start
      setTimeout(() => {
        if (serverProcess.pid) {
          reject(new Error(`Server failed to start within 10 seconds\n${serverOutput}`));
        }
      }, 10000);
    });
  }, 15000); // 15 second timeout for server startup

  afterAll(async () => {
    // Stop the server
    if (serverProcess && serverProcess.pid) {
      try {
        serverProcess.kill('SIGTERM'); // TODO: This doesn't happen. Dodgy error handling?
        console.log('Go SRP server stopped');
      } catch (error) {
        // Process might already be dead
      }
    }

    // Wait a moment for cleanup
    await new Promise<void>((resolve) => setTimeout(() => resolve(), 1000));
  });

  it('should successfully register and authenticate a user', async () => {
    client = new SRPClient({
      group: 3,
      baseURL: BASE_URL,
      attestationPath: '/api/srp/register',
      assertionInitiationPath: '/api/srp/authenticate/begin',
      assertionCompletionPath: '/api/srp/authenticate/finish',
    });

    const identifier = `testuser-${Date.now()}@example.com`;
    const password = 'SecurePassword123!';

    // Step 1: Register the user
    const registerResult = await client.attest(identifier, password);

    expect(registerResult.success).toBe(true);
    expect(registerResult.identifier).toBe(identifier);
    expect(registerResult.error).toBeUndefined();

    // Step 2: Authenticate with the same credentials
    const authResult = await client.assert(identifier, password);

    expect(authResult.success).toBe(true);
    expect(authResult.sessionKey).toBeInstanceOf(Uint8Array);
    expect(authResult.sessionKey?.length).toBe(32);
    expect(authResult.error).toBeUndefined();
  }, 10000);

  it('should fail authentication with wrong password', async () => {
    client = new SRPClient({
      group: 3,
      baseURL: BASE_URL,
      attestationPath: '/api/srp/register',
      assertionInitiationPath: '/api/srp/authenticate/begin',
      assertionCompletionPath: '/api/srp/authenticate/finish',
    });

    const identifier = `testuser2-${Date.now()}@example.com`;
    const password = 'CorrectPassword123!';
    const wrongPassword = 'WrongPassword123!';

    // Register with correct password
    const registerResult = await client.attest(identifier, password);
    expect(registerResult.success).toBe(true);

    // Attempt authentication with wrong password
    const authResult = await client.assert(identifier, wrongPassword);

    expect(authResult.success).toBe(false);
    expect(authResult.error).toBeDefined();
  }, 10000);

  it('should fail authentication for non-existent user', async () => {
    client = new SRPClient({
      group: 3,
      baseURL: BASE_URL,
      attestationPath: '/api/srp/register',
      assertionInitiationPath: '/api/srp/authenticate/begin',
      assertionCompletionPath: '/api/srp/authenticate/finish',
    });

    const identifier = `nonexistent-${Date.now()}@example.com`;
    const password = 'SomePassword123!';

    // Attempt authentication without registration
    const authResult = await client.assert(identifier, password);

    expect(authResult.success).toBe(false);
    expect(authResult.error).toBeDefined();
  }, 10000);

  it('should handle multiple sequential authentications', async () => {
    client = new SRPClient({
      group: 3,
      baseURL: BASE_URL,
      attestationPath: '/api/srp/register',
      assertionInitiationPath: '/api/srp/authenticate/begin',
      assertionCompletionPath: '/api/srp/authenticate/finish',
    });

    const identifier = `testuser3-${Date.now()}@example.com`;
    const password = 'Password123!';

    // Register
    const registerResult = await client.attest(identifier, password);
    expect(registerResult.success).toBe(true);

    // Authenticate multiple times
    for (let i = 0; i < 3; i++) {
      const authResult = await client.assert(identifier, password);
      expect(authResult.success).toBe(true);
      expect(authResult.sessionKey).toBeInstanceOf(Uint8Array);
    }
  }, 15000);
});
