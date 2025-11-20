/**
 * NoPasswords WebAuthn Client Library
 *
 * Provides a high-level API for WebAuthn registration and authentication.
 */

import {
  WebAuthnConfig,
  BeginRegistrationOptions,
  BeginAuthenticationOptions,
  RegistrationResult,
  AuthenticationResult,
  BrowserCapabilities,
  WebAuthnError,
  WebAuthnErrorType,
} from './types';

/**
 * WebAuthn Client for managing passwordless authentication
 *
 * @example
 * ```typescript
 * const client = new WebAuthnClient({
 *   apiBaseURL: 'https://example.com/api/webauthn'
 * });
 *
 * // Registration
 * const regResult = await client.register({
 *   userID: 'user-123',
 *   userName: 'alice',
 *   userDisplayName: 'Alice Smith'
 * });
 *
 * // Authentication
 * const authResult = await client.authenticate({
 *   userID: 'user-123'
 * });
 * ```
 */
export class WebAuthnClient {
  private config: Required<WebAuthnConfig>;

  constructor(config: WebAuthnConfig) {
    this.config = {
      apiBaseURL: config.apiBaseURL,
      fetchFn: config.fetchFn || fetch.bind(window),
      timeout: config.timeout || 60000,
    };
  }

  /**
   * Check browser capabilities for WebAuthn
   *
   * @risk Information Disclosure: Feature detection reveals browser capabilities
   * but does not leak sensitive user information
   */
  async checkCapabilities(): Promise<BrowserCapabilities> {
    const webauthnSupported = this.isWebAuthnSupported();

    let platformAuthenticator: boolean | null = null;
    if (webauthnSupported) {
      try {
        platformAuthenticator = await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
      } catch (err) {
        // Some browsers don't support this method
        platformAuthenticator = null;
      }
    }

    return {
      webauthn: webauthnSupported,
      platformAuthenticator,
      browserName: this.getBrowserName(),
    };
  }

  /**
   * Register a new WebAuthn credential
   *
   * @param options Registration options
   * @returns Registration result
   * @throws {WebAuthnError} If registration fails
   *
   * Security Considerations:
   * @risk Spoofing: Origin validation is performed by the browser and server
   * @risk Tampering: Attestation is verified server-side
   */
  async register(options: BeginRegistrationOptions): Promise<RegistrationResult> {
    // Check browser support
    if (!this.isWebAuthnSupported()) {
      throw new WebAuthnError(
        WebAuthnErrorType.NOT_SUPPORTED,
        'WebAuthn is not supported in this browser'
      );
    }

    try {
      // Step 1: Begin registration - get challenge from server
      const beginURL = `${this.config.apiBaseURL}/register/begin`;
      const beginResponse = await this.config.fetchFn(beginURL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(options),
      });

      if (!beginResponse.ok) {
        throw new Error(`Server returned ${beginResponse.status}: ${await beginResponse.text()}`);
      }

      const credentialCreationOptions = await beginResponse.json();

      // Step 2: Create credential using WebAuthn API
      const credential = await this.createCredential(credentialCreationOptions);

      // Step 3: Send credential to server for verification
      const finishURL = `${this.config.apiBaseURL}/register/finish`;
      const finishResponse = await this.config.fetchFn(finishURL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(credential),
      });

      if (!finishResponse.ok) {
        throw new Error(`Server returned ${finishResponse.status}: ${await finishResponse.text()}`);
      }

      return { success: true };
    } catch (err) {
      return this.handleError(err, 'Registration failed');
    }
  }

  /**
   * Authenticate using a WebAuthn credential
   *
   * @param options Authentication options
   * @returns Authentication result
   * @throws {WebAuthnError} If authentication fails
   *
   * Security Considerations:
   * @risk Elevation of Privilege: Challenge verification prevents replay attacks
   * @risk Information Disclosure: Timing attacks mitigated by constant-time server operations
   */
  async authenticate(options: BeginAuthenticationOptions = {}): Promise<AuthenticationResult> {
    // Check browser support
    if (!this.isWebAuthnSupported()) {
      throw new WebAuthnError(
        WebAuthnErrorType.NOT_SUPPORTED,
        'WebAuthn is not supported in this browser'
      );
    }

    try {
      // Step 1: Begin authentication - get challenge from server
      const beginURL = `${this.config.apiBaseURL}/authenticate/begin`;
      const beginResponse = await this.config.fetchFn(beginURL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(options),
      });

      if (!beginResponse.ok) {
        throw new Error(`Server returned ${beginResponse.status}: ${await beginResponse.text()}`);
      }

      const credentialRequestOptions = await beginResponse.json();

      // Step 2: Get credential using WebAuthn API
      const assertion = await this.getAssertion(credentialRequestOptions);

      // Step 3: Send assertion to server for verification
      const finishURL = `${this.config.apiBaseURL}/authenticate/finish`;
      const finishResponse = await this.config.fetchFn(finishURL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(assertion),
      });

      if (!finishResponse.ok) {
        throw new Error(`Server returned ${finishResponse.status}: ${await finishResponse.text()}`);
      }

      const result = await finishResponse.json();

      return {
        success: true,
        userID: result.userID,
      };
    } catch (err) {
      return this.handleError(err, 'Authentication failed');
    }
  }

  /**
   * Check if WebAuthn is supported in the current browser
   */
  isWebAuthnSupported(): boolean {
    return (
      typeof window !== 'undefined' &&
      typeof window.PublicKeyCredential !== 'undefined' &&
      typeof navigator.credentials !== 'undefined' &&
      typeof navigator.credentials.create === 'function' &&
      typeof navigator.credentials.get === 'function'
    );
  }

  /**
   * Create a WebAuthn credential (registration)
   * @internal
   */
  private async createCredential(options: any): Promise<any> {
    // Convert base64url strings to Uint8Arrays
    const publicKey = {
      ...options.publicKey,
      challenge: this.base64urlDecode(options.publicKey.challenge),
      user: {
        ...options.publicKey.user,
        id: this.base64urlDecode(options.publicKey.user.id),
      },
      excludeCredentials: options.publicKey.excludeCredentials?.map((cred: any) => ({
        ...cred,
        id: this.base64urlDecode(cred.id),
      })),
    };

    const credential = await navigator.credentials.create({ publicKey });

    if (!credential) {
      throw new WebAuthnError(
        WebAuthnErrorType.INVALID_STATE,
        'Failed to create credential'
      );
    }

    // Convert credential to JSON-serializable format
    return this.credentialToJSON(credential);
  }

  /**
   * Get a WebAuthn assertion (authentication)
   * @internal
   */
  private async getAssertion(options: any): Promise<any> {
    // Convert base64url strings to Uint8Arrays
    const publicKey = {
      ...options.publicKey,
      challenge: this.base64urlDecode(options.publicKey.challenge),
      allowCredentials: options.publicKey.allowCredentials?.map((cred: any) => ({
        ...cred,
        id: this.base64urlDecode(cred.id),
      })),
    };

    const assertion = await navigator.credentials.get({ publicKey });

    if (!assertion) {
      throw new WebAuthnError(
        WebAuthnErrorType.INVALID_STATE,
        'Failed to get assertion'
      );
    }

    // Convert assertion to JSON-serializable format
    return this.credentialToJSON(assertion);
  }

  /**
   * Convert WebAuthn credential to JSON format
   * @internal
   */
  private credentialToJSON(credential: any): any {
    const response: any = {
      id: credential.id,
      rawId: this.base64urlEncode(credential.rawId),
      type: credential.type,
      response: {},
    };

    if (credential.response.clientDataJSON) {
      response.response.clientDataJSON = this.base64urlEncode(credential.response.clientDataJSON);
    }

    if (credential.response.attestationObject) {
      // Registration response
      response.response.attestationObject = this.base64urlEncode(credential.response.attestationObject);
    }

    if (credential.response.authenticatorData) {
      // Authentication response
      response.response.authenticatorData = this.base64urlEncode(credential.response.authenticatorData);
      response.response.signature = this.base64urlEncode(credential.response.signature);

      if (credential.response.userHandle) {
        response.response.userHandle = this.base64urlEncode(credential.response.userHandle);
      }
    }

    return response;
  }

  /**
   * Decode base64url string to Uint8Array
   * @internal
   */
  private base64urlDecode(str: string): Uint8Array {
    // Convert base64url to base64
    const base64 = str.replace(/-/g, '+').replace(/_/g, '/');

    // Decode base64 to binary string
    const binaryString = atob(base64);

    // Convert binary string to Uint8Array
    const bytes = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) {
      bytes[i] = binaryString.charCodeAt(i);
    }

    return bytes;
  }

  /**
   * Encode Uint8Array or ArrayBuffer to base64url string
   * @internal
   */
  private base64urlEncode(buffer: ArrayBuffer | Uint8Array): string {
    // Convert to Uint8Array if needed
    const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);

    // Convert to binary string
    let binaryString = '';
    for (let i = 0; i < bytes.length; i++) {
      binaryString += String.fromCharCode(bytes[i]);
    }

    // Encode to base64 and convert to base64url
    return btoa(binaryString)
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '');
  }

  /**
   * Get browser name
   * @internal
   */
  private getBrowserName(): string {
    const userAgent = navigator.userAgent.toLowerCase();

    if (userAgent.includes('chrome')) return 'Chrome';
    if (userAgent.includes('firefox')) return 'Firefox';
    if (userAgent.includes('safari')) return 'Safari';
    if (userAgent.includes('edge')) return 'Edge';
    if (userAgent.includes('opera')) return 'Opera';

    return 'Unknown';
  }

  /**
   * Handle errors and convert to WebAuthnError or RegistrationResult/AuthenticationResult
   * @internal
   */
  private handleError(err: unknown, defaultMessage: string): never | RegistrationResult | AuthenticationResult {
    if (err instanceof WebAuthnError) {
      return { success: false, error: err.message };
    }

    if (err instanceof Error) {
      if (err.name === 'NotAllowedError') {
        return {
          success: false,
          error: 'User cancelled the operation or permission was denied',
        };
      }

      if (err.name === 'NotSupportedError') {
        return {
          success: false,
          error: 'This operation is not supported',
        };
      }

      if (err.name === 'TimeoutError') {
        return {
          success: false,
          error: 'The operation timed out',
        };
      }

      if (err.name === 'InvalidStateError') {
        return {
          success: false,
          error: 'This credential is already registered or in an invalid state',
        };
      }

      return {
        success: false,
        error: err.message || defaultMessage,
      };
    }

    return {
      success: false,
      error: defaultMessage,
    };
  }
}
