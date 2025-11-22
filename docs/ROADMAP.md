# NoPasswords - Roadmap

Future requirements and enhancements beyond the initial implementation. These items are not committed deliverables but represent logical extensions of the library's functionality.

---

## Multi-Factor Authentication (MFA)

Support for multi-factor authentication flows, where passwordless methods serve as either primary or secondary factors.

**TOTP (Time-based One-Time Password):**
- RFC6238 implementation with QR code generation
- Configurable time window and code length
- Recovery code generation and validation
- Integration with existing authentication flows

**WebAuthn as Second Factor:**
- Support WebAuthn as supplementary authentication
- Distinct credential storage for 2FA credentials
- Configurable user verification requirements
- Fallback mechanisms if authenticator unavailable

Implementation would require session state management between factors, likely requiring additional interfaces for multi-step authentication flows.

---

## OAuth2/OIDC Integration Helpers

Utility functions and patterns for integrating NoPasswords authentication with OAuth2 and OpenID Connect flows.

- Token exchange patterns
- Custom grant type examples
- Claims mapping from passwordless authentication
- Integration with existing OIDC providers

Not a full OAuth2 server implementation, but helpers for common integration scenarios.
