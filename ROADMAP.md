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

## Passkey Synchronisation Support

Enhanced WebAuthn implementation supporting passkey synchronisation across devices via platform providers (iCloud Keychain, Google Password Manager).

- Discoverable credentials (resident keys)
- Conditional UI for passkey selection
- Cross-device authentication flows
- Guidance on passkey UX patterns

Requires careful consideration of user verification levels and backup authentication methods.

---

## FIDO2 Enterprise Attestation

Support for enterprise attestation scenarios where organisations require cryptographic proof of authenticator properties.

- Attestation format validation beyond basic checks
- Enterprise attestation trust root configuration
- Metadata service integration (FIDO MDS)
- Device identification and policy enforcement

Primarily relevant for high-security environments with specific compliance requirements.

---

## OAuth2/OIDC Integration Helpers

Utility functions and patterns for integrating NoPasswords authentication with OAuth2 and OpenID Connect flows.

- Token exchange patterns
- Custom grant type examples
- Claims mapping from passwordless authentication
- Integration with existing OIDC providers

Not a full OAuth2 server implementation, but helpers for common integration scenarios.

---

## Account Recovery Utilities

Toolkit for implementing secure account recovery flows when primary authentication methods are unavailable.

- Recovery code generation and storage (hashed)
- Time-limited recovery token generation
- Multi-step recovery verification
- Audit trail for recovery events

Account recovery remains implementer responsibility, but library could provide cryptographic primitives and patterns.

---

## Credential Management Utilities

Helper functions for credential lifecycle management.

- Credential rotation/renewal
- Credential revocation and tombstoning
- Credential usage tracking (last used, registration date)
- Bulk credential operations (admin tooling)
- Credential export/import (account portability)

Focus on operational concerns rather than authentication flows.

---

## Advanced SRP Features

Extensions to the base SRP implementation for specific use cases.

- SRP-6a variant support
- Custom prime group generation
- Key derivation function configuration (PBKDF2, scrypt, Argon2)
- Protocol version negotiation

Would need to balance cryptographic flexibility against misconfiguration risks.

---

## Rate Limiting Interface

Optional rate limiting interface for implementers who want standardised patterns.

- Interface definition for rate limiters
- Reference implementations (in-memory, Redis-based)
- Per-method rate limiting configuration
- Adaptive rate limiting based on failure patterns

Implementer remains responsible, but library could provide contracts and examples.

---

## Session Management Interface

Optional session management interface for implementers wanting standardised patterns.

- Session creation and validation
- Session storage interface
- Reference implementations (signed cookies, Redis)
- Session fixation prevention

Library would remain unopinionated, but provide contracts for those who want consistency.

---

## Metrics and Observability

Structured metrics interface for authentication telemetry.

- Prometheus-style metrics interface
- Standard metric definitions (auth attempts, latency, failures)
- Exemplar support for distributed tracing
- Reference implementations

Similar pattern to audit logging - interface with pluggable implementations.

---

## Risk-Based Authentication

Framework for implementing risk-based authentication decisions.

- Risk signal interface (device fingerprint, location, behaviour)
- Configurable risk scoring
- Step-up authentication triggers
- Integration with existing authentication flows

Requires significant architectural consideration and clear boundaries between library and implementer concerns.

---

## Mobile SDK

Native mobile implementations for iOS and Android.

**iOS (Swift):**
- Native WebAuthn support via ASAuthorization
- SRP client implementation
- Keychain integration

**Android (Kotlin):**
- Native WebAuthn support via FIDO2 API
- SRP client implementation
- KeyStore integration

Significant expansion of project scope, but logical extension for mobile-first applications.

---

## Hardware Security Module (HSM) Integration

Support for hardware-backed cryptographic operations.

- PKCS#11 interface for token signing
- Cloud HSM integration (AWS CloudHSM, GCP Cloud HSM)
- Key management patterns
- Performance considerations

Relevant for high-security deployments with compliance requirements.

---

## Formal Security Analysis

Third-party security assessment and formal verification.

- Protocol analysis by cryptography experts
- Penetration testing of reference implementations
- Formal verification of cryptographic implementations
- Public security audit reports

Essential before production use in high-risk environments, but outside typical development roadmap.
