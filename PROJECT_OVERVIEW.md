# NoPasswords - Project Overview

## Intention

NoPasswords provides a Go library and companion JavaScript client for implementing passwordless authentication in web applications. The library handles the cryptographic and protocol complexity whilst remaining unopinionated about application architecture, storage layers, and session management.

Target use case: web applications where passwords are either a poor UX choice or represent an unnecessary security risk. The library supports multiple authentication methods with consistent interfaces, allowing implementers to choose appropriate methods for their use case.

## Core Design Principles

- **Interface-driven**: Storage, logging, metrics are abstracted behind interfaces
- **Minimal dependencies**: Rely on standard library and proven cryptographic packages
- **Configuration over opinion**: Sensible defaults, but implementer retains control
- **Security by design**: No shortcuts in cryptographic implementation or protocol handling
- **Testable**: Clear boundaries between components, comprehensive test coverage of critical paths

## Scope

### Initial Implementation (Heavy MVP)

**Server-side (Go module):**
- Signed token generation and verification for magic link authentication
- WebAuthn attestation (credential registration) and assertion (authentication)
- SRP protocol implementation (groups 3, 4, 5 - 2048/3072/4096-bit)
- Audit logging interface with reference implementations
- Pluggable storage interfaces with in-memory reference implementation

**Client-side (JavaScript):**
- WebAuthn browser API integration with graceful degradation
- SRP client implementation (modernised from existing open-source)
- Unified configuration format matching server-side

**Development tooling:**
- Linting and code quality enforcement (both languages)
- Dockerised development environment
- Automated build pipeline
- GitHub Actions for npm publication

**Testing:**
- Unit tests for cryptographic operations and protocol implementations
- BDD/E2E tests for complete authentication flows
- Cross-language compatibility verification (Go ↔ JavaScript)

### Explicitly Out of Scope

- Session management (implementer responsibility)
- Rate limiting (implementer responsibility)
- User account creation/management
- Account recovery flows
- Multi-factor authentication (roadmap item)
- Token/credential delivery mechanisms (e.g. email sending)

## Success Criteria

A successful initial implementation allows a developer to:

1. Add the Go module to an existing application
2. Implement required storage and logging interfaces
3. Choose one or more authentication methods
4. Integrate client-side JavaScript
5. Have a working, secure, passwordless authentication flow

The implementation must be secure, stable, and well-tested. Feature completeness is secondary to correctness.
