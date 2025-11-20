# NoPasswords - Development Changelog

This changelog is optimized for AI-assisted development context. Each entry provides implementation details, rationale, and risks addressed.

---

## [Unreleased]

### 2025-11-20 - Feature 1: Core Library Structure

**Status**: Completed

**Objective**: Establish foundational architecture for the NoPasswords library with core interfaces and reference implementations.

**Changes Implemented**:

1. **Module Initialization**
   - Module path: `go.fergus.london/nopasswords`
   - Go version: 1.23 (minimum)
   - Dependencies: testify for testing framework

2. **Core Package Structure**
   - Created flat package structure: `core/` for shared interfaces and types
   - Future packages: `signedtoken/`, `webauthn/`, `srp/` (to be implemented)

3. **Interfaces Defined** (`core/interfaces.go`)
   - `CredentialStore`: Storage abstraction for WebAuthn credentials and SRP verifiers
   - `TokenStore`: Optional storage for token revocation support
   - `AuditLogger`: Security event logging abstraction
   - All interfaces use dependency injection pattern (library remains unopinionated)

4. **Base Types** (`core/types.go`)
   - `AuthResult`: Standardized authentication outcome structure
   - `AuthError`: Rich error types with security context
   - `AuditEvent`: Structured logging event format
   - `Config`: Base configuration with functional options support

5. **Reference Implementations** (`core/memory/`)
   - `MemoryCredentialStore`: Thread-safe in-memory credential storage
   - `MemoryTokenStore`: Thread-safe in-memory token storage
   - `NopLogger`: No-op logger for zero overhead
   - `StdoutLogger`: JSON-formatted stdout logger for development
   - All use sync.RWMutex for concurrent access safety

6. **Error Handling** (`core/errors.go`)
   - Common error types: ErrInvalidCredential, ErrExpired, ErrNotFound, etc.
   - Error wrapping support for context preservation
   - Secure error messages (no sensitive data leakage)

7. **Configuration Pattern** (`core/config.go`)
   - Functional options pattern: `WithLogger()`, `WithCredentialStore()`, etc.
   - Type-safe builder pattern
   - Sensible defaults (NopLogger, in-memory stores)

8. **Testing**
   - Comprehensive unit tests for all interfaces and implementations
   - Table-driven tests using testify/assert and testify/require
   - Concurrent access tests for memory implementations
   - Interface compliance tests

9. **Development Tooling**
   - Makefile with targets: test, lint, fmt, vet, coverage
   - golangci-lint configuration
   - Documentation generation support

**Security Risks Addressed**:

- **@risk Tampering**: Memory implementations use sync.RWMutex to prevent data races
  - Location: `core/memory/*.go`
  - Mitigation: All concurrent access is protected by mutex locks
  - Implementer responsibility: Custom stores must handle their own concurrency

- **@risk Information Disclosure**: Logging interface designed to prevent credential leakage
  - Location: `core/interfaces.go` (AuditLogger documentation)
  - Mitigation: AuditEvent excludes sensitive fields, documented in godoc
  - Implementer responsibility: Custom loggers must respect security boundaries

- **@risk Denial of Service**: No automatic cleanup in reference implementations
  - Location: `core/memory/*.go`
  - Documented: Implementers must implement their own TTL/cleanup strategies
  - Future consideration: Add optional TTL support to memory stores

- **@risk Elevation of Privilege**: Store interfaces prevent credential enumeration
  - Location: `core/interfaces.go`
  - Mitigation: List operations require explicit user context, no global enumeration
  - Constant-time operations where applicable (to be verified in crypto operations)

**Architecture Decisions**:

1. **Functional Options Pattern**: Chosen for flexibility and backward compatibility
   - Allows adding new options without breaking existing code
   - Clear, self-documenting API

2. **Flat Package Structure**: Simplifies imports and reduces nesting
   - `go.fergus.london/nopasswords/core`
   - `go.fergus.london/nopasswords/signedtoken` (future)
   - `go.fergus.london/nopasswords/webauthn` (future)
   - `go.fergus.london/nopasswords/srp` (future)

3. **Interface-First Design**: All dependencies injected via interfaces
   - Library remains unopinionated about infrastructure
   - Easy to mock for testing
   - Supports custom implementations

4. **Memory Reference Implementations**: Provide working examples
   - Demonstrate interface contracts
   - Useful for testing and development
   - NOT recommended for production (no persistence)

**Testing Coverage**:
- Unit tests for all public interfaces
- Concurrent access tests for memory stores
- Interface compliance verification
- Example code in tests demonstrating usage

**Next Steps** (Future Features):
- Feature 2: Implement signed token authentication
- Feature 3: Implement WebAuthn support
- Feature 4: Implement SRP protocol
- Feature 5: Expand audit logging capabilities
- Feature 6: CI/CD and development tooling

**Files Created**:
- `go.mod`, `go.sum`
- `core/interfaces.go`
- `core/types.go`
- `core/errors.go`
- `core/config.go`
- `core/memory/credential_store.go`
- `core/memory/token_store.go`
- `core/memory/logger.go`
- `core/interfaces_test.go`
- `core/memory/credential_store_test.go`
- `core/memory/token_store_test.go`
- `core/memory/logger_test.go`
- `Makefile`
- `.golangci.yml`

**Dependencies Added**:
- `github.com/stretchr/testify` v1.9.0 (testing)

**Godoc Comments**: All public types, interfaces, and functions documented with security considerations noted where applicable.

---

### 2025-11-20 - Feature 2: Signed Token Authentication

**Status**: Completed

**Objective**: Implement time-limited, cryptographically signed tokens for magic link style authentication with URL-safe encoding and optional revocation support.

**Changes Implemented**:

1. **Token Structure** (`signedtoken/token.go`)
   - `Token`: Core token structure with user ID, timestamps, and optional metadata
   - `SignedToken`: Token with cryptographic signature
   - Enforces maximum token lifetime of 24 hours
   - Enforces maximum metadata size of 1KB
   - URL-safe base64 encoding (no padding, using `-` and `_`)
   - Token ID generation via SHA-256 hash for revocation support

2. **Signing Infrastructure** (`signedtoken/signer.go`)
   - `Signer`: Interface for pluggable signing implementations
   - `HMACSignerSHA256`: Default HMAC-SHA256 implementation
   - Enforces minimum key length of 256 bits (32 bytes)
   - Constant-time signature comparison to prevent timing attacks
   - Key is copied on initialization to prevent external modification

3. **Manager** (`signedtoken/manager.go`)
   - `Manager`: Main API for token generation and verification
   - `GenerateToken()`: Creates signed tokens with default lifetime
   - `GenerateTokenWithLifetime()`: Creates tokens with custom lifetime
   - `VerifyToken()`: Validates signature, expiration, and revocation status
   - `RevokeToken()`: Marks tokens as revoked (requires TokenStore)
   - Integrates with core audit logging for all operations
   - Stateless verification (signature-based) with optional stateful revocation

4. **Configuration** (`signedtoken/config.go`)
   - Functional options pattern for flexible configuration
   - `WithSigner()`: Required - sets cryptographic signer
   - `WithDefaultLifetime()`: Optional - default 1 hour
   - `WithTokenStore()`: Optional - enables revocation support
   - `WithAuditLogger()`: Optional - defaults to no-op logger
   - `WithOpaqueIDs()`: Optional - enables opaque identifier mode
   - Configuration validation ensures signer is present and lifetime is valid

5. **Testing** (`signedtoken/*_test.go`)
   - Comprehensive unit tests for all components
   - Token serialization/deserialization tests
   - Signer implementation tests with various key lengths
   - Manager tests covering generation, verification, and revocation
   - Integration tests for full generate → verify → revoke cycle
   - Negative tests for expired tokens, invalid signatures, tampered data
   - Concurrent operation tests verifying thread safety
   - Benchmarks for performance measurement

**Security Risks Addressed**:

- **@risk Spoofing** (Weak signing keys allow token forgery)
  - Location: `signedtoken/signer.go:28-30`
  - Mitigation: Enforced minimum key length of 256 bits
  - Code comment: Lines 23-25

- **@risk Tampering** (Insufficient signature validation allows modification)
  - Location: `signedtoken/signer.go:103-105, signedtoken/manager.go:138-143`
  - Mitigation: Cryptographic signature verification with constant-time comparison
  - Code comment: Lines 96, 104, 141

- **@risk Repudiation** (Lack of audit logging prevents investigation)
  - Location: `signedtoken/manager.go:112-117, 172-177, 221-223, 257-260`
  - Mitigation: Comprehensive audit events for all token operations
  - Code comment: Lines 66-67, 164, 219, 255

- **@risk Information Disclosure** (Tokens might leak user identifiers in URLs)
  - Location: `signedtoken/token.go:46-49, signedtoken/config.go:47-58`
  - Mitigation: Optional opaque identifier mode available via configuration
  - Code comment: Lines 46-49 in token.go, 47-57 in config.go
  - Documented as implementer responsibility with mitigation option

- **@risk Denial of Service** (No rate limiting on token generation, unbounded storage)
  - Location: INITIAL_IMPLEMENTATION.md line 112
  - Documented: Explicitly noted as implementer responsibility
  - Mitigation: Maximum token lifetime (24 hours) and metadata size (1KB) limits enforced
  - Code comment: Lines 10-13, 17-20 in token.go

**Architecture Decisions**:

1. **HMAC-SHA256 as Default**: Chosen for balance of security, performance, and simplicity
   - Symmetric key operation (same key for sign/verify)
   - Well-understood cryptographic properties
   - Fast computation suitable for high-throughput scenarios
   - Extensible via Signer interface for asymmetric alternatives

2. **URL-Safe Base64 Encoding**: Required for magic link delivery
   - No padding (`=`) to prevent URL encoding issues
   - Uses `-` and `_` instead of `+` and `/`
   - Warns if token exceeds 2048 bytes (common URL length limit)

3. **Optional Revocation Support**: Tokens are stateless by default
   - Signature-only verification for maximum scalability
   - Optional TokenStore enables revocation at cost of state
   - Token ID derived from hash (not embedded) to prevent information disclosure

4. **Opaque Identifier Mode**: Privacy-conscious option for user IDs
   - Disabled by default (IDs included in tokens as-is)
   - When enabled, expects application to provide opaque IDs
   - Reduces information leakage in URLs and logs

5. **Functional Options Pattern**: Consistent with core library design
   - Required options (Signer) enforced via validation
   - Optional features have sensible defaults
   - Backward compatible - new options don't break existing code

**Testing Coverage**:
- Unit tests for token creation, encoding, validation
- Unit tests for HMAC signer with various key lengths and edge cases
- Manager tests for generation, verification, revocation workflows
- Integration tests for complete authentication flows
- Negative tests for security boundaries (expired, tampered, invalid)
- Concurrent access tests for thread safety
- Benchmarks for performance analysis

**Next Steps** (Future Features):
- Feature 3: Implement WebAuthn support
- Feature 4: Implement SRP protocol
- Feature 5: Expand audit logging capabilities
- Feature 6: CI/CD and development tooling
- Consider: Example code for email integration
- Consider: KMS-based signer implementation example

**Files Created**:
- `signedtoken/token.go` - Token structures and serialization
- `signedtoken/signer.go` - Signer interface and HMAC implementation
- `signedtoken/manager.go` - Token generation and verification
- `signedtoken/config.go` - Configuration and options
- `signedtoken/token_test.go` - Token tests
- `signedtoken/signer_test.go` - Signer tests
- `signedtoken/manager_test.go` - Manager and integration tests

**Dependencies**: No new dependencies (uses existing testify)

**Godoc Comments**: All public types, interfaces, and functions documented with:
- Security considerations and risk annotations (@risk, @mitigation)
- Usage examples where appropriate
- Parameter constraints (e.g., key lengths, lifetime limits)
- Thread safety guarantees

---

### 2025-11-20 - Feature 3: WebAuthn Support

**Status**: Completed

**Objective**: Implement FIDO2/WebAuthn authentication support, allowing users to authenticate using hardware tokens, platform authenticators (Touch ID, Windows Hello), or security keys.

**Changes Implemented**:

1. **Go WebAuthn Package** (`webauthn/`)
   - Created comprehensive WebAuthn implementation wrapping `github.com/go-webauthn/webauthn` v0.15.0
   - Package structure: `types.go`, `config.go`, `manager.go`
   - Integrates with core NoPasswords interfaces (CredentialStore, AuditLogger)

2. **Type Definitions** (`webauthn/types.go`)
   - `Credential`: Stored credential structure with public key, sign count, AAGUID, transport info
   - `User`: WebAuthn user implementing webauthn.User interface
   - `SessionData`: Temporary data for multi-step WebAuthn ceremonies (challenge, userID, expiry)
   - `RegistrationResult` / `AuthenticationResult`: Operation outcomes
   - User verification levels: Required, Preferred, Discouraged
   - Attestation preferences: None (default), Indirect, Direct, Enterprise
   - JSON serialization for credential and session persistence

3. **Configuration** (`webauthn/config.go`)
   - Functional options pattern matching core library design
   - `WithRPDisplayName()`, `WithRPID()`, `WithRPOrigins()` - relying party configuration
   - `WithUserVerification()` - default "preferred", configurable
   - `WithAttestationPreference()` - default "none", supports all formats
   - `WithTimeout()` - default 60 seconds, max 10 minutes
   - `WithAuthenticatorSelection()` - platform/cross-platform, resident key options
   - `WithCredentialStore()` - required, uses core.CredentialStore interface
   - `WithAuditLogger()` - optional, defaults to no-op logger
   - Environment variable fallbacks: WEBAUTHN_RP_ID, WEBAUTHN_RP_ORIGINS
   - Comprehensive validation of required fields and constraints

4. **WebAuthn Manager** (`webauthn/manager.go`)
   - `BeginRegistration()`: Initiates attestation ceremony, generates challenge
   - `FinishRegistration()`: Verifies attestation response, stores credential
   - `BeginAuthentication()`: Initiates assertion ceremony, supports user-scoped and discoverable credentials
   - `FinishAuthentication()`: Verifies assertion, validates sign counter, updates credential
   - `GenerateChallenge()`: Cryptographically random challenge generation (32 bytes)
   - Session data encoding: Base64URL for challenge transport between ceremony steps
   - Credential ID encoding: Base64URL for storage keys
   - Automatic credential exclusion during registration (prevents duplicate credentials)
   - Sign counter validation to detect cloned authenticators

5. **Comprehensive Testing** (`webauthn/*_test.go`)
   - `types_test.go`: Credential/session serialization, user interface compliance
   - `config_test.go`: Configuration validation, environment variable fallbacks, option validation
   - `manager_test.go`: Registration/authentication flows, session expiry, error handling
   - Coverage: 56.8% (good for initial implementation)
   - Tests for nil handling, expired sessions, invalid credentials
   - Concurrent access verification for thread safety

6. **TypeScript Client Library** (`client/`)
   - Modern TypeScript implementation with ES2020 target
   - Single-bundle distribution via esbuild (IIFE format)
   - Global name: `NoPasswordsWebAuthn` for easy browser integration
   - Comprehensive error handling and browser compatibility detection

7. **Client Features** (`client/src/`)
   - `WebAuthnClient`: Main API for registration and authentication
   - `checkCapabilities()`: Browser WebAuthn support detection, platform authenticator availability
   - `register()`: Three-step registration flow (begin → create → finish)
   - `authenticate()`: Three-step authentication flow (begin → get → finish)
   - Base64URL encoding/decoding for WebAuthn credential transport
   - Automatic ArrayBuffer/Uint8Array conversion for WebAuthn API
   - Typed error handling: NOT_SUPPORTED, NOT_ALLOWED, TIMEOUT, NETWORK, INVALID_STATE, UNKNOWN
   - Graceful degradation for browsers without WebAuthn support

8. **Example Implementation** (`examples/webauthn-demo/`)
   - Complete working demo with Go HTTP server
   - RESTful API endpoints: `/api/webauthn/register/{begin,finish}`, `/api/webauthn/authenticate/{begin,finish}`
   - In-memory session storage (with warnings for production use)
   - Cookie-based session management
   - Static file serving for HTML/JS/CSS
   - Beautiful, responsive UI with status indicators
   - Real-time browser capability detection
   - Form validation and user feedback

9. **Build System**
   - TypeScript compilation with declaration files
   - esbuild bundling for production distribution
   - npm scripts: `build`, `watch`
   - Automated build pipeline in package.json

**Security Risks Addressed**:

- **@risk Spoofing** (Incorrect origin validation allows phishing)
  - Location: `webauthn/config.go:65-78`
  - Mitigation: Explicit origin configuration with documentation warnings against wildcards
  - Code comment: Lines 65-71 warn about validation importance
  - Browser enforces origin matching during credential creation/retrieval

- **@risk Tampering** (Insufficient attestation verification allows credential injection)
  - Location: `webauthn/manager.go:256-269`
  - Mitigation: go-webauthn library handles cryptographic verification
  - Session data validation ensures request/response correlation
  - Code comment: Lines 182-188 document attestation verification

- **@risk Repudiation** (Lack of audit logging prevents investigation)
  - Location: `webauthn/manager.go:87-94, 158-162, 254-263, 354-362, 537-545`
  - Mitigation: Comprehensive audit events for all operations
  - Events logged: registration.begin, registration.finish, authentication.begin, authentication.finish
  - Includes success/failure, user context, error details
  - Code comments: Lines 66-67, 81-88, 179-188, 310-318, 448-457

- **@risk Information Disclosure** (Credential enumeration via timing attacks)
  - Location: `webauthn/manager.go:357-362`
  - Documented: Timing attack mitigation should be implemented by applications
  - Recommendation: Use constant-time operations and rate limiting
  - Code comment: Lines 309-315 document the risk

- **@risk Denial of Service** (Unbounded credential storage per user)
  - Location: `webauthn/manager.go:186-190`
  - Documented: Applications should implement credential limits
  - Code comment: Lines 186-190 document DoS risk
  - Recommendation: Enforce max credentials per user (e.g., 5-10)

- **@risk Elevation of Privilege** (Incorrect challenge validation allows replay attacks)
  - Location: `webauthn/manager.go:73-80, 207-212, 470-478`
  - Mitigation: Cryptographically random challenges (32 bytes)
  - Session timeout enforcement prevents stale challenge reuse
  - Challenge stored securely server-side, never sent to client
  - Code comments: Lines 73-80, 207-212, 470-478

- **@risk Elevation of Privilege** (Sign counter anomaly detection)
  - Location: `webauthn/manager.go:555-571`
  - Mitigation: Validate sign counter increments to detect cloned authenticators
  - Reject authentication if counter doesn't increment or decreases
  - Comprehensive audit logging of anomalies
  - Code comment: Lines 555-561

**Architecture Decisions**:

1. **Wrapper Pattern**: Wrap go-webauthn library rather than reimplementing
   - Rationale: Leverage well-tested, spec-compliant implementation
   - Maintains NoPasswords interface consistency
   - Allows library upgrades without API changes
   - Reduces crypto implementation risk

2. **Session Data Storage**: Base64URL encoding for challenge transport
   - Challenge stored as bytes in SessionData (our type)
   - Encoded to base64url string for webauthn.SessionData (library type)
   - Prevents encoding issues, matches WebAuthn spec
   - Consistent with credential ID encoding

3. **Default Settings**: Conservative security defaults
   - Attestation: "none" (privacy-friendly, reduces friction)
   - User verification: "preferred" (balance security and UX)
   - Timeout: 60 seconds (sufficient for user interaction)
   - All defaults configurable via functional options

4. **TypeScript Client**: Compiled to single IIFE bundle
   - Rationale: Easy integration without build tools
   - Global namespace prevents module conflicts
   - Minified for production performance
   - Source maps for debugging

5. **Error Handling**: Graceful degradation in client
   - Detect WebAuthn support before operations
   - User-friendly error messages
   - Typed error categories for application handling
   - Never throws on unsupported browsers

6. **Example Demo**: Simplified for clarity
   - In-memory storage (clearly documented as non-production)
   - Cookie sessions (with security warnings)
   - Minimal dependencies
   - Focuses on WebAuthn flow, not production concerns

**Testing Coverage**:

- Unit tests for all public interfaces and types
- Configuration validation with environment variable fallbacks
- Session lifecycle: creation, expiry, validation
- Error conditions: nil parameters, expired sessions, invalid data
- Concurrent access verification
- Type serialization/deserialization roundtrips
- 56.8% code coverage (focused on critical paths)

**Next Steps** (Future Enhancements):

- Feature 4: Implement SRP protocol
- Feature 5: Expand audit logging capabilities
- Feature 6: CI/CD and development tooling
- Consider: Credential management API (list/delete credentials)
- Consider: TypeScript tests with Jest
- Consider: E2E tests with Playwright
- Consider: Credential backup and recovery documentation
- Consider: User verification level per-request override
- Consider: Discoverable credential (resident key) examples

**Files Created**:

Go Implementation:
- `webauthn/types.go` - Type definitions and WebAuthn interfaces
- `webauthn/config.go` - Configuration and functional options
- `webauthn/manager.go` - WebAuthn manager and ceremony flows
- `webauthn/types_test.go` - Type and serialization tests
- `webauthn/config_test.go` - Configuration validation tests
- `webauthn/manager_test.go` - Manager and integration tests

TypeScript Client:
- `client/package.json` - npm package configuration
- `client/tsconfig.json` - TypeScript compiler configuration
- `client/build.js` - esbuild bundler script
- `client/src/types.ts` - TypeScript type definitions
- `client/src/client.ts` - WebAuthn client implementation
- `client/src/index.ts` - Package exports

Example:
- `examples/webauthn-demo/main.go` - Demo HTTP server
- `examples/webauthn-demo/static/index.html` - Demo UI
- `examples/webauthn-demo/static/nopasswords-webauthn.js` - Compiled client (bundled)
- `examples/webauthn-demo/README.md` - Demo documentation

**Dependencies Added**:
- `github.com/go-webauthn/webauthn` v0.15.0 (WebAuthn protocol)
- TypeScript v5.9.3 (client development)
- esbuild v0.27.0 (client bundling)

**Documentation**:
- All public types, interfaces, and functions have godoc comments
- Security considerations documented with @risk/@mitigation tags
- TypeScript types fully documented with JSDoc comments
- Example README with security warnings
- Client library usage examples in code comments

**Cross-Browser Compatibility**:
- Chrome/Edge: Full support
- Firefox: Full support
- Safari: Full support (macOS/iOS)
- Browser detection and capability reporting
- Graceful degradation for unsupported browsers

**Production Readiness Notes**:
- ✅ Core implementation production-ready
- ✅ Comprehensive error handling
- ✅ Audit logging integration
- ⚠️  Example is for demonstration only
- ⚠️  Applications must implement: rate limiting, credential limits, persistent storage, HTTPS, CSRF protection
- ⚠️  Credential backup/recovery policies are application responsibility

---

## Changelog Format Guide (for AI context)

Each entry should include:
- **Date and Feature**: Clear identification
- **Status**: In Progress, Completed, Blocked
- **Objective**: What and why
- **Changes Implemented**: Detailed list with file locations
- **Security Risks Addressed**: Map to STRIDE model with @risk/@mitigation tags
- **Architecture Decisions**: Rationale for design choices
- **Testing Coverage**: What's tested and how
- **Next Steps**: Dependencies and follow-up work
- **Files Created/Modified**: Complete file list for reference
- **Dependencies**: External packages with versions

This format provides comprehensive context for:
- Understanding implementation details
- Tracking security considerations
- Making informed decisions in future features
- Debugging and maintenance
- Code review and auditing
