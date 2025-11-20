# NoPasswords - Initial Implementation

## Requirements

The initial implementation provides three distinct passwordless authentication methods: signed tokens (magic links), WebAuthn, and SRP. Each method is implemented as a standalone component with well-defined interfaces for storage, logging, and configuration. The Go library remains unopinionated about application architecture, requiring implementers to provide storage and logging implementations via dependency injection. Client-side JavaScript is provided for WebAuthn and SRP, with configuration formats matching server-side equivalents to prevent misconfiguration. All cryptographic operations must be thoroughly tested, with particular attention to cross-language compatibility between Go and JavaScript implementations.

---

## Feature 1: Core Library Structure

### Use Case

Establish the foundational architecture for the NoPasswords library, defining common interfaces and patterns used across all authentication methods.

### Scenario

```gherkin
Given an implementer wants to use NoPasswords
When they import the Go module
Then they should find clearly defined interfaces for storage and logging
And they should be able to implement these interfaces with their existing infrastructure
And the library should not force opinions about database, logging, or metrics systems
```

### Implementation

- Define core interfaces (`CredentialStore`, `TokenStore`, `AuditLogger`)
- Provide in-memory reference implementations for all interfaces
- Create base types for authentication results and errors
- Establish configuration patterns (functional options or struct-based)
- Define common error types and handling patterns

### Recommended Tests

- Unit tests verifying in-memory implementations satisfy interfaces
- Unit tests for configuration builders/validators
- Example code demonstrating interface implementation

### Incidental Tasks

- Repository structure (separate packages for each auth method)
- Go module configuration and dependency management
- Documentation structure and godoc comments
- Makefile or task runner for common operations

### Identified Risks

- **Tampering**: Custom storage implementations may not handle concurrent access safely
- **Information Disclosure**: Logging implementations might inadvertently log sensitive data
- **Denial of Service**: Unbounded storage growth if implementer doesn't handle cleanup
- **Elevation of Privilege**: Storage interface must prevent credential enumeration

---

## Feature 2: Signed Token Authentication

### Use Case

Generate time-limited, cryptographically signed tokens for magic link style authentication. Tokens are embedded in URLs, sent to users (typically via email), and verified on callback.

### Scenario

```gherkin
Given a user requests authentication
When the server generates a signed token with user identifier and expiry
Then the token should contain all required state
And the token should be cryptographically signed
And the token should be URL-safe

Given a user receives a magic link
When they click the link within the validity period
Then the server should verify the signature
And extract the user identifier
And allow authentication to proceed

Given a user clicks an expired or tampered link
When the server attempts verification
Then verification should fail with a clear error
And the failure should be logged
```

### Implementation

- Token structure: user identifier, issued-at, expires-at, optional metadata (JSON serialised)
- Default signer: HMAC-SHA256 with configurable secret key
- Encoding: Base64 URL-safe encoding
- Interface for custom signers/verifiers (e.g. asymmetric keys, KMS)
- Configurable token lifetime (default: 1 hour)
- TokenStore interface for optional revocation support

### Recommended Tests

- Unit tests: token generation, signature verification, expiry validation
- Unit tests: URL-safe encoding/decoding
- Unit tests: metadata serialisation/deserialisation
- Unit tests: custom signer implementation
- Integration test: full generate → verify cycle
- Negative tests: expired tokens, invalid signatures, malformed tokens

### Incidental Tasks

- Documentation on token delivery mechanisms (out of scope for library)
- Example implementation showing email integration
- Guidelines on secret key management

### Identified Risks

- **Spoofing**: Weak signing keys allow token forgery
- **Tampering**: Insufficient signature validation allows modification
- **Repudiation**: Lack of audit logging prevents investigation
- **Information Disclosure**: Tokens might leak user identifiers in URLs
- **Denial of Service**: No rate limiting on token generation (implementer responsibility)

---

## Feature 3: WebAuthn Support

### Use Case

Support FIDO2/WebAuthn authentication, allowing users to authenticate using hardware tokens, platform authenticators (Touch ID, Windows Hello), or security keys.

### Scenario

```gherkin
# Attestation (Registration)
Given a user wants to register a new credential
When the server initiates attestation
Then it should generate challenge and options
And the client should invoke navigator.credentials.create()
And the authenticator should create a credential
And the client should return the attestation response
And the server should verify the attestation
And store the credential for future authentication

# Assertion (Authentication)
Given a user has a registered credential
When the user initiates authentication
Then the server should generate an assertion challenge
And the client should invoke navigator.credentials.get()
And the authenticator should sign the challenge
And the client should return the assertion response
And the server should verify the signature
And allow authentication to proceed

# Browser Compatibility
Given a browser without WebAuthn support
When the client library loads
Then it should detect the lack of support
And fail gracefully without errors
And optionally notify the application
```

### Implementation

**Server (Go):**
- Use `github.com/go-webauthn/webauthn` as base library
- Wrap library with NoPasswords interfaces
- Implement CredentialStore interface for credential persistence
- Configurable relying party ID and origin
- Support both attestation and assertion flows

**Client (JavaScript):**
- Feature detection for WebAuthn support
- Wrapper functions for `create()` and `get()` operations
- Base64 encoding/decoding for transport
- Error handling and user-friendly messages
- Configuration object matching server-side format

### Recommended Tests

- Unit tests: credential storage, challenge generation, verification logic
- Unit tests: base64 encoding/decoding compatibility
- BDD/E2E test: successful registration and authentication flow
- BDD/E2E test: authentication failure scenarios
- BDD/E2E test: graceful degradation without WebAuthn support
- Cross-browser testing (Chrome, Firefox, Safari, Edge)

### Incidental Tasks

- Dockerfile for test container with browser automation
- Example HTML page demonstrating integration
- Documentation on user verification levels
- Guidelines on credential backup and recovery

### Identified Risks

- **Spoofing**: Incorrect origin validation allows phishing
- **Tampering**: Insufficient attestation verification allows credential injection
- **Repudiation**: Lack of audit logging prevents investigation
- **Information Disclosure**: Credential enumeration via timing attacks
- **Denial of Service**: Unbounded credential storage per user
- **Elevation of Privilege**: Incorrect challenge validation allows replay attacks

---

## Feature 4: Secure Remote Password (SRP)

### Use Case

Implement SRP protocol for zero-knowledge password proof, allowing password-based authentication without transmitting passwords or storing password-equivalent data.

### Scenario

```gherkin
# Registration
Given a user wants to register with a password
When the client generates a salt
And computes the SRP verifier
Then the server should store the salt and verifier
And discard the password
And the verifier should not allow password recovery

# Authentication
Given a user has registered credentials
When the user initiates authentication with password
Then the server should send salt and public ephemeral (B)
And the client should compute public ephemeral (A)
And both parties should derive session key
And the client should send proof (M1)
And the server should verify M1
And the server should send proof (M2)
And the client should verify M2
And authentication should succeed with matching session key

# Failed Authentication
Given incorrect password or tampering
When either party verifies the proof
Then verification should fail
And authentication should be rejected
And the failure should be logged
```

### Implementation

**Server (Go):**
- RFC5054 implementation with groups 3, 4, 5 (2048/3072/4096-bit)
- Verifier storage via CredentialStore interface
- Configurable group selection
- Constant-time comparison for M1 verification
- Session key derivation (implementer handles session management)

**Client (JavaScript):**
- Modernise existing open-source implementation (e.g. Stanford JS SRP)
- Replace deprecated crypto APIs with WebCrypto
- Match server configuration format exactly
- Support same group parameters as server
- BigInteger arithmetic via modern library

**Configuration:**
- Identical structure between client and server
- Group parameter selection
- Hash algorithm (SHA-256 minimum)
- Salt length (128-bit minimum)

### Recommended Tests

- Unit tests: verifier generation, ephemeral key generation, session key derivation
- Unit tests: M1/M2 computation and verification
- Unit tests: group parameter validation
- Unit tests: constant-time comparison
- Cross-language test: Go and JavaScript produce compatible keys
- BDD/E2E test: successful registration and authentication
- BDD/E2E test: authentication with incorrect password
- BDD/E2E test: protocol tampering detection
- Performance test: acceptable latency on 4096-bit group

### Incidental Tasks

- Selection and licensing review of JavaScript SRP base library
- Modernisation plan for chosen library
- Documentation on group parameter selection
- Guidance on password policy (library doesn't enforce)
- Example implementation showing complete flow

### Identified Risks

- **Spoofing**: Weak group parameters allow offline attacks
- **Tampering**: Incorrect protocol implementation allows man-in-the-middle
- **Repudiation**: Lack of audit logging prevents investigation
- **Information Disclosure**: Timing attacks on verification reveal information
- **Denial of Service**: Large group parameters cause CPU exhaustion
- **Elevation of Privilege**: Session key misuse allows impersonation

---

## Feature 5: Audit Logging Interface

### Use Case

Provide structured logging for security-relevant events across all authentication methods, allowing implementers to integrate with their existing logging infrastructure.

### Scenario

```gherkin
Given any authentication event occurs
When the library generates an audit event
Then it should be passed to the configured AuditLogger
And the event should contain relevant context
And the event should not contain sensitive data (passwords, keys)

Given an implementer uses the nop logger
When audit events are generated
Then they should be silently discarded
And have no performance impact

Given an implementer uses the stdout logger
When audit events are generated
Then they should be written as structured JSON
And include timestamp, event type, user identifier, and outcome
```

### Implementation

- Define `AuditLogger` interface with single `Log(event AuditEvent)` method
- `AuditEvent` structure with standard fields (timestamp, event type, user ID, outcome, metadata)
- Provide `NopLogger` (no-op implementation)
- Provide `StdoutLogger` (JSON output to stdout)
- Event types: authentication attempt, credential registration, token generation, verification failure
- Ensure no sensitive data in logged events

### Recommended Tests

- Unit tests: audit event serialisation
- Unit tests: stdout logger output format
- Integration tests: verify audit events generated for all authentication flows
- Unit tests: sensitive data exclusion

### Incidental Tasks

- Documentation on audit event schema
- Example implementation with structured logging library (zerolog, zap)
- Guidelines on SIEM integration

### Identified Risks

- **Information Disclosure**: Accidentally logging sensitive credentials or keys
- **Repudiation**: Insufficient event detail prevents investigation
- **Denial of Service**: Unbounded logging fills disk (implementer responsibility)

---

## Feature 6: Development Tooling and CI/CD

### Use Case

Provide comprehensive development tooling to ensure code quality, enable rapid iteration, and automate the release process.

### Scenario

```gherkin
Given a developer clones the repository
When they run the development environment setup
Then all dependencies should be available
And linting should pass
And tests should pass
And examples should run

Given a pull request is submitted
When GitHub Actions runs
Then Go and JavaScript code should be linted
And all tests should pass
And code coverage should be reported

Given a new version is tagged
When the release workflow runs
Then the npm package should be published
And GitHub release should be created
And documentation should be updated
```

### Implementation

**Go tooling:**
- `golangci-lint` for linting
- `go test` with race detector
- `go mod` for dependency management

**JavaScript tooling:**
- ESLint for linting
- Jest or similar for testing
- npm for package management

**Docker:**
- Development container with all dependencies
- Test container for E2E tests (Playwright + browsers)

**GitHub Actions:**
- Workflow: lint, test, build
- Workflow: publish to npm on tag
- Dependabot for dependency updates

**Makefile/Task runner:**
- `make lint`: run all linters
- `make test`: run all tests
- `make dev`: start development environment
- `make examples`: run all examples

### Recommended Tests

- Verify all workflows execute successfully
- Verify Docker containers build correctly
- Verify examples run without errors

### Incidental Tasks

- README with setup instructions
- CONTRIBUTING guide
- LICENSE selection
- Code of conduct

### Identified Risks

- **Tampering**: Supply chain attacks via compromised dependencies
- **Information Disclosure**: Secrets leaked in CI logs
- **Elevation of Privilege**: Overly permissive GitHub Actions permissions
