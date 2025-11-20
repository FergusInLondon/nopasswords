# NoPasswords - Development Changelog

This changelog is optimized for AI-assisted development context. Each entry provides implementation details, rationale, and risks addressed.

---

## [Unreleased]

### 2025-11-20 - Feature 1: Core Library Structure

**Status**: In Progress

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
