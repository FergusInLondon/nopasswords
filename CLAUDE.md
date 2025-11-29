# CLAUDE.md - AI Assistant Guide for NoPasswords

This document provides comprehensive guidance for AI assistants working on the NoPasswords codebase. It covers architecture, conventions, workflows, and best practices to ensure consistent, high-quality contributions.

## Project Overview

**NoPasswords** is a Go library for passwordless authentication implementing the Secure Remote Password (SRP) protocol per RFC 5054. It's designed as a "proof of presence" library, not a full authentication framework.

**Key Characteristics:**
- **Opinionless Design**: Dependency injection for storage, caching, and logging
- **Cross-Platform**: Go backend with TypeScript/JavaScript browser client
- **Security-First**: Constant-time operations, comprehensive threat modeling, audit logging
- **Well-Tested**: Unit, integration, and cross-implementation tests
- **Production-Ready Patterns**: Interface-based design supports production backends

**What it IS:**
- Cryptographic proof-of-presence implementation
- SRP protocol library (RFC 5054)
- WebAuthn terminology (Attestation = registration, Assertion = authentication)

**What it is NOT:**
- Session management framework
- User account system
- Rate limiting solution
- Account recovery system

## Repository Structure

```
nopasswords/
├── pkg/                          # Core library code
│   ├── srp/                      # SRP protocol implementation
│   │   ├── manager.go            # Central orchestrator, thread-safe
│   │   ├── attestation.go        # Registration flow
│   │   ├── assertion.go          # Authentication flow (two-phase)
│   │   ├── config.go             # Functional options pattern
│   │   ├── groups.go             # RFC 5054 group parameters
│   │   ├── events.go             # Event definitions
│   │   ├── memory/               # Reference implementations (dev/test only)
│   │   └── *_test.go             # Unit and integration tests
│   └── core/                     # Core utilities
│       ├── events/               # Event logging system
│       │   ├── logging.go        # EventLogger interface
│       │   └── memory/           # In-memory logger implementations
│       └── errors/               # Custom error types
├── client/                       # TypeScript/JavaScript client
│   ├── src/srp/                  # SRP client implementation
│   │   ├── client.ts             # Main SRP client (WebCrypto API)
│   │   ├── groups.ts             # RFC 5054 groups (BigInt)
│   │   └── utils.ts              # Byte conversion helpers
│   ├── test/                     # Client tests
│   │   ├── unit/                 # Unit tests
│   │   ├── integration/          # Integration tests
│   │   └── cross-impl/           # Go-TS compatibility tests
│   ├── build.js                  # esbuild configuration (IIFE bundle)
│   └── dist/                     # Build artifacts (gitignored)
├── cmd/examples/                 # Example applications
│   └── srp-demo/                 # Working demo server + frontend
├── docs/                         # Documentation
│   ├── SECURITY.md               # Threat model, best practices
│   ├── ROADMAP.md                # Future plans
│   └── CODE_OF_CONDUCT.md        # Community guidelines
├── .github/workflows/            # CI/CD
│   ├── ci.yml                    # Main CI pipeline
│   └── release.yml               # Release automation
└── Makefile                      # Build automation
```

## Key Architectural Patterns

### 1. Dependency Injection

All external dependencies are injected via interfaces:

```go
type ParameterStore interface {
    StoreParameters(ctx context.Context, params Parameters) error
    RetrieveParameters(ctx context.Context, userID string) (Parameters, error)
}

type StateCache interface {
    Set(ctx context.Context, key string, value any, expiration time.Duration) error
    Get(ctx context.Context, key string, dest any) error
    Delete(ctx context.Context, key string) error
}

type EventLogger interface {
    LogEvent(ctx context.Context, event Event) error
}
```

**When adding features:**
- Define interfaces for external dependencies
- Provide in-memory reference implementations in `pkg/*/memory/`
- Document that memory implementations are for dev/test only

### 2. Functional Options Pattern

Configuration uses functional options:

```go
manager, err := srp.NewManager(
    srp.WithGroup(3),
    srp.WithEventLogger(logger),
    srp.WithStateCache(cache),
    srp.WithParameterStore(store),
)
```

**When adding configuration:**
- Add option functions following the `WithXxx()` pattern
- Provide sensible defaults
- Validate configuration in `NewManager()`

### 3. WebAuthn Terminology

Uses WebAuthn terms despite implementing SRP:

- **Attestation** = Registration/enrollment
- **Assertion** = Authentication/verification

**Reasoning:** Reflects that the library proves presence, not identity.

### 4. Two-Phase Authentication Flow

Assertion (authentication) is a two-phase process:

1. **Begin Phase** (`AssertionBeginHandler`):
   - Client requests challenge
   - Server generates ephemeral key B
   - Stores state in cache with expiration

2. **Verification Phase** (`AssertionVerificationHandler`):
   - Client submits proof (M1)
   - Server validates using cached state
   - Constant-time comparison prevents timing attacks
   - Calls success callback on validation

**When modifying authentication flow:**
- Preserve statelessness between phases (all state in cache)
- Maintain constant-time comparisons
- Clear state cache after verification (success or failure)

## Security Conventions

### Critical Security Practices

1. **Constant-Time Comparisons**
   ```go
   // Use subtle.ConstantTimeCompare for cryptographic comparisons
   if subtle.ConstantTimeCompare(expected, received) != 1 {
       return ErrInvalidProof
   }
   ```

2. **Cryptographic RNG**
   ```go
   // Always use crypto/rand, never math/rand
   import "crypto/rand"

   _, err := rand.Read(buffer)
   ```

3. **STRIDE Annotations**
   - Use `@risk` comments to identify threats
   - Use `@mitigation` comments to document countermeasures
   - Reference STRIDE categories: Spoofing, Tampering, Repudiation, Information Disclosure, DoS, Elevation of Privilege

4. **No Sensitive Data in Logs**
   - Event logging must NEVER include:
     - Passwords or password derivatives
     - Cryptographic keys (a, b, A, B, etc.)
     - Session tokens
   - OK to log: User IDs, timestamps, IP addresses, success/failure

### Security Review Checklist

When making changes to cryptographic code:
- [ ] Uses `crypto/rand` for random number generation
- [ ] Uses `subtle.ConstantTimeCompare` for secret comparisons
- [ ] No sensitive data in error messages or logs
- [ ] Input validation for untrusted data
- [ ] STRIDE annotations for new code paths
- [ ] Tests cover error conditions and edge cases

## Code Quality Standards

### Go Code Conventions

1. **Formatting**
   - Run `make fmt` before committing
   - Uses standard `go fmt`

2. **Linting**
   - Run `make lint` (golangci-lint)
   - Security-focused linters enabled (gosec, govet)
   - Cyclomatic complexity threshold: 20
   - Configuration in `.golangci.yml`

3. **Documentation**
   - Godoc comments on all exported types/functions
   - Include examples for complex functionality
   - Published to pkg.go.dev

4. **Error Handling**
   - Return errors, don't panic (except in `main()` setup)
   - Wrap errors with context: `fmt.Errorf("operation failed: %w", err)`
   - Use custom error types in `pkg/core/errors/`

5. **Testing**
   - Table-driven tests for multiple scenarios
   - Use testify for assertions
   - Integration tests in `integration_test.go`
   - Test files alongside source files (`*_test.go`)

### TypeScript Code Conventions

1. **Formatting**
   - Prettier for consistent formatting
   - Config in `.prettierrc.json`

2. **Linting**
   - ESLint with TypeScript plugin
   - Strict type checking enabled
   - No `console.log` (warn/error OK)
   - Config in `.eslintrc.json`

3. **Build**
   - esbuild for bundling
   - Output: IIFE format as `nopasswords.js`
   - Global name: `NoPasswords`
   - Minification + source maps

4. **Testing**
   - Vitest with jsdom environment
   - Unit tests: Individual functions
   - Integration tests: Full registration/auth flows
   - Cross-impl tests: Go-TypeScript compatibility

## Development Workflows

### Initial Setup

```bash
# Clone and setup
git clone <repo-url>
cd nopasswords
make dev  # Installs dependencies, builds client
```

### Daily Development

```bash
# Run tests
make test              # Go tests
make client-test       # TypeScript tests
make test-race         # Race detector
make test-coverage     # Coverage report

# Quality checks
make lint              # golangci-lint
make client-lint       # ESLint
make fmt               # Format code
make check             # All checks (fmt + vet + lint + test)

# Build examples
make examples          # Builds demo applications
cd cmd/examples/srp-demo && ./srp-demo  # Run demo on :8081
```

### Docker Development

```bash
# Interactive development environment
docker-compose up dev

# Run full CI suite
docker-compose up test

# Run demo server
docker-compose up srp-demo  # Available on :8081
```

### Making Changes

1. **Create feature branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make changes**
   - Follow existing code patterns
   - Add tests for new functionality
   - Update documentation if needed

3. **Quality checks**
   ```bash
   make check         # Run all checks
   make ci            # Full CI pipeline locally
   ```

4. **Commit**
   ```bash
   git add .
   git commit -m "feat: your feature description"
   ```

5. **Push and create PR**
   ```bash
   git push -u origin feature/your-feature-name
   ```

### CI/CD Pipeline

**CI Workflow** (`.github/workflows/ci.yml`):
- Triggers: Push to `main` or `claude/**`, PRs to `main`
- Jobs:
  1. `go-test`: fmt, lint, tests, race detector, coverage → Codecov
  2. `client-test`: lint, build, tests
  3. `examples`: Build example applications
  4. `security`: Trivy vulnerability scanning

**Release Workflow** (`.github/workflows/release.yml`):
- Trigger: Git tags `v*.*.*`
- Jobs:
  1. `create-release`: GitHub release
  2. `publish-npm`: Publish to npm
  3. `publish-docs`: Deploy to GitHub Pages

## Testing Guidelines

### Test Organization

1. **Unit Tests**
   - Test individual functions in isolation
   - Mock external dependencies
   - File naming: `*_test.go` (Go), `*.test.ts` (TypeScript)

2. **Integration Tests**
   - Test complete flows (attestation → assertion)
   - Use real implementations (not mocks)
   - File: `integration_test.go` or `test/integration/`

3. **Cross-Implementation Tests**
   - Verify Go-TypeScript compatibility
   - Test data serialization/deserialization
   - File: `client/test/cross-impl/`

### Test Coverage Expectations

- **Critical/sensitive functions**: 100% coverage (cryptographic operations)
- **Integration flows**: Complete coverage (attestation, assertion)
- **Error conditions**: All error paths tested
- **No strict coverage metrics**: Focus on meaningful tests

### Writing Tests

**Go Table-Driven Tests:**
```go
func TestFunction(t *testing.T) {
    tests := []struct {
        name    string
        input   Type
        want    Type
        wantErr bool
    }{
        {"valid input", validInput, expectedOutput, false},
        {"invalid input", invalidInput, nil, true},
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            got, err := Function(tt.input)
            if tt.wantErr {
                require.Error(t, err)
                return
            }
            require.NoError(t, err)
            assert.Equal(t, tt.want, got)
        })
    }
}
```

**TypeScript Tests:**
```typescript
describe('functionName', () => {
    it('should handle valid input', () => {
        const result = functionName(validInput);
        expect(result).toBe(expectedOutput);
    });

    it('should reject invalid input', () => {
        expect(() => functionName(invalidInput)).toThrow();
    });
});
```

## Common Tasks

### Adding a New Configuration Option

1. Add field to `Manager` struct in `manager.go`
2. Add `WithXxx()` option function in `config.go`
3. Update `NewManager()` to apply option
4. Add validation if needed
5. Update tests
6. Document in godoc comments

### Adding a New Event Type

1. Define event type in `events.go`
2. Add event emission in relevant code path
3. Update event logger tests
4. Document event in README.md observability section

### Modifying the SRP Protocol

⚠️ **WARNING**: Protocol changes require extreme care

1. Understand RFC 5054 implications
2. Add `@risk` and `@mitigation` comments
3. Update both Go and TypeScript implementations
4. Add cross-implementation tests
5. Update security documentation
6. Consider backwards compatibility

### Adding Storage Implementation

1. Create new package (e.g., `pkg/srp/redis/`)
2. Implement `ParameterStore` and/or `StateCache` interfaces
3. Add comprehensive tests
4. Document configuration and usage
5. Add example usage in README or `cmd/examples/`

## Important Gotchas

### 1. Memory Implementations Are Not Production-Ready

The `memory/` packages are reference implementations only:
- No persistence across restarts
- Not thread-safe for distributed systems
- Suitable for development/testing only

**When helping users:**
- Warn about production use
- Recommend implementing interfaces with real storage (Redis, PostgreSQL, etc.)

### 2. State Cache Expiration

Assertion state in cache has TTL (default 5 minutes):
- Too short: Users can't complete auth
- Too long: Memory bloat, security risk

**When modifying:**
- Keep TTL configurable
- Document recommended values
- Clean up state after verification

### 3. Constant-Time Comparisons Are Critical

Using `==` or `bytes.Equal` for cryptographic comparisons enables timing attacks.

**Always use:**
```go
import "crypto/subtle"

if subtle.ConstantTimeCompare(a, b) != 1 {
    // Not equal
}
```

### 4. Cross-Implementation Compatibility

Go and TypeScript implementations must produce identical results:
- Same hash algorithm (SHA-256)
- Same byte ordering (big-endian for BigInt)
- Same padding schemes
- Same group parameters

**When changing crypto code:**
- Update both implementations
- Run cross-implementation tests
- Test with different platforms/architectures

### 5. HTTP Handler Patterns

HTTP handlers use functional callbacks for application logic:

```go
http.HandleFunc("/api/login/finish", manager.AssertionVerificationHandler(
    func(userID string, w http.ResponseWriter, r *http.Request) error {
        // Application-specific logic here
        // Create session, issue tokens, etc.
        return nil
    },
))
```

**When adding handlers:**
- Follow this pattern
- Keep library code generic
- Let application handle business logic
- Return errors for library to handle HTTP status

## AI Assistant Best Practices

### When Asked to Add Features

1. **Read existing code first**
   - Understand patterns and conventions
   - Match existing style and architecture
   - Check for similar existing functionality

2. **Consider interfaces**
   - Will this require a new interface?
   - Should this be injected or configured?
   - Is this application-specific or library-generic?

3. **Security implications**
   - Does this handle sensitive data?
   - Could this introduce timing attacks?
   - Should this be logged/audited?

4. **Testing strategy**
   - What are the critical paths?
   - What error conditions exist?
   - Does this affect Go-TypeScript compatibility?

5. **Documentation updates**
   - Godoc/JSDoc comments
   - README examples if user-facing
   - Security documentation if relevant

### When Asked to Debug

1. **Gather context**
   - Read relevant source files
   - Check test files for expected behavior
   - Review recent git history if relevant

2. **Check common issues**
   - Memory implementations in production?
   - State cache expiration?
   - CORS configuration?
   - TLS/HTTPS in production?

3. **Review security**
   - Constant-time comparisons used?
   - Cryptographic RNG used?
   - No sensitive data in logs?

### When Asked to Refactor

1. **Don't over-engineer**
   - Keep solutions simple and focused
   - Avoid premature abstractions
   - Don't add features beyond the request

2. **Maintain compatibility**
   - Don't break public APIs
   - Consider backwards compatibility
   - Update both Go and TypeScript if needed

3. **Preserve security properties**
   - Don't weaken constant-time comparisons
   - Don't change cryptographic algorithms without analysis
   - Maintain audit logging

## Resources

- **RFC 5054**: SRP protocol specification
- **STRIDE Model**: Threat modeling framework
- **WebAuthn Spec**: For terminology and future WebAuthn support
- **Go Best Practices**: https://go.dev/doc/effective_go
- **TypeScript Handbook**: https://www.typescriptlang.org/docs/

## Getting Help

- **Code Documentation**: https://pkg.go.dev/go.fergus.london/nopasswords
- **Examples**: `cmd/examples/srp-demo/`
- **Security**: `docs/SECURITY.md`
- **Contributing**: Submit PRs with tests
- **Issues**: GitHub issues for bugs/features

## Version Information

- **Go**: 1.24.0+
- **TypeScript**: 5.7.2
- **Node.js**: 20+ (for client build)
- **golangci-lint**: v1.61.0

## License

MIT License - See LICENSE file for details.

---

**Last Updated**: 2025-11-22

This document should be updated when:
- Major architectural changes occur
- New conventions are established
- Significant features are added
- Security practices evolve
