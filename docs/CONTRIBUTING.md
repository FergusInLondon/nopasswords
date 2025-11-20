# Contributing to NoPasswords

Thank you for your interest in contributing to NoPasswords! This document provides guidelines and information for contributors.

## Code of Conduct

This project adheres to a [Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code.

## Getting Started

### Prerequisites

- Go 1.23 or later
- Node.js 20 or later
- Make
- Git
- golangci-lint (optional, but recommended)

### Development Setup

1. **Fork the repository**

   Click the "Fork" button on GitHub to create your own copy.

2. **Clone your fork**

   ```bash
   git clone https://github.com/YOUR_USERNAME/nopasswords.git
   cd nopasswords
   ```

3. **Add upstream remote**

   ```bash
   git remote add upstream https://github.com/FergusInLondon/nopasswords.git
   ```

4. **Set up development environment**

   ```bash
   make dev
   ```

   This will:
   - Download Go dependencies
   - Install npm dependencies for client libraries
   - Build client libraries

5. **Verify setup**

   ```bash
   make check
   ```

   This runs formatters, linters, and tests.

## Development Workflow

### 1. Create a Feature Branch

```bash
git checkout -b feature/your-feature-name
```

Use descriptive branch names:
- `feature/add-totp-support`
- `fix/webauthn-timeout-issue`
- `docs/improve-srp-examples`
- `refactor/simplify-audit-logger`

### 2. Make Your Changes

Follow these guidelines:

#### Go Code

- Follow [Effective Go](https://golang.org/doc/effective_go) conventions
- Run `make fmt` before committing
- Ensure `make lint` passes
- Add tests for new functionality
- Update godoc comments for public APIs

#### TypeScript Code

- Follow existing code style
- Run `make client-lint` before committing
- Use TypeScript's strict mode
- Add JSDoc comments for public APIs

#### Tests

- Write unit tests for new code
- Aim for >80% code coverage
- Use table-driven tests where appropriate
- Test error conditions, not just happy paths

### 3. Commit Your Changes

Write clear, descriptive commit messages following the [Conventional Commits](https://www.conventionalcommits.org/) specification:

```
<type>(<scope>): <subject>

<body>

<footer>
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting, etc.)
- `refactor`: Code refactoring
- `test`: Adding or updating tests
- `chore`: Maintenance tasks

**Examples:**

```
feat(webauthn): add support for user verification levels

Adds configuration option for user verification: required, preferred, discouraged.
Updates client library to respect server configuration.

Closes #123
```

```
fix(srp): prevent timing attack in M1 verification

Use constant-time comparison for client proof verification.
Addresses security vulnerability identified in audit.

Refs #456
```

### 4. Push and Create Pull Request

```bash
git push origin feature/your-feature-name
```

Then create a Pull Request on GitHub. Fill out the PR template completely.

## Code Review Process

1. **Automated Checks**: CI must pass (linting, tests, builds)
2. **Manual Review**: At least one maintainer approval required
3. **Security Review**: Security-sensitive changes require additional review
4. **Documentation**: Significant features require documentation updates

### Review Checklist

- [ ] Code follows project style guidelines
- [ ] Tests added/updated and passing
- [ ] Documentation updated (godoc, README, examples)
- [ ] CHANGELOG.md updated (for significant changes)
- [ ] Security implications considered and documented
- [ ] Breaking changes clearly marked

## Testing

### Running Tests

```bash
# All tests
make test

# With race detector
make test-race

# With coverage
make test-coverage

# Specific package
go test -v ./core/...
```

### Writing Tests

Follow these patterns:

**Unit Tests:**

```go
func TestFeature(t *testing.T) {
    tests := []struct {
        name    string
        input   string
        want    string
        wantErr bool
    }{
        {"valid input", "test", "result", false},
        {"invalid input", "", "", true},
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            got, err := Feature(tt.input)
            if (err != nil) != tt.wantErr {
                t.Errorf("Feature() error = %v, wantErr %v", err, tt.wantErr)
                return
            }
            if got != tt.want {
                t.Errorf("Feature() = %v, want %v", got, tt.want)
            }
        })
    }
}
```

**Using testify:**

```go
func TestWithTestify(t *testing.T) {
    result, err := Feature("input")
    require.NoError(t, err)
    assert.Equal(t, "expected", result)
}
```

## Documentation

### Godoc Comments

All public APIs must have godoc comments:

```go
// Manager handles token generation and verification.
// It uses pluggable signers for cryptographic operations
// and integrates with audit logging.
//
// Manager is safe for concurrent use.
type Manager struct {
    // ...
}

// GenerateToken creates a new signed token for the given user.
// The token will expire after the configured default lifetime.
//
// Returns an error if the user ID is empty or token generation fails.
func (m *Manager) GenerateToken(userID string) (string, error) {
    // ...
}
```

### Security Comments

Document security considerations with `@risk` and `@mitigation` tags:

```go
// @risk Tampering: Weak signing keys allow token forgery
// @mitigation: Enforce minimum key length of 256 bits
if len(key) < 32 {
    return nil, ErrInsufficientKeyLength
}
```

### Examples

Add runnable examples to `*_test.go` files:

```go
func ExampleManager_GenerateToken() {
    signer, _ := NewHMACSignerSHA256([]byte("secret-key-min-32-bytes-long!!!"))
    manager, _ := NewManager(WithSigner(signer))

    token, _ := manager.GenerateToken("user@example.com", nil)
    fmt.Println("Generated token:", token)
    // Output: Generated token: (token string)
}
```

## Security

### Reporting Vulnerabilities

**Do NOT open public issues for security vulnerabilities.**

Email security@fergus.london with:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

### Security Considerations

When contributing, consider:

1. **Cryptography**: Use standard library crypto primitives
2. **Timing Attacks**: Use `subtle.ConstantTimeCompare` for sensitive comparisons
3. **Input Validation**: Validate all inputs, especially from untrusted sources
4. **Error Messages**: Don't leak sensitive information in errors
5. **Logging**: Never log passwords, keys, or tokens
6. **Dependencies**: Minimize external dependencies, vet carefully

## Style Guide

### Go

- Follow `gofmt` and `goimports` formatting
- Use meaningful variable names (no single letters except loop counters)
- Keep functions small and focused
- Prefer composition over inheritance
- Return errors, don't panic (except in truly exceptional cases)

### TypeScript

- Use strict mode
- Prefer `const` over `let`, never use `var`
- Use TypeScript types, avoid `any`
- Follow existing code style
- Use async/await over promise chains

### Comments

- Write comments that explain *why*, not *what*
- Keep comments up to date with code changes
- Use complete sentences with proper punctuation
- Document all public APIs

## Building and Releasing

### Version Numbering

NoPasswords follows [Semantic Versioning](https://semver.org/):

- **MAJOR**: Breaking API changes
- **MINOR**: New features, backward compatible
- **PATCH**: Bug fixes, backward compatible

### Release Process

1. Update `CHANGELOG.md` with release notes
2. Update version in `client/package.json` and `client-srp/package.json`
3. Create and push a git tag: `git tag v1.2.3 && git push --tags`
4. GitHub Actions will automatically:
   - Create a GitHub release
   - Publish npm packages
   - Update documentation

## Getting Help

- **Questions**: Open a [GitHub Discussion](https://github.com/FergusInLondon/nopasswords/discussions)
- **Bugs**: Open a [GitHub Issue](https://github.com/FergusInLondon/nopasswords/issues)
- **Documentation**: Check [pkg.go.dev](https://pkg.go.dev/go.fergus.london/nopasswords)

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

---

Thank you for contributing to NoPasswords! 🎉
