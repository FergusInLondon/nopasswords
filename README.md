# NoPasswords

[![CI](https://github.com/FergusInLondon/nopasswords/workflows/CI/badge.svg)](https://github.com/FergusInLondon/nopasswords/actions)
[![Go Report Card](https://goreportcard.com/badge/go.fergus.london/nopasswords)](https://goreportcard.com/report/go.fergus.london/nopasswords)
[![GoDoc](https://pkg.go.dev/badge/go.fergus.london/nopasswords)](https://pkg.go.dev/go.fergus.london/nopasswords)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A comprehensive, production-ready Go library for passwordless authentication supporting multiple methods: WebAuthn/FIDO2, and Secure Remote Password (SRP).

## Features

- **🔐 Multiple Authentication Methods**
  - **WebAuthn/FIDO2**: Hardware tokens, platform authenticators (Touch ID, Windows Hello), security keys
  - **SRP (RFC5054)**: Zero-knowledge password proof without transmitting passwords

- **🏗️ Unopinionated Architecture**
  - Dependency injection for storage and logging
  - No forced opinions about databases, logging, or metrics
  - Easy integration with existing infrastructure

- **🔒 Security First**
  - Comprehensive audit logging
  - STRIDE threat model coverage
  - Constant-time comparisons
  - Cryptographic best practices

- **📦 Production Ready**
  - Extensive test coverage with race detection
  - TypeScript client libraries included
  - Complete working examples
  - Comprehensive documentation

## Quick Start

### Example: WebAuthn

See [`examples/webauthn-demo/`](examples/webauthn-demo/) for a complete working example with client and server code.

### Example: SRP

See [`examples/srp-demo/`](examples/srp-demo/) for a complete working example with client and server code.

## Development Setup

### Prerequisites

- Go 1.23 or later
- Node.js 20 or later
- Make
- Docker (optional, for containerized development)

### Local Development

```bash
# Clone the repository
git clone https://github.com/FergusInLondon/nopasswords.git
cd nopasswords

# Set up development environment
make dev

# Run tests
make test

# Run tests with race detector
make test-race

# Run linters
make lint

# Build everything (Go + TypeScript)
make all

# Build and run examples
make examples
```

### Docker Development

```bash
# Start development environment
docker compose up dev

# Run tests in container
docker compose run test

# Run WebAuthn example
docker compose up webauthn-demo
# Visit http://localhost:8080
```

## Project Structure

```
nopasswords/
├── core/               # Core interfaces and types
│   ├── memory/        # In-memory reference implementations
│   └── *.go           # Shared types and interfaces
├── webauthn/          # WebAuthn/FIDO2 implementation
├── srp/               # Secure Remote Password implementation
├── client/            # TypeScript WebAuthn client library
├── client-srp/        # TypeScript SRP client library
├── examples/          # Working example applications
│   ├── webauthn-demo/
│   ├── srp-demo/
│   └── audit-logging/
├── .github/           # GitHub Actions workflows
└── Makefile           # Build automation
```

## Architecture

NoPasswords uses a **dependency injection** pattern for maximum flexibility:

1. **Core Interfaces**: Define contracts for storage and logging
2. **Reference Implementations**: In-memory stores for development/testing
3. **Production Integration**: Implement interfaces with your database, logging, etc.

### Key Interfaces

- **`CredentialStore`**: Store and retrieve authentication credentials
- **`AuditLogger`**: Security event logging

See [`core/interfaces.go`](core/interfaces.go) for full interface definitions.

## Security

### Threat Model

NoPasswords addresses threats from the STRIDE model:

- **Spoofing**: Strong cryptographic signatures, WebAuthn origin validation
- **Tampering**: Signature verification, protocol integrity checks
- **Repudiation**: Comprehensive audit logging
- **Information Disclosure**: No credential storage in plaintext, timing attack prevention
- **Denial of Service**: Rate limiting guidance, session timeouts
- **Elevation of Privilege**: Challenge validation, session key protection

### Reporting Security Issues

Please report security vulnerabilities to [security@fergus.london](mailto:security@fergus.london).

**Do not** open public GitHub issues for security vulnerabilities.

## Testing

```bash
# Run all tests
make test

# Run tests with race detector
make test-race

# Generate coverage report
make test-coverage

# Run linters
make lint

# Run complete CI pipeline
make ci
```

## Client Libraries

TypeScript client libraries are available for browser-based authentication:

- **WebAuthn**: [`client/`](client/) - Published as `@nopasswords/webauthn-client`
- **SRP**: [`client-srp/`](client-srp/) - Published as `@nopasswords/srp-client`

Both libraries:
- Zero dependencies (except build tools)
- TypeScript with full type definitions
- Single IIFE bundle for easy integration
- Comprehensive error handling

## Examples

All examples are in [`examples/`](examples/):

- **[webauthn-demo](examples/webauthn-demo/)**: Complete WebAuthn registration and authentication
- **[srp-demo](examples/srp-demo/)**: Complete SRP registration and authentication
- **[audit-logging](examples/audit-logging/)**: Audit logging patterns and integration

⚠️ **Examples are for demonstration only. Do not use in production without proper security hardening.**

## Documentation

- **[Godoc](https://pkg.go.dev/go.fergus.london/nopasswords)**: Complete API documentation
- **[INITIAL_IMPLEMENTATION.md](INITIAL_IMPLEMENTATION.md)**: Feature specifications and requirements
- **[CHANGELOG.md](CHANGELOG.md)**: Detailed implementation history with security notes
- **[CONTRIBUTING.md](CONTRIBUTING.md)**: Development guidelines
- **[PROJECT_OVERVIEW.md](PROJECT_OVERVIEW.md)**: High-level project overview
- **[ROADMAP.md](ROADMAP.md)**: Future development plans

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Development Workflow

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Run tests and linters (`make check`)
5. Commit your changes (`git commit -m 'Add amazing feature'`)
6. Push to the branch (`git push origin feature/amazing-feature`)
7. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [go-webauthn/webauthn](https://github.com/go-webauthn/webauthn) - WebAuthn library foundation
- RFC5054 - Secure Remote Password specification
- The passwordless authentication community

## Roadmap

See [ROADMAP.md](ROADMAP.md) for planned features and enhancements.

## Support

- **Documentation**: [pkg.go.dev](https://pkg.go.dev/go.fergus.london/nopasswords)
- **Issues**: [GitHub Issues](https://github.com/FergusInLondon/nopasswords/issues)
- **Discussions**: [GitHub Discussions](https://github.com/FergusInLondon/nopasswords/discussions)

---

**Built with ❤️ for secure, passwordless authentication**
