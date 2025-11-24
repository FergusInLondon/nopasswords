# NoPasswords

[![CI](https://github.com/FergusInLondon/nopasswords/workflows/CI/badge.svg)](https://github.com/FergusInLondon/nopasswords/actions)
[![Go Report Card](https://goreportcard.com/badge/go.fergus.london/nopasswords)](https://goreportcard.com/report/go.fergus.london/nopasswords)
[![GoDoc](https://pkg.go.dev/badge/go.fergus.london/nopasswords)](https://pkg.go.dev/go.fergus.london/nopasswords)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A Go library for passwordless authentication using Secure Remote Password (SRP) protocol. Simple, opinionless, and built for easy integration.

> **Note**: Currently implements SRP (RFC5054). WebAuthn support is in development.

## Why NoPasswords?

This isn't an authentication/authorization framework—it's a **proof of presence** library. It handles the cryptographic complexity of verifying someone can prove they possess a credential, without prescribing how you structure your auth flows, sessions, or user management.

## Features

- **🔐 SRP Protocol (RFC5054)**: Zero-knowledge password proof supporting 2048, 3072, and 4096-bit groups.
- **🏗️ Opinionless Design**: Dependency injection for storage and logging—bring your own database and logging infrastructure.
- **📊 Observable**: Built-in event logging interface with structured events for debugging and security monitoring.
- **✅ Well-Tested**: Complete test coverage of authentication flows, with granular unit test coverage of critical/sensitive functions.
- **📦 TypeScript Client**: Browser-ready SRP client library included.

## Terminology

NoPasswords uses generic terminology to avoid any confusion:

- **Attestation**: The registration/enrollment process where a user creates a new credential
- **Assertion**: The authentication/verification process where a user proves possession of their credential

This terminology reflects that the library proves presence rather than handling full authentication flows.

## Quick Start

### Server Setup

```go
package main

import (
    "fmt"
    "net/http"

    "go.fergus.london/nopasswords/pkg/srp"
    srpmem "go.fergus.london/nopasswords/pkg/srp/memory"
    coremem "go.fergus.london/nopasswords/pkg/core/events/memory"
)

func main() {
    // Initialize SRP manager with your implementations
    manager, err := srp.NewManager(
        srp.WithGroup(3),  // 2048-bit group
        srp.WithEventLogger(coremem.NewStdoutLogger(true)),
        srp.WithStateCache(srpmem.NewInMemoryStateCache()),
        srp.WithParameterStore(srpmem.NewInMemoryParameterStore()),
    )
    if err != nil {
        panic(err)
    }

    // Attestation (registration) endpoint
    http.HandleFunc("/api/register", manager.AttestationHandlerFunc(
        func(params srp.Parameters) {
            fmt.Printf("User registered: %s\n", params.UserIdentifier)
            // Store user etc.
        },
    ))

    // Assertion (authentication) endpoints
    http.HandleFunc("/api/login/begin", manager.AssertionBeginHandler())
    http.HandleFunc("/api/login/finish", manager.AssertionVerificationHandler(
        func(userID string, w http.ResponseWriter, r *http.Request) error {
            fmt.Printf("User authenticated: %s\n", userID)
            // Create session, issue tokens, etc.
            return nil
        },
    ))

    http.ListenAndServe(":8080", nil)
}
```

### Client Setup (TypeScript)

```typescript
import { SRPClient } from '@nopasswords/srp-client';

// Registration
const client = new SRPClient({
    group: 3,
    attestationPath: "/api/register",
    assertionInitiationPath: "/api/login/begin",
    assertionCompeltionPath: "/api/login/finish"
});
await client.attest('user@example.com', 'password');

// Authentication
const authClient = new SRPClient({
    group: 3,
    attestationPath: "/api/register",
    assertionInitiationPath: "/api/login/begin",
    assertionCompeltionPath: "/api/login/finish"
});
await authClient.authenticate('user@example.com', 'password');
```

See [cmd/examples/srp-demo](cmd/examples/srp-demo) for a complete working example with client and server code.

## Core Interfaces

NoPasswords uses dependency injection for flexibility. Implement these interfaces with your infrastructure:

- **`ParameterStore`**: Persist user SRP parameters (verifier, salt)
- **`StateCache`**: Temporarily store protocol state during authentication
- **`EventLogger`**: Capture security events for monitoring and debugging

Reference implementations using in-memory storage are provided for development and testing. See [pkg/srp/memory](pkg/srp/memory) and [pkg/core/events/memory](pkg/core/events/memory).

## Observability & Debugging

The library provides comprehensive observability through the `EventLogger` interface:

- Structured events for all authentication operations
- Success/failure events with contextual metadata
- Request context (IP, user agent, etc.)
- No sensitive data in logs (passwords, keys, etc.)

Events include:
- `attestation.attempt` / `attestation.success` / `attestation.failure`
- `assertion.attempt` / `assertion.success` / `assertion.failure`

Use the included stdout logger for development, or implement the interface for your logging infrastructure (slog, zap, logrus, etc.).

## Testing

The library has complete test coverage of all authentication flows:

```bash
# Run all tests
make test

# Run with race detector
make test-race

# Run linters
make lint
```

Tests cover protocol correctness, concurrent usage, error conditions, and cross-language compatibility with the TypeScript client.

## Documentation

- 📖 **[API Documentation](https://pkg.go.dev/go.fergus.london/nopasswords)**: Complete Go API reference
- 📁 **[docs/](docs/)**: Additional documentation including security guidance and roadmap ideas.
- 💡 **[cmd/examples/srp-demo](cmd/examples/srp-demo)**: Complete working example

## What This Library Does NOT Do

NoPasswords is intentionally focused. It does **not** handle:

- Session management (use your existing session infrastructure)
- Rate limiting (implement at your application/network layer)
- User account creation/management
- Account recovery flows
- Email/SMS delivery for magic links

These are your application's responsibility. _NoPasswords handles the cryptographic proof; you handle the business logic._

## Security

See [SECURITY.md](SECURITY.md) for:
- Threat model and mitigations
- Security best practices
- Vulnerability reporting

## Contributing

Contributions welcome - simply submit a Pull Request. I do ask that tests are included for any sensitive/critical operations, but there are no requirements for adhering to specific test coverage metrics.

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Roadmap

- 🚧 `RedisParameterStore` and `RedisStateCache` implementations (in progress)
- 🚧 WebAuthn/FIDO2 support (in progress)
- MFA - TOTP and WebAuthn 

See [docs/ROADMAP.md](docs/ROADMAP.md) for detailed plans.
