# Security

## Threat Model

NoPasswords addresses threats from the STRIDE model:

- **Spoofing**: Strong cryptographic signatures, WebAuthn origin validation
- **Tampering**: Signature verification, protocol integrity checks
- **Repudiation**: Comprehensive audit logging via the EventLogger interface
- **Information Disclosure**: No credential storage in plaintext, constant-time comparisons for timing attack prevention
- **Denial of Service**: Rate limiting guidance, session timeouts
- **Elevation of Privilege**: Challenge validation, session key protection

Identified threats are labelled within the codebase via the use of `@risk` and `@mitigation` comments.

## Security Best Practices

### Implementation Guidelines

1. **Storage Security**
   - Implement your `ParameterStore` with appropriate database security
   - Use encrypted connections to your storage backend
   - Consider encryption at rest for sensitive credential data

2. **Audit Logging**
   - Implement the `EventLogger` interface to capture security events
   - Store audit logs securely and protect against tampering
   - Monitor logs for suspicious authentication patterns

3. **Network Security**
   - Always use HTTPS/TLS in production
   - Implement appropriate CORS policies
   - Consider additional rate limiting at the network/application level

4. **Session Management**
   - Session management is the implementer's responsibility
   - Use secure, httpOnly cookies for session tokens
   - Implement appropriate session timeouts
   - Invalidate sessions on logout

### Cryptographic Implementation

- **SRP**: Implements RFC5054 with groups 3, 4, and 5 (2048/3072/4096-bit)
- **Constant-time operations**: Critical comparisons use constant-time algorithms to prevent timing attacks
- **Random number generation**: Uses `crypto/rand` for all cryptographic random number generation

## Reporting Security Issues

**Please report security vulnerabilities to @FergusInLondon.**

**Do not** open public GitHub issues for security vulnerabilities.

When communicating a potential vulnerability, please include the following details:

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested remediation (if any)
