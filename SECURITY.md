# Security

## Threat Model

NoPasswords addresses threats from the STRIDE model:

- **Spoofing**: Strong cryptographic signatures, WebAuthn origin validation
- **Tampering**: Signature verification, protocol integrity checks
- **Repudiation**: Comprehensive audit logging via the EventLogger interface
- **Information Disclosure**: No credential storage in plaintext, constant-time comparisons for timing attack prevention
- **Denial of Service**: Rate limiting guidance, session timeouts
- **Elevation of Privilege**: Challenge validation, session key protection

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
   - See the [audit-logging example](examples/audit-logging/) for integration patterns

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

**Please report security vulnerabilities to [security@fergus.london](mailto:security@fergus.london).**

**Do not** open public GitHub issues for security vulnerabilities.

We take security seriously and will respond to valid reports as quickly as possible. Please include:

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested remediation (if any)

## Security Considerations for Examples

⚠️ **The example applications in this repository are for demonstration purposes only.**

Before using any example code in production:

1. Implement proper session management
2. Add rate limiting to authentication endpoints
3. Use production-grade storage implementations (not in-memory stores)
4. Configure appropriate CORS policies
5. Enable comprehensive audit logging
6. Review and test all security controls
7. Consider security testing and penetration testing

## Responsible Disclosure

We follow responsible disclosure practices. If you report a vulnerability:

1. We will acknowledge receipt within 48 hours
2. We will provide an estimated timeline for a fix
3. We will notify you when the fix is released
4. We will credit you in the security advisory (unless you prefer to remain anonymous)

Thank you for helping keep NoPasswords secure.
