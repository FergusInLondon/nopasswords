# SRP Demo

This is a demonstration of the Secure Remote Password (SRP) protocol implementation from the NoPasswords library.

## About SRP

SRP is a cryptographic protocol that allows password-based authentication without transmitting passwords or storing password-equivalent data on the server. Key features:

- **Zero-Knowledge Proof**: The server never sees the password, not even during registration
- **Mutual Authentication**: Both client and server prove knowledge of the password
- **Forward Secrecy**: Each session derives a unique session key
- **Resistance to Offline Attacks**: Even if the database is compromised, passwords cannot be recovered

## Running the Demo

1. Build and run the server:
   ```bash
   cd examples/srp-demo
   go run main.go
   ```

2. Open your browser to: http://localhost:8081

## How It Works

### Registration Flow

1. **Client Side**:
   - Generates random salt (256 bits)
   - Computes `x = H(salt | H(userID | ":" | password))`
   - Computes verifier `v = g^x mod N`
   - Sends salt and verifier to server

2. **Server Side**:
   - Stores salt and verifier for the user
   - Password is never seen or stored

### Authentication Flow

1. **Begin Authentication** (Client → Server):
   - Client requests authentication for userID
   - Server responds with salt and public ephemeral value `B`

2. **Client Computation**:
   - Generates private ephemeral `a` (random 256 bits)
   - Computes public ephemeral `A = g^a mod N`
   - Derives session key `S` using SRP-6a protocol
   - Computes session key `K = H(S)`
   - Computes proof `M1 = H(A | B | K)`

3. **Finish Authentication** (Client → Server):
   - Client sends `A` and `M1` to server
   - Server verifies `M1` (constant-time comparison)
   - Server computes proof `M2 = H(A | M1 | K)`
   - Server responds with `M2`

4. **Client Verification**:
   - Client verifies server's `M2`
   - Both parties now share session key `K`

## Security Considerations

⚠️ **This is a demo application** ⚠️

Production deployments should implement:

- **Persistent Storage**: Use a proper database instead of in-memory storage
- **HTTPS**: Always use TLS for production
- **Session Management**: Implement proper session handling with the derived key
- **Rate Limiting**: Prevent brute-force attempts
- **CSRF Protection**: Implement CSRF tokens
- **Input Validation**: Validate all user inputs
- **Logging**: Monitor authentication attempts
- **Password Policy**: Enforce strong password requirements

## Group Parameters

The demo uses RFC5054 Group 3 (2048-bit prime). Available groups:

- Group 3: 2048-bit (recommended minimum)
- Group 4: 3072-bit (stronger, slower)
- Group 5: 4096-bit (strongest, slowest)

## API Endpoints

### POST `/api/srp/register`
Register a new user.

**Request:**
```json
{
  "user_id": "user@example.com",
  "salt": "base64-encoded-salt",
  "verifier": "base64-encoded-verifier",
  "group": 3
}
```

**Response:**
```json
{
  "success": true,
  "user_id": "user@example.com"
}
```

### POST `/api/srp/authenticate/begin`
Start authentication process.

**Request:**
```json
{
  "user_id": "user@example.com",
  "group": 3
}
```

**Response:**
```json
{
  "salt": "base64-encoded-salt",
  "b": "base64-encoded-B",
  "group": 3
}
```

### POST `/api/srp/authenticate/finish`
Complete authentication process.

**Request:**
```json
{
  "user_id": "user@example.com",
  "a": "base64-encoded-A",
  "m1": "base64-encoded-M1"
}
```

**Response:**
```json
{
  "success": true,
  "m2": "base64-encoded-M2"
}
```

## Client Library

The demo HTML includes placeholder code. For production use, install the TypeScript client library:

```bash
cd client-srp
npm install
npm run build
```

Then include in your HTML:
```html
<script src="dist/nopasswords-srp.js"></script>
<script>
  const client = new NoPasswordsSRP.SRPClient({
    group: 3,
    baseURL: 'https://api.example.com'
  });

  // Registration
  const regResult = await client.register('user@example.com', 'password');

  // Authentication
  const authResult = await client.authenticate('user@example.com', 'password');
  const sessionKey = authResult.sessionKey; // Use for session management
</script>
```

## References

- [RFC 5054: Using SRP for TLS Authentication](https://tools.ietf.org/html/rfc5054)
- [RFC 2945: The SRP Authentication and Key Exchange System](https://tools.ietf.org/html/rfc2945)
- [SRP Design](http://srp.stanford.edu/design.html)
