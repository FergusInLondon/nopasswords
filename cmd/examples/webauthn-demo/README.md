# WebAuthn Demo

A simple demonstration of the NoPasswords WebAuthn implementation.

## Running the Demo

1. Build the TypeScript client library (if not already built):
   ```bash
   cd ../../client
   npm install
   npm run build
   ```

2. Run the demo server:
   ```bash
   cd ../examples/webauthn-demo
   go run main.go
   ```

3. Open your browser to `http://localhost:8080`

## Features Demonstrated

- **Registration**: Create a new WebAuthn credential using a hardware key, platform authenticator (Touch ID/Windows Hello), or security key
- **Authentication**: Authenticate using a registered credential
- **Browser Detection**: Automatic detection of WebAuthn support and platform authenticator availability

## Notes

- This is a simplified demo for development purposes
- The server uses in-memory storage and basic session management
- In production, you should:
  - Use secure, distributed session storage
  - Implement proper CSRF protection
  - Use HTTPS
  - Implement rate limiting
  - Add proper error handling and logging
  - Store credentials in a persistent database

## Security Considerations

The demo includes security annotations (`@risk`, `@mitigation`) highlighting security considerations:
- Session management is simplified for demo purposes
- Origin validation is handled by the browser and server
- Credential verification should use proper protocol parsing in production
