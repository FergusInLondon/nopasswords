package srp

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"time"

	"go.fergus.london/nopasswords/pkg/core/events"
)

// AssertionState represents the server-side state during an SRP authentication flow.
// This must be stored between the Begin and Finish steps.
//
// Security Considerations:
// @risk Elevation of Privilege: Session data must be protected against tampering.
// Store sessions securely (e.g., encrypted, signed, in server memory with timeout).
//
// @risk Denial of Service: Sessions must have expiration to prevent resource exhaustion.
type AssertionState struct {
	// InitiatedAt represents the time of the initial request.
	InitiatedAt time.Time

	// Group identifies which RFC5054 group is being used
	Group int `json:"group"`

	// b is the server's private ephemeral value (kept secret)
	// @risk Information Disclosure: Never serialize or expose private ephemeral value
	b *big.Int

	// B is the server's public ephemeral value (sent to client)
	B *big.Int `json:"B"`

	// v is the verifier value from storage
	// @risk Information Disclosure: Never serialize or expose verifier directly
	v *big.Int
}

// AssertionInitiationRequest initiates an SRP authentication flow.
type AssertionInitiationRequest struct {
	// UserID identifies the user attempting to authenticate
	UserIdentifier string `json:"identifier"`

	// Group identifies which RFC5054 group to use (optional, server can choose)
	Group int `json:"group,omitempty"`
}

// AssertionInitiationResponse contains the server's initial authentication response.
type AssertionInitiationResponse struct {
	// Salt is the user's salt from registration
	Salt []byte `json:"salt"`

	// B is the server's public ephemeral value
	B []byte `json:"b"`

	// Group identifies which RFC5054 group is being used
	Group int `json:"group"`
}

// AssertionBeginHandler handles the initial request of the SRP assertion flow.
//
// Request 1. Client makes an initial request containing two fields:
//
//	an identifier associated with the user, and the SRP
//	"group" (which signifies cryptographic properties to use).
//
// Processing Steps:
//
//	-> Request Validation: HTTP Method and Payload Validity (i.e. JSON)
//	  -> is POST request?
//	  -> is valid JSON?
//	  -> has user identifier?
//	-> Get Parameters associated with the user_id
//	  -> Salt, Verifier, Group
//	-> Verify that the Verifier Group and Request Group match
//	-> Generate Server Ephmeral Values
//	-> Cache AssertionState
//	  -> UserIdentifier -> [Group, b, B, v]
//	-> Return Response
//
// Response: The Server responds with the Salt value associated with
//
//	that user, `B` which is the server's public ephemeral value,
//	and confirmation of the "group".
//
// Security Considerations:
// @risk Elevation of Privilege: Ephemeral value b must be cryptographically random.
// @risk Denial of Service: Sessions must expire to prevent resource exhaustion.
func (m *Manager) AssertionBeginHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		eventStream := newBuildableEvent(
			r.Context(), m.config.AuditLogger, events.GenerateEventID(),
		)
		eventOutcome := events.OutcomeFailure

		startTime := time.Now()
		defer func() {
			eventStream.log(events.EventAuthAttempt, eventOutcome, "assertion_initiated", map[string]interface{}{
				"group":    m.config.Group,
				"duration": time.Since(startTime).Milliseconds(),
			})
		}()

		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req AssertionInitiationRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request", http.StatusBadRequest)
			return
		}

		if req.UserIdentifier == "" {
			eventStream.log(events.EventAuthAttempt, eventOutcome, "empty_user_id", nil)
			http.Error(w, "user identifier cannot be empty", http.StatusBadRequest)
			return
		}
		eventStream.withUserIdentifier(req.UserIdentifier)

		assertionParams, err := m.config.Store.GetForUserIdentifier(req.UserIdentifier)
		if err != nil {
			eventStream.log(events.EventAuthAttempt, eventOutcome, "no_assertion_params", nil)
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		// IDEA: I mean, we support multiple groups. Should we have a way of allowing this?
		//  i.e. for in-place upgrades?
		if assertionParams.Group != m.config.Group {
			eventStream.log(
				events.EventAuthAttempt, eventOutcome, "group_mismatch", map[string]interface{}{
					"stored_group":   assertionParams.Group,
					"expected_group": m.config.Group,
				},
			)
			http.Error(w, fmt.Sprintf("group mismatch: expected %d, got %d", m.config.Group, assertionParams.Group), http.StatusUnauthorized)
			return
		}

		// Generate server ephemeral values
		// b is a random value (256 bits)
		// @risk Elevation of Privilege: b must be cryptographically random to prevent
		// session key prediction.
		b, err := generateRandomBigInt(256)
		if err != nil {
			eventStream.log(events.EventAuthAttempt, eventOutcome, "random_generation_failed", nil)
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		// B = kv + g^b mod N
		// where k = H(N | g)
		k := m.group.k()
		v := new(big.Int).SetBytes(assertionParams.Verifier)

		// Compute g^b mod N
		gb := new(big.Int).Exp(m.group.g, b, m.group.N)

		// Compute kv mod N
		kv := new(big.Int).Mul(k, v)
		kv.Mod(kv, m.group.N)

		// B = kv + g^b mod N
		B := new(big.Int).Add(kv, gb)
		B.Mod(B, m.group.N)

		m.config.Cache.StoreForUserIdentifier(req.UserIdentifier, &AssertionState{
			InitiatedAt: time.Now(),
			Group:       m.config.Group,
			b:           b,
			B:           B,
			v:           v,
		})

		eventOutcome = events.OutcomeSuccess
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(&AssertionInitiationResponse{
			Salt:  assertionParams.Salt,
			B:     B.Bytes(),
			Group: m.config.Group,
		})
	}
}

// AssertionCompletionRequest contains the client's proof of password knowledge.
type AssertionCompletionRequest struct {
	// UserID identifies the user attempting to authenticate
	UserIdentifier string `json:"identifier"`

	// A is the client's public ephemeral value
	A []byte `json:"a"`

	// M1 is the client's proof (hash of session key and other values)
	M1 []byte `json:"m1"`
}

// AssertionCompletionResponse contains the server's proof and final authentication result.
type AssertionCompletionResponse struct {
	// Success indicates whether authentication succeeded
	Success bool `json:"success"`

	// M2 is the server's proof (hash of session key and other values)
	// Only present if Success is true
	M2 []byte `json:"m2,omitempty"`

	// Error contains any error message if Success is false
	Error string `json:"error,omitempty"`
}

// AssertionSuccessFunc is a callback type that is triggered when an users password
// is successfully verified.
type AssertionSuccessFunc func(string, http.ResponseWriter, *http.Request) error

// AssertionVerificationHandler handles the second (verification) request of
// the assertion flow.
//
// Request 2: The Client sends a second request containing three values:
//
//	an identifier associated with the user, `A` - their public
//	ephmeral value, and `M1` - their proof.
//
// Processing:
//
//	-> Request Validation: HTTP Method and Payload Validity (i.e. JSON)
//	  -> is POST request?
//	  -> is valid JSON?
//	  -> has user identifier?
//	  -> has `A` and `M1`?
//	-> Get AssertionState
//	  -> UserIdentifier -> [Group, b, B, v]
//	-> Perform Computations
//	-> Call SuccessHandlerFunc
//	  -> User Identifier, Request, Response
//	-> Clear Cache Entry
//	-> Return Response
//
// Response:  The Server responds with two values: a boolean indicating
//
//	whether the operation was successful and `M2` which is their
//	proof. In the event of a failure, `M2` is replaced with an
//	error string.
//
// Security Considerations:
// @risk Tampering: Incorrect protocol implementation allows man-in-the-middle attacks.
// @risk Information Disclosure: Constant-time comparison prevents timing attacks.
// @mitigation Elevation of Privilege: Session key is derived correctly per RFC5054.
func (m *Manager) AssertionVerificationHandler(h AssertionSuccessFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		eventStream := newBuildableEvent(
			r.Context(), m.config.AuditLogger, events.GenerateEventID(),
		)
		eventOutcome := events.OutcomeFailure

		startTime := time.Now()
		defer func() {
			eventStream.log(events.EventAuthSuccess, eventOutcome, "assertion_complete", map[string]interface{}{
				"group":    m.config.Group,
				"duration": time.Since(startTime).Milliseconds(),
			})
		}()

		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req AssertionCompletionRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request", http.StatusBadRequest)
			return
		}

		if req.UserIdentifier == "" {
			eventStream.log(events.EventAuthAttempt, eventOutcome, "empty_user_id", nil)
			http.Error(w, "user identifier cannot be empty", http.StatusUnauthorized)
			return
		}

		eventStream.withUserIdentifier(req.UserIdentifier)

		assertionState, err := m.config.Cache.GetForUserIdentifier(req.UserIdentifier)
		if err != nil {
			eventStream.log(events.EventAuthAttempt, eventOutcome, "no_assertion_state", nil)
			http.Error(w, err.Error(), http.StatusUnauthorized) // TODO sanitise the errors we're sending out!
			return
		}

		defer m.config.Cache.PurgeForUserIdentity(req.UserIdentifier)

		// Parse client's public ephemeral value A
		A := new(big.Int).SetBytes(req.A)

		// Verify A % N != 0 (security check per RFC5054)
		// @mitigation Tampering: Reject invalid A values that could compromise security
		Amod := new(big.Int).Mod(A, m.group.N)
		if Amod.Cmp(big.NewInt(0)) == 0 {
			eventStream.log(events.EventAuthAttempt, eventOutcome, "invalid_client_ephemeral", nil)
			http.Error(w, "invalid client ephemeral value", http.StatusUnauthorized)
			return
		}

		// Compute u = H(A | B)
		u := m.computeU(A, assertionState.B)

		// Compute S = (A * v^u)^b mod N
		// @mitigation Elevation of Privilege: Correct session key derivation per RFC5054
		vu := new(big.Int).Exp(assertionState.v, u, m.group.N)
		Avu := new(big.Int).Mul(A, vu)
		Avu.Mod(Avu, m.group.N)
		S := new(big.Int).Exp(Avu, assertionState.b, m.group.N)

		// Compute session key K = H(S)
		K := hashSHA256(S.Bytes())

		// Compute expected M1 = H(H(N) XOR H(g) | H(I) | salt | A | B | K)
		expectedM1 := m.computeM1(req.UserIdentifier, assertionState.B.Bytes(), req.A, K)

		// Verify M1 using constant-time comparison
		// @mitigation Information Disclosure: Constant-time comparison prevents timing attacks
		// that could leak information about the password
		if subtle.ConstantTimeCompare(req.M1, expectedM1) != 1 {
			eventStream.log(events.EventAuthFailure, eventOutcome, "invalid_proof", map[string]interface{}{
				"duration": time.Since(startTime).Milliseconds(),
			})
			http.Error(w, "authentication failed: invalid proof", http.StatusUnauthorized)
			return
		}

		// Compute M2 = H(A | M1 | K)
		M2 := m.computeM2(req.A, req.M1, K)

		if err := h(req.UserIdentifier, w, r); err != nil {
			eventStream.log(events.EventAuthFailure, eventOutcome, "callback_failure", map[string]interface{}{
				"reason": err.Error(),
			})

			http.Error(w, "unknown error", http.StatusInternalServerError)
		}

		eventOutcome = events.OutcomeSuccess
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(&AssertionCompletionResponse{
			Success: true,
			M2:      M2,
		})
	}
}
