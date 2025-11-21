// An example demonstrating Secure Remote Password (SRP) operations.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"

	"go.fergus.london/nopasswords/core/memory"
	"go.fergus.london/nopasswords/srp"
)

// TODO: We can rip all this session stuff out when we refine
//  the SRP interface.

// sessionStore holds authentication sessions temporarily
// WARNING: In-memory storage is for demo purposes only!
// Production applications should use persistent, secure storage.
type sessionStore struct {
	sessions sync.Map // map[userID]sessionData
}

type sessionData struct {
	SessionKey []byte
}

func main() {
	// Initialize SRP manager
	// WARNING: In-memory credential store is for demo only!
	credStore := memory.NewCredentialStore()
	auditLogger := memory.NewStdoutLogger(true)

	manager, err := srp.NewManager(
		srp.WithGroup(3), // Use 2048-bit group
		srp.WithCredentialStore(credStore),
		srp.WithAuditLogger(auditLogger),
	)
	if err != nil {
		log.Fatalf("Failed to create SRP manager: %v", err)
	}

	sessions := &sessionStore{}

	// SRP Handlers
	http.HandleFunc("/api/srp/register", corsMiddleware(
		m.AttestationHandlerFunc(attestationHandler)
	))
	http.HandleFunc("/api/srp/authenticate/begin", corsMiddleware(
		m.AssertionBeginHandler(assertionInitiationHandler)
	))
	http.HandleFunc("/api/srp/authenticate/finish", corsMiddleware(
		m.AssertionFinishHandler(assertionCompletionHandler)
	))

	http.HandleFunc("/api/session", corsMiddleware(handleSession(sessions)))

	// Serve static files
	http.Handle("/", http.FileServer(http.Dir("./static")))

	fmt.Println("🔐 SRP Demo Server")
	fmt.Println("Server running on http://localhost:8081")
	fmt.Println("Open your browser to http://localhost:8081")
	fmt.Println("")

	if err := http.ListenAndServe(":8081", nil); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}

// CORS middleware for demo purposes
func corsMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next(w, r)
	}
}

func attestationHandler(w http.RequestWriter, r *http.Request, *srp.RegistrationRequest) bool {
	fmt.Println("Successfully attested credentials for user!")

	return true // allow default response
}

func assertionInitiationHandler(w http.RequestWriter, r *http.Request, *srp.RegistrationRequest) bool {
	fmt.Println("Starting assertion process")

	// This would be where we get the salt from the database.

	return true // allow default response
}

func assertionCompletionHandler(w http.RequestWirter, r *http.Request, *srp.SuccessfulAssertionCtx) bool {
	fmt.Println("Successfully confirmed users password!")
	return true
}

func handleSession(sessions *sessionStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID := r.URL.Query().Get("user_id")
		if userID == "" {
			http.Error(w, "user_id required", http.StatusBadRequest)
			return
		}

		data, ok := sessions.sessions.Load(userID)
		if !ok {
			http.Error(w, "No active session", http.StatusUnauthorized)
			return
		}

		session := data.(sessionData)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"authenticated":      true,
			"user_id":            userID,
			"session_key_length": len(session.SessionKey),
		})
	}
}
