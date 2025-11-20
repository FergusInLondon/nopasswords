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
	credStore := memory.NewMemoryCredentialStore()
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

	// HTTP handlers
	http.HandleFunc("/api/srp/register", corsMiddleware(handleRegister(manager)))
	http.HandleFunc("/api/srp/authenticate/begin", corsMiddleware(handleAuthBegin(manager)))
	http.HandleFunc("/api/srp/authenticate/finish", corsMiddleware(handleAuthFinish(manager, sessions)))
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

func handleRegister(manager *srp.Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req srp.RegistrationRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request", http.StatusBadRequest)
			return
		}

		resp, err := manager.Register(context.Background(), &req)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}

func handleAuthBegin(manager *srp.Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req srp.AuthenticationBeginRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request", http.StatusBadRequest)
			return
		}

		resp, err := manager.BeginAuthentication(context.Background(), &req)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}

func handleAuthFinish(manager *srp.Manager, sessions *sessionStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req srp.AuthenticationFinishRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request", http.StatusBadRequest)
			return
		}

		resp, sessionKey, err := manager.FinishAuthentication(context.Background(), &req)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// If authentication succeeded, store session
		if resp.Success && sessionKey != nil {
			sessions.sessions.Store(req.UserID, sessionData{
				SessionKey: sessionKey.Key,
			})
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
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
			"authenticated": true,
			"user_id":       userID,
			"session_key_length": len(session.SessionKey),
		})
	}
}
