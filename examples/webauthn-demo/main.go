// An example of using nopasswords to implement WebAuthN operations.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"

	"go.fergus.london/nopasswords/core/memory"
	"go.fergus.london/nopasswords/webauthn"
)

// Simple in-memory session store for demo purposes
// @risk Production systems should use secure, distributed session storage
type sessionStore struct {
	mu       sync.RWMutex
	sessions map[string]*webauthn.SessionData
}

func newSessionStore() *sessionStore {
	return &sessionStore{
		sessions: make(map[string]*webauthn.SessionData),
	}
}

func (s *sessionStore) set(sessionID string, data *webauthn.SessionData) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[sessionID] = data
}

func (s *sessionStore) get(sessionID string) (*webauthn.SessionData, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	data, ok := s.sessions[sessionID]
	return data, ok
}

func (s *sessionStore) delete(sessionID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, sessionID)
}

type server struct {
	manager  *webauthn.Manager
	sessions *sessionStore
}

func main() {
	// Create WebAuthn manager
	config, err := webauthn.NewConfig(
		webauthn.WithRPDisplayName("NoPasswords Demo"),
		webauthn.WithRPID("localhost"),
		webauthn.WithRPOrigins("http://localhost:8080"),
		webauthn.WithCredentialStore(memory.NewCredentialStore()),
		webauthn.WithAuditLogger(memory.NewStdoutLogger(true)),
	)
	if err != nil {
		log.Fatalf("Failed to create WebAuthn config: %v", err)
	}

	manager, err := webauthn.NewManager(config)
	if err != nil {
		log.Fatalf("Failed to create WebAuthn manager: %v", err)
	}

	srv := &server{
		manager:  manager,
		sessions: newSessionStore(),
	}

	// API endpoints
	http.HandleFunc("/api/webauthn/register/begin", srv.handleRegisterBegin)
	http.HandleFunc("/api/webauthn/register/finish", srv.handleRegisterFinish)
	http.HandleFunc("/api/webauthn/authenticate/begin", srv.handleAuthenticateBegin)
	http.HandleFunc("/api/webauthn/authenticate/finish", srv.handleAuthenticateFinish)

	// Serve static files (HTML, JS, CSS)
	http.Handle("/", http.FileServer(http.Dir("./static")))

	log.Println("Server starting on http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func (s *server) handleRegisterBegin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		UserID          string `json:"userID"`
		UserName        string `json:"userName"`
		UserDisplayName string `json:"userDisplayName"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf("Invalid request: %v", err), http.StatusBadRequest)
		return
	}

	ctx := context.Background()
	creation, sessionData, err := s.manager.BeginRegistration(ctx, req.UserID, req.UserName, req.UserDisplayName)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to begin registration: %v", err), http.StatusInternalServerError)
		return
	}

	// Store session data
	// @risk In production, use secure session management with CSRF protection
	sessionID := req.UserID + "-register"
	s.sessions.set(sessionID, sessionData)

	// Set session cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "webauthn_session",
		Value:    sessionID,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(creation)
}

func (s *server) handleRegisterFinish(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get session ID from cookie
	cookie, err := r.Cookie("webauthn_session")
	if err != nil {
		http.Error(w, "No session found", http.StatusUnauthorized)
		return
	}

	_, ok := s.sessions.get(cookie.Value)
	if !ok {
		http.Error(w, "Invalid session", http.StatusUnauthorized)
		return
	}

	var credentialCreationResponse map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&credentialCreationResponse); err != nil {
		http.Error(w, fmt.Sprintf("Invalid request: %v", err), http.StatusBadRequest)
		return
	}

	// Note: For simplicity, we're accepting the raw JSON and would need to parse it
	// into protocol.ParsedCredentialCreationData. In a real implementation,
	// you would use protocol.ParseCredentialCreationResponse()
	//
	// This is simplified for demo purposes
	log.Printf("Registration credential received (session data exists, would verify in production)")

	// Clean up session
	s.sessions.delete(cookie.Value)
	http.SetCookie(w, &http.Cookie{
		Name:   "webauthn_session",
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

func (s *server) handleAuthenticateBegin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		UserID string `json:"userID"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf("Invalid request: %v", err), http.StatusBadRequest)
		return
	}

	ctx := context.Background()
	assertion, sessionData, err := s.manager.BeginAuthentication(ctx, req.UserID)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to begin authentication: %v", err), http.StatusInternalServerError)
		return
	}

	// Store session data
	sessionID := req.UserID + "-authenticate"
	s.sessions.set(sessionID, sessionData)

	// Set session cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "webauthn_session",
		Value:    sessionID,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(assertion)
}

func (s *server) handleAuthenticateFinish(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get session ID from cookie
	cookie, err := r.Cookie("webauthn_session")
	if err != nil {
		http.Error(w, "No session found", http.StatusUnauthorized)
		return
	}

	sessionData, ok := s.sessions.get(cookie.Value)
	if !ok {
		http.Error(w, "Invalid session", http.StatusUnauthorized)
		return
	}

	var credentialAssertionResponse map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&credentialAssertionResponse); err != nil {
		http.Error(w, fmt.Sprintf("Invalid request: %v", err), http.StatusBadRequest)
		return
	}

	// Note: For simplicity, we're accepting the raw JSON and would need to parse it
	// into protocol.ParsedCredentialAssertionData. In a real implementation,
	// you would use protocol.ParseCredentialRequestResponse()
	//
	// This is simplified for demo purposes
	log.Printf("Authentication assertion received (session data exists, would verify in production)")

	// Clean up session
	s.sessions.delete(cookie.Value)
	http.SetCookie(w, &http.Cookie{
		Name:   "webauthn_session",
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"userID":  sessionData.UserIdentifier,
	})
}
