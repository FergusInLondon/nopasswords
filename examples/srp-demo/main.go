// An example demonstrating Secure Remote Password (SRP) operations.
package main

import (
	"fmt"
	"log"
	"net/http"

	"go.fergus.london/nopasswords/core/memory"
	"go.fergus.london/nopasswords/srp"
)

func main() {
	corsMiddleware := func(next http.HandlerFunc) http.HandlerFunc {
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

	// Initialize SRP manager
	manager, err := srp.NewManager(
		srp.WithGroup(3), // Use 2048-bit group
		srp.WithEventLogger(memory.NewStdoutLogger(true)),
		srp.WithStateCache(nil),
		srp.WithParameterStore(nil),
	)
	if err != nil {
		log.Fatalf("Failed to create SRP manager: %v", err)
	}

	// SRP Handlers
	http.HandleFunc("/api/srp/register", corsMiddleware(
		manager.AttestationHandlerFunc(func(p srp.Parameters) {
			fmt.Println("Attestation Complete: %s", p.UserIdentifier)
		}),
	))
	http.HandleFunc("/api/srp/authenticate/begin", corsMiddleware(
		manager.AssertionBeginHandler(),
	))
	http.HandleFunc("/api/srp/authenticate/finish", corsMiddleware(
		manager.AssertionVerificationHandler(
			func(userIdentifier string, _ http.ResponseWriter, _ *http.Request) error {
				fmt.Println("Successful Assertion: %s", userIdentifier)
				return nil
			},
		),
	))

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
