package events

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"time"

	"github.com/google/uuid"
)

// AuditEvent represents a security-relevant event for logging purposes.
//
// Security Note: This struct is designed to exclude sensitive information.
// Do not add fields that might contain passwords, private keys, or full credential data.
//
// @mitigation Information Disclosure: Explicitly excludes sensitive fields to prevent
// accidental logging of credentials or keys.
type AuditEvent struct {
	// EventID is a unique identifier for this event (e.g., UUID).
	EventID string

	// Timestamp records when the event occurred.
	Timestamp time.Time

	// EventType categorizes the event (e.g., "auth.attempt", "auth.success", "auth.failure",
	// "credential.register", "token.generate", "token.revoke").
	EventType string

	// Method indicates the authentication method involved (e.g., "webauthn", "srp", "signed_token").
	Method string

	// UserIdentifier identifies the user associated with this event.
	// May be empty for anonymous operations or registration attempts.
	UserIdentifier string

	// CredentialID identifies the credential involved, if applicable.
	CredentialID string

	// Outcome indicates the result of the operation (e.g., "success", "failure", "error").
	Outcome string

	// Reason provides additional context for the outcome (e.g., "expired_token", "invalid_signature").
	// This should be a machine-readable code, not a user-facing message.
	Reason string

	// IPAddress records the source IP address of the request, if available.
	IPAddress string

	// UserAgent records the user agent string, if available.
	UserAgent string

	// Metadata contains additional event-specific context.
	// MUST NOT contain sensitive information.
	Metadata map[string]interface{}
}

// EventType constants for common audit events.
const (
	EventAuthAttempt        = "auth.attempt"
	EventAuthSuccess        = "auth.success"
	EventAuthFailure        = "auth.failure"
	EventCredentialRegister = "credential.register"
	EventCredentialDelete   = "credential.delete"
	EventCredentialUpdate   = "credential.update"
	EventTokenGenerate      = "token.generate"
	EventTokenVerify        = "token.verify"
	EventTokenRevoke        = "token.revoke"
)

// Outcome constants for audit events.
const (
	OutcomeSuccess = "success"
	OutcomeFailure = "failure"
	OutcomeError   = "error"
)

// EventLogger defines the interface for structured security event logging.
// All authentication operations generate audit events that are passed to this interface.
//
// Implementations must be safe for concurrent use by multiple goroutines.
//
// Security Considerations:
//
// @risk Information Disclosure: Implementations MUST NOT log sensitive data such as
// passwords, private keys, tokens, or full credentials. The AuditEvent struct is
// designed to exclude such data; custom implementations should maintain this contract.
//
// @risk Repudiation: Comprehensive audit logging is essential for security investigations
// and compliance. Ensure events are logged reliably and cannot be easily tampered with.
//
// @risk Denial of Service: Unbounded logging can fill disk space. Implementations
// should include log rotation, rate limiting, or external log aggregation.
type EventLogger interface {
	// Log records a security audit event. This method should not block for extended
	// periods; consider using buffering or async logging for I/O operations.
	//
	// Implementations should not return errors for logging failures unless absolutely
	// necessary. Consider logging errors to stderr or a fallback mechanism rather than
	// disrupting authentication flows.
	Log(ctx context.Context, event AuditEvent) error
}

// NewAuditEvent creates a new AuditEvent with common fields pre-populated.
// This is a convenience function that generates a unique EventID and sets the timestamp.
//
// Usage:
//
//	event := core.NewAuditEvent(
//	    core.EventAuthSuccess,
//	    "webauthn",
//	    "user123",
//	    core.OutcomeSuccess,
//	)
func NewAuditEvent(eventType, method, userIdentifier, outcome string) AuditEvent {
	return AuditEvent{
		EventID:        uuid.New().String(),
		Timestamp:      time.Now().UTC(),
		EventType:      eventType,
		Method:         method,
		UserIdentifier: userIdentifier,
		Outcome:        outcome,
		Metadata:       make(map[string]interface{}),
	}
}

// AuditEventBuilder provides a fluent interface for constructing AuditEvent objects.
// This builder pattern makes it easier to create events with optional fields.
//
// Usage:
//
//	event := core.NewAuditEventBuilder().
//	    WithEventType(core.EventAuthSuccess).
//	    WithMethod("webauthn").
//	    WithUserID("user123").
//	    WithOutcome(core.OutcomeSuccess).
//	    WithCredentialID("cred456").
//	    WithReason("valid_signature").
//	    WithMetadata("authenticator_type", "platform").
//	    Build()
type AuditEventBuilder struct {
	event AuditEvent
}

// NewAuditEventBuilder creates a new AuditEventBuilder with an event ID and timestamp.
func NewAuditEventBuilder() *AuditEventBuilder {
	return &AuditEventBuilder{
		event: AuditEvent{
			EventID:   uuid.New().String(),
			Timestamp: time.Now().UTC(),
			Metadata:  make(map[string]interface{}),
		},
	}
}

// WithEventID sets a custom event ID (overrides the auto-generated UUID).
func (b *AuditEventBuilder) WithEventID(eventID string) *AuditEventBuilder {
	b.event.EventID = eventID
	return b
}

// WithTimestamp sets a custom timestamp (overrides the auto-generated timestamp).
func (b *AuditEventBuilder) WithTimestamp(timestamp time.Time) *AuditEventBuilder {
	b.event.Timestamp = timestamp
	return b
}

// WithEventType sets the event type.
func (b *AuditEventBuilder) WithEventType(eventType string) *AuditEventBuilder {
	b.event.EventType = eventType
	return b
}

// WithMethod sets the authentication method.
func (b *AuditEventBuilder) WithMethod(method string) *AuditEventBuilder {
	b.event.Method = method
	return b
}

// WithUserID sets the user identifier.
func (b *AuditEventBuilder) WithUserIdentifier(userIdentifier string) *AuditEventBuilder {
	b.event.UserIdentifier = userIdentifier
	return b
}

// WithCredentialID sets the credential identifier.
func (b *AuditEventBuilder) WithCredentialID(credentialID string) *AuditEventBuilder {
	b.event.CredentialID = credentialID
	return b
}

// WithOutcome sets the outcome.
func (b *AuditEventBuilder) WithOutcome(outcome string) *AuditEventBuilder {
	b.event.Outcome = outcome
	return b
}

// WithReason sets the reason/error code.
func (b *AuditEventBuilder) WithReason(reason string) *AuditEventBuilder {
	b.event.Reason = reason
	return b
}

// WithIPAddress sets the source IP address.
func (b *AuditEventBuilder) WithIPAddress(ipAddress string) *AuditEventBuilder {
	b.event.IPAddress = ipAddress
	return b
}

// WithUserAgent sets the user agent string.
func (b *AuditEventBuilder) WithUserAgent(userAgent string) *AuditEventBuilder {
	b.event.UserAgent = userAgent
	return b
}

// WithMetadata adds a key-value pair to the metadata map.
//
// @risk Information Disclosure: Ensure values do not contain sensitive data
// such as passwords, private keys, or full credentials.
func (b *AuditEventBuilder) WithMetadata(key string, value interface{}) *AuditEventBuilder {
	b.event.Metadata[key] = value
	return b
}

// WithMetadataMap merges the provided map into the event's metadata.
//
// @risk Information Disclosure: Ensure the map does not contain sensitive data.
func (b *AuditEventBuilder) WithMetadataMap(metadata map[string]interface{}) *AuditEventBuilder {
	for k, v := range metadata {
		b.event.Metadata[k] = v
	}
	return b
}

// Build returns the constructed AuditEvent.
func (b *AuditEventBuilder) Build() AuditEvent {
	return b.event
}

// HTTPRequestContext extracts common audit metadata from an HTTP request.
// This includes IP address, user agent, and other relevant request information.
//
// The returned map can be used with WithMetadataMap or individual values can be
// extracted for WithIPAddress/WithUserAgent.
//
// Usage:
//
//	metadata := core.HTTPRequestContext(r)
//	event := core.NewAuditEventBuilder().
//	    WithEventType(core.EventAuthAttempt).
//	    WithIPAddress(metadata["ip_address"].(string)).
//	    WithUserAgent(metadata["user_agent"].(string)).
//	    Build()
func HTTPRequestContext(r *http.Request) map[string]interface{} {
	metadata := make(map[string]interface{})

	// Extract IP address (consider X-Forwarded-For, X-Real-IP)
	ipAddress := r.RemoteAddr
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		ipAddress = forwarded
	} else if realIP := r.Header.Get("X-Real-IP"); realIP != "" {
		ipAddress = realIP
	}
	metadata["ip_address"] = ipAddress

	// Extract user agent
	metadata["user_agent"] = r.Header.Get("User-Agent")

	// Extract request method and path (useful for API audit logs)
	metadata["http_method"] = r.Method
	metadata["http_path"] = r.URL.Path

	// Extract referer if present
	if referer := r.Header.Get("Referer"); referer != "" {
		metadata["referer"] = referer
	}

	return metadata
}

// HTTPContextToAuditEvent is a helper that extracts HTTP context from a request
// and applies it to an AuditEventBuilder.
//
// Usage:
//
//	event := core.NewAuditEventBuilder().
//	    WithEventType(core.EventAuthSuccess).
//	    WithMethod("webauthn").
//	    WithUserID(userID)
//
//	core.HTTPContextToAuditEvent(r, event)
//
//	finalEvent := event.WithOutcome(core.OutcomeSuccess).Build()
func HTTPContextToAuditEvent(r *http.Request, builder *AuditEventBuilder) *AuditEventBuilder {
	metadata := HTTPRequestContext(r)

	if ipAddr, ok := metadata["ip_address"].(string); ok {
		builder.WithIPAddress(ipAddr)
	}

	if ua, ok := metadata["user_agent"].(string); ok {
		builder.WithUserAgent(ua)
	}

	// Add remaining metadata (http_method, http_path, referer)
	for k, v := range metadata {
		if k != "ip_address" && k != "user_agent" {
			builder.WithMetadata(k, v)
		}
	}

	return builder
}

// GenerateEventID generates a unique event ID for event logging.
func GenerateEventID() string {
	randomBytes := make([]byte, 16)
	rand.Read(randomBytes)
	return hex.EncodeToString(randomBytes)
}
