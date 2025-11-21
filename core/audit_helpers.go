package core

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"time"

	"github.com/google/uuid"
)

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

// ExtractUserIDFromContext is a helper that extracts a user ID from a context.Context.
// This assumes the application stores the authenticated user ID in the context
// using a specific key.
//
// Applications should define their own context key constant and use it consistently:
//
//	type contextKey string
//	const UserIDKey contextKey = "user_id"
//
//	ctx = context.WithValue(ctx, UserIDKey, "user123")
//	userID := core.ExtractUserIDFromContext(ctx, UserIDKey)
func ExtractUserIDFromContext(ctx context.Context, key interface{}) string {
	if userID, ok := ctx.Value(key).(string); ok {
		return userID
	}
	return ""
}

// GenerateEventID generates a unique event ID for event logging.
func GenerateEventID() string {
	randomBytes := make([]byte, 16)
	rand.Read(randomBytes)
	return hex.EncodeToString(randomBytes)
}
