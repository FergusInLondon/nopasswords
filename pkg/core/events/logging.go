// Package events ... TODO
package events

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"time"
)

// Event represents a security or performance relevant event for logging purposes.
//
// Security Note: This struct is designed to exclude sensitive information.
// Do not add fields that might contain passwords, private keys, or full credential data.
//
// @mitigation Information Disclosure: Explicitly excludes sensitive fields to prevent
// accidental logging of credentials or keys.
type Event struct {
	// EventID is a unique identifier for this event (e.g., UUID).
	EventID string

	// Timestamp records when the event occurred.
	Timestamp time.Time

	// EventType categorizes the event (e.g., "attestation.attempt" or "assertion.success").
	Type Type

	// Protocol indicates the authentication method involved (e.g., "webauthn" or "srp").
	Protocol Protocol

	// UserIdentifier identifies the user associated with this event.
	// May be empty for anonymous operations or registration attempts.
	UserIdentifier string

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

// Event Types

// Type ... TODO
type Type int

const (
	// EventAttestationAttempt ... TODO
	EventAttestationAttempt Type = iota
	// EventAttestationSuccess ... TODO
	EventAttestationSuccess
	// EventAttestationFailure ... TODO
	EventAttestationFailure
	// EventAssertionAttempt ... TODO
	EventAssertionAttempt
	// EventAssertionSuccess ... TODO
	EventAssertionSuccess
	// EventAssertionFailure ... TODO
	EventAssertionFailure
)

var eventStrings = map[Type]string{
	EventAttestationAttempt: "attestation.attempt",
	EventAttestationSuccess: "attestation.success",
	EventAttestationFailure: "attestation.failure",
	EventAssertionAttempt:   "assertion.attempt",
	EventAssertionSuccess:   "assertion.success",
	EventAssertionFailure:   "assertion.failure",
}

// String ... TODO
func (evtType Type) String() string {
	return eventStrings[evtType]
}

// Protocols

// Protocol ... TODO
type Protocol int

const (
	// ProtocolSecureRemotePassword ... TODO
	ProtocolSecureRemotePassword Protocol = iota
	// ProtocolWebAuthn ... TODO
	ProtocolWebAuthn
)

var protocolStrings = map[Protocol]string{
	ProtocolSecureRemotePassword: "srp",
	ProtocolWebAuthn:             "webauthn",
}

// String ... TODO
func (protocol Protocol) String() string {
	return protocolStrings[protocol]
}

// EventLogger defines the interface for structured security event logging.
// All authentication operations generate audit events that are passed to this interface.
//
// Implementations must be safe for concurrent use by multiple goroutines.
//
// Security Considerations:
//
// @risk Information Disclosure: Implementations MUST NOT log sensitive data such as
// passwords, private keys, tokens, or full credentials. The Event struct is
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
	Log(ctx context.Context, event Event) error
}

// NewEvent creates a new Event with common fields pre-populated.
// This is a convenience function that generates a unique EventID and sets the timestamp.
//
// Usage:
//
//	event := core.NewEvent(
//	    core.EventAuthSuccess,
//	    "webauthn",
//	    "user123",
//	    core.OutcomeSuccess,
//	)
func NewEvent(eventType Type, protocol Protocol, userIdentifier string) Event {
	return Event{
		EventID:        GenerateEventID(),
		Timestamp:      time.Now().UTC(),
		Type:           eventType,
		Protocol:       protocol,
		UserIdentifier: userIdentifier,
		Metadata:       make(map[string]interface{}),
	}
}

// EventBuilder provides a fluent interface for constructing Event objects.
// This builder pattern makes it easier to create events with optional fields.
//
// Usage:
//
//	event := core.NewEventBuilder().
//	    WithEventType(core.EventAuthSuccess).
//	    WithMethod("webauthn").
//	    WithUserID("user123").
//	    WithCredentialID("cred456").
//	    WithReason("valid_signature").
//	    WithMetadata("authenticator_type", "platform").
//	    Build()
type EventBuilder struct {
	event Event
}

// NewEventBuilder creates a new EventBuilder with an event ID and timestamp.
func NewEventBuilder() *EventBuilder {
	return &EventBuilder{
		event: Event{
			EventID:   GenerateEventID(),
			Timestamp: time.Now().UTC(),
			Metadata:  make(map[string]interface{}),
		},
	}
}

// WithEventID sets a custom event ID (overrides the auto-generated UUID).
func (b *EventBuilder) WithEventID(eventID string) *EventBuilder {
	b.event.EventID = eventID
	return b
}

// WithTimestamp sets a custom timestamp (overrides the auto-generated timestamp).
func (b *EventBuilder) WithTimestamp(timestamp time.Time) *EventBuilder {
	b.event.Timestamp = timestamp
	return b
}

// WithEventType sets the event type.
func (b *EventBuilder) WithEventType(eventType Type) *EventBuilder {
	b.event.Type = eventType
	return b
}

// WithProtocol sets the authentication protocol.
func (b *EventBuilder) WithProtocol(protocol Protocol) *EventBuilder {
	b.event.Protocol = protocol
	return b
}

// WithUserID sets the user identifier.
func (b *EventBuilder) WithUserIdentifier(userIdentifier string) *EventBuilder {
	b.event.UserIdentifier = userIdentifier
	return b
}

// WithReason sets the reason/error code.
func (b *EventBuilder) WithReason(reason string) *EventBuilder {
	b.event.Reason = reason
	return b
}

// WithIPAddress sets the source IP address.
func (b *EventBuilder) WithIPAddress(ipAddress string) *EventBuilder {
	b.event.IPAddress = ipAddress
	return b
}

// WithUserAgent sets the user agent string.
func (b *EventBuilder) WithUserAgent(userAgent string) *EventBuilder {
	b.event.UserAgent = userAgent
	return b
}

// WithMetadata adds a key-value pair to the metadata map.
//
// @risk Information Disclosure: Ensure values do not contain sensitive data
// such as passwords, private keys, or full credentials.
func (b *EventBuilder) WithMetadata(key string, value interface{}) *EventBuilder {
	b.event.Metadata[key] = value
	return b
}

// WithMetadataMap merges the provided map into the event's metadata.
//
// @risk Information Disclosure: Ensure the map does not contain sensitive data.
func (b *EventBuilder) WithMetadataMap(metadata map[string]interface{}) *EventBuilder {
	for k, v := range metadata {
		b.event.Metadata[k] = v
	}
	return b
}

// Build returns the constructed Event.
func (b *EventBuilder) Build() Event {
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
//	event := core.NewEventBuilder().
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

// HTTPContextToEvent is a helper that extracts HTTP context from a request
// and applies it to an EventBuilder.
//
// Usage:
//
//	event := core.NewEventBuilder().
//	    WithEventType(core.EventAuthSuccess).
//	    WithMethod("webauthn").
//	    WithUserID(userID)
//
//	core.HTTPContextToEvent(r, event)
//
//	finalEvent := event.WithOutcome(core.OutcomeSuccess).Build()
func HTTPContextToEvent(r *http.Request, builder *EventBuilder) *EventBuilder {
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
