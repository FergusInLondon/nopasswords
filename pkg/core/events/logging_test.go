package events

import (
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestNewEvent(t *testing.T) {
	event := NewEvent(EventAssertionSuccess, ProtocolWebAuthn, "user123")

	assert.NotEmpty(t, event.EventID, "EventID should be generated")
	assert.Equal(t, EventAssertionSuccess, event.Type)
	assert.Equal(t, ProtocolWebAuthn, event.Protocol)
	assert.Equal(t, "user123", event.UserIdentifier)
	assert.NotZero(t, event.Timestamp)
	assert.NotNil(t, event.Metadata)
}

func TestEventBuilder(t *testing.T) {
	t.Run("basic construction", func(t *testing.T) {
		event := NewEventBuilder().
			WithEventType(EventAssertionSuccess).
			WithProtocol(ProtocolWebAuthn).
			WithUserIdentifier("user123").
			WithReason("valid_signature").
			WithIPAddress("192.168.1.1").
			WithUserAgent("Mozilla/5.0").
			Build()

		assert.NotEmpty(t, event.EventID)
		assert.Equal(t, EventAssertionSuccess, event.Type)
		assert.Equal(t, ProtocolWebAuthn, event.Protocol)
		assert.Equal(t, "user123", event.UserIdentifier)
		assert.Equal(t, "valid_signature", event.Reason)
		assert.Equal(t, "192.168.1.1", event.IPAddress)
		assert.Equal(t, "Mozilla/5.0", event.UserAgent)
	})

	t.Run("custom event ID and timestamp", func(t *testing.T) {
		customTime := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)
		event := NewEventBuilder().
			WithEventID("custom-id-123").
			WithTimestamp(customTime).
			WithEventType(EventAssertionFailure).
			Build()

		assert.Equal(t, "custom-id-123", event.EventID)
		assert.Equal(t, customTime, event.Timestamp)
	})

	t.Run("metadata", func(t *testing.T) {
		event := NewEventBuilder().
			WithEventType(EventAssertionSuccess).
			WithMetadata("key1", "value1").
			WithMetadata("key2", 123).
			WithMetadata("key3", true).
			Build()

		assert.Equal(t, "value1", event.Metadata["key1"])
		assert.Equal(t, 123, event.Metadata["key2"])
		assert.Equal(t, true, event.Metadata["key3"])
	})

	t.Run("metadata map", func(t *testing.T) {
		metadata := map[string]interface{}{
			"key1": "value1",
			"key2": 123,
			"key3": true,
		}

		event := NewEventBuilder().
			WithEventType(EventAssertionSuccess).
			WithMetadataMap(metadata).
			Build()

		assert.Equal(t, "value1", event.Metadata["key1"])
		assert.Equal(t, 123, event.Metadata["key2"])
		assert.Equal(t, true, event.Metadata["key3"])
	})

	t.Run("fluent interface chaining", func(t *testing.T) {
		builder := NewEventBuilder()

		// Should be able to chain multiple calls
		builder.
			WithEventType(EventAttestationAttempt).
			WithProtocol(ProtocolSecureRemotePassword).
			WithUserIdentifier("user789")

		event := builder.Build()

		assert.Equal(t, EventAttestationAttempt, event.Type)
		assert.Equal(t, ProtocolSecureRemotePassword, event.Protocol)
		assert.Equal(t, "user789", event.UserIdentifier)
	})
}

func TestHTTPRequestContext(t *testing.T) {
	t.Run("basic request", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/api/auth", nil)
		req.RemoteAddr = "192.168.1.1:12345"
		req.Header.Set("User-Agent", "Mozilla/5.0")

		metadata := HTTPRequestContext(req)

		assert.Equal(t, "192.168.1.1:12345", metadata["ip_address"])
		assert.Equal(t, "Mozilla/5.0", metadata["user_agent"])
		assert.Equal(t, "POST", metadata["http_method"])
		assert.Equal(t, "/api/auth", metadata["http_path"])
	})

	t.Run("X-Forwarded-For header", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/status", nil)
		req.RemoteAddr = "192.168.1.1:12345"
		req.Header.Set("X-Forwarded-For", "203.0.113.1")

		metadata := HTTPRequestContext(req)

		// Should prefer X-Forwarded-For
		assert.Equal(t, "203.0.113.1", metadata["ip_address"])
	})

	t.Run("X-Real-IP header", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/status", nil)
		req.RemoteAddr = "192.168.1.1:12345"
		req.Header.Set("X-Real-IP", "203.0.113.2")

		metadata := HTTPRequestContext(req)

		// Should prefer X-Real-IP when X-Forwarded-For is not present
		assert.Equal(t, "203.0.113.2", metadata["ip_address"])
	})

	t.Run("X-Forwarded-For takes precedence over X-Real-IP", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/status", nil)
		req.RemoteAddr = "192.168.1.1:12345"
		req.Header.Set("X-Forwarded-For", "203.0.113.1")
		req.Header.Set("X-Real-IP", "203.0.113.2")

		metadata := HTTPRequestContext(req)

		// X-Forwarded-For should take precedence
		assert.Equal(t, "203.0.113.1", metadata["ip_address"])
	})

	t.Run("referer header", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/auth", nil)
		req.Header.Set("Referer", "https://example.com/login")

		metadata := HTTPRequestContext(req)

		assert.Equal(t, "https://example.com/login", metadata["referer"])
	})

	t.Run("missing optional headers", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)

		metadata := HTTPRequestContext(req)

		// Should not contain referer
		_, hasReferer := metadata["referer"]
		assert.False(t, hasReferer)

		// Should still have required fields
		assert.Contains(t, metadata, "ip_address")
		assert.Contains(t, metadata, "user_agent")
		assert.Contains(t, metadata, "http_method")
		assert.Contains(t, metadata, "http_path")
	})
}

func TestHTTPContextToEvent(t *testing.T) {
	t.Run("applies HTTP context to builder", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/api/auth/login", nil)
		req.RemoteAddr = "192.168.1.1:12345"
		req.Header.Set("User-Agent", "Mozilla/5.0")
		req.Header.Set("Referer", "https://example.com")

		builder := NewEventBuilder().
			WithEventType(EventAttestationFailure).
			WithProtocol(ProtocolWebAuthn).
			WithUserIdentifier("user123")

		HTTPContextToEvent(req, builder)

		event := builder.Build()

		assert.Equal(t, "192.168.1.1:12345", event.IPAddress)
		assert.Equal(t, "Mozilla/5.0", event.UserAgent)
		assert.Equal(t, "POST", event.Metadata["http_method"])
		assert.Equal(t, "/api/auth/login", event.Metadata["http_path"])
		assert.Equal(t, "https://example.com", event.Metadata["referer"])
	})

	t.Run("preserves existing builder state", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/status", nil)

		builder := NewEventBuilder().
			WithEventType(EventAssertionSuccess).
			WithUserIdentifier("user456").
			WithMetadata("existing_key", "existing_value")

		HTTPContextToEvent(req, builder)

		event := builder.Build()

		// Should preserve existing fields
		assert.Equal(t, EventAssertionSuccess, event.Type)
		assert.Equal(t, "user456", event.UserIdentifier)
		assert.Equal(t, "existing_value", event.Metadata["existing_key"])

		// Should add HTTP context
		assert.NotEmpty(t, event.IPAddress)
		assert.Contains(t, event.Metadata, "http_method")
	})
}

func TestEventBuilder_Integration(t *testing.T) {
	// Simulate a complete authentication flow with HTTP request
	req := httptest.NewRequest("POST", "/api/webauthn/authenticate", nil)
	req.RemoteAddr = "203.0.113.1:54321"
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)")
	req.Header.Set("X-Forwarded-For", "198.51.100.42")

	// Build audit event using helpers
	builder := NewEventBuilder().
		WithEventType(EventAssertionSuccess).
		WithProtocol(ProtocolWebAuthn).
		WithUserIdentifier("user789").
		WithReason("valid_signature")

	HTTPContextToEvent(req, builder)

	event := builder.
		WithMetadata("authenticator_type", "platform").
		WithMetadata("sign_count", 42).
		Build()

	// Verify all fields are populated correctly
	assert.NotEmpty(t, event.EventID)
	assert.NotZero(t, event.Timestamp)
	assert.Equal(t, EventAssertionSuccess, event.Type)
	assert.Equal(t, ProtocolWebAuthn, event.Protocol)
	assert.Equal(t, "user789", event.UserIdentifier)
	assert.Equal(t, "valid_signature", event.Reason)
	assert.Equal(t, "198.51.100.42", event.IPAddress) // X-Forwarded-For
	assert.Equal(t, "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)", event.UserAgent)
	assert.Equal(t, "POST", event.Metadata["http_method"])
	assert.Equal(t, "/api/webauthn/authenticate", event.Metadata["http_path"])
	assert.Equal(t, "platform", event.Metadata["authenticator_type"])
	assert.Equal(t, 42, event.Metadata["sign_count"])
}
