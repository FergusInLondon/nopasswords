package srp

import (
	"context"

	"go.fergus.london/nopasswords/core"
)

type buildableEventStream struct {
	ctx    context.Context
	logger core.AuditLogger
	entry  core.AuditEvent
}

func newBuildableEvent(ctx context.Context, logger core.AuditLogger, eventID string) *buildableEventStream {
	return &buildableEventStream{
		ctx:    ctx,
		logger: logger,
		entry: core.AuditEvent{
			EventID: eventID,
		},
	}
}

func (bes *buildableEventStream) withUserIdentifier(userIdentifier string) {
	bes.entry.UserIdentifier = userIdentifier
}

func (bes *buildableEventStream) log(eventType, outcome, reason string, metadata map[string]interface{}) {
	event := bes.entry
	event.Outcome = outcome
	event.Reason = reason
	event.Metadata = metadata

	_ = bes.logger.Log(bes.ctx, event)
}
