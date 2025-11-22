package srp

import (
	"context"

	"go.fergus.london/nopasswords/pkg/core/events"
)

type buildableEventStream struct {
	ctx    context.Context
	logger events.EventLogger
	entry  events.Event
}

func newBuildableEvent(ctx context.Context, logger events.EventLogger, eventID string) *buildableEventStream {
	return &buildableEventStream{
		ctx:    ctx,
		logger: logger,
		entry: events.Event{
			EventID: eventID,
		},
	}
}

func (bes *buildableEventStream) withUserIdentifier(userIdentifier string) {
	bes.entry.UserIdentifier = userIdentifier
}

func (bes *buildableEventStream) log(eventType events.Type, reason string, metadata map[string]interface{}) {
	event := bes.entry
	event.Reason = reason
	event.Metadata = metadata

	_ = bes.logger.Log(bes.ctx, event)
}
