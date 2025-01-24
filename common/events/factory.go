package events

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"github.com/kptm-tools/common/common/results"
)

type ToolEventFactory struct{}

func (f *ToolEventFactory) BuildEvent(scanID uuid.UUID, toolResult results.ToolResult) ([]byte, error) {
	evt := NewToolResultEvent(scanID, toolResult)
	return json.Marshal(evt)
}

func NewToolResultEvent(scanID uuid.UUID, toolResult results.ToolResult) ToolResultEvent {
	return ToolResultEvent{
		BaseEvent: BaseEvent{
			ScanID:    scanID,
			Timestamp: time.Now().UTC(),
		},
		ToolResult: toolResult,
	}
}
