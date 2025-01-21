package events

import (
	"encoding/json"
	"time"

	"github.com/kptm-tools/common/common/enums"
	"github.com/kptm-tools/common/common/results"
)

type ToolEventFactory struct{}

func (f *ToolEventFactory) BuildEvent(scanID string, toolResult results.ToolResult, err error) ([]byte, error) {
	evt := NewToolResultEvent(scanID, toolResult, err)
	return json.Marshal(evt)
}

func NewToolResultEvent(scanID string, toolResult results.ToolResult, err error) ToolResultEvent {
	return ToolResultEvent{
		BaseEvent: BaseEvent{
			ScanID:    scanID,
			Timestamp: time.Now().Unix(),
			Error:     getEventError(err),
		},
		ToolResult: toolResult,
	}
}

// getEventError is a helper function to map the error result to a Service EventError
func getEventError(err error) *EventError {
	if err != nil {
		return &EventError{
			Code:    enums.ToolError,
			Message: err.Error(),
		}
	}
	return nil
}
