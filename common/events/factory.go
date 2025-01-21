package events

import (
	"encoding/json"
	"time"

	"github.com/kptm-tools/common/common/results"
)

type ToolEventFactory struct{}

func (f *ToolEventFactory) BuildEvent(scanID string, toolResult results.ToolResult, err error) ([]byte, error) {
	evt := NewToolResultEvent(scanID, toolResult)
	return json.Marshal(evt)
}

func NewToolResultEvent(scanID string, toolResult results.ToolResult) ToolResultEvent {
	return ToolResultEvent{
		BaseEvent: BaseEvent{
			ScanID:    scanID,
			Timestamp: time.Now().Unix(),
		},
		ToolResult: toolResult,
	}
}
