package events

import (
	"time"

	"github.com/google/uuid"
	"github.com/kptm-tools/common/common/pkg/results"
	"github.com/kptm-tools/common/common/pkg/results/tools"
)

type BaseEvent struct {
	// ScanID is the unique identifier of the scan
	ScanID uuid.UUID `json:"scan_id"`

	// Timestamp is the UTC timestamp when the scan started
	Timestamp time.Time `json:"timestamp"`
}

// ScanStartedEvent represents the payload for a scan initiation event.
// This event signals that a scan has begun for a specific target.
type ScanStartedEvent struct {
	BaseEvent
	// Target is the domain or IP being scanned
	Target results.Target `json:"target"`
}

// ScanCancelledEvent represents the payload for a scan cancellation event.
// This event signals that a specific scan has been cancelled.
type ScanCancelledEvent struct {
	BaseEvent
}

// ScanFailedEvent represents the payload for a scan failure event.
// This event signals that a specific scan has failed and cannot go on.
type ScanFailedEvent struct {
	BaseEvent

	// Reason is the reason for the failure
	Reason string `json:"reason"`
}

// ToolResultEvent represents the payload of a tool output.
type ToolResultEvent struct {
	BaseEvent
	ToolResult tools.ToolResult
}

func NewScanStartedEvent(scanID uuid.UUID, target results.Target) ScanStartedEvent {
	return ScanStartedEvent{
		BaseEvent: BaseEvent{
			ScanID:    scanID,
			Timestamp: time.Now().UTC(),
		},
		Target: target,
	}
}

func NewScanFailedEvent(scanID uuid.UUID, reason string) ScanFailedEvent {
	return ScanFailedEvent{
		BaseEvent: BaseEvent{
			ScanID:    scanID,
			Timestamp: time.Now().UTC(),
		},
		Reason: reason,
	}
}

func NewScanCancelledEvent(scanID uuid.UUID) ScanCancelledEvent {
	return ScanCancelledEvent{
		BaseEvent: BaseEvent{
			ScanID:    scanID,
			Timestamp: time.Now().UTC(),
		},
	}
}
