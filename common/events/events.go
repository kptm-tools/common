package events

import "github.com/kptm-tools/common/pkg/results"

// ScanStartedEvent represents the payload for a scan initiation event.
// This event signals that a scan has begun for a specific target.
type ScanStartedEvent struct {
	// ScanID is the unique ideantifier of the scan
	ScanID string `json:"scan_id"`

	// Target is the domain or IP being scanned
	Target string `json:"target"`

	// Timestamp is the Unix timestamp when the scan started
	Timestamp int64 `json:"timestamp"`
}

// DNSLookupEvent represents the payload of a DNSLookup operation.
// This event provides details about the DNS information gathered for a target.
type DNSLookupEvent struct {
	// ScanID is the unique identifier of the scan associated with this event.
	ScanID string `json:"scan_id"`

	// TargetResult contains the DNS lookup results for the target.
	TargetResult results.TargetResult `json:"target_result"`

	// Timestamp is the Unix timestamp when the scan started
	Timestamp int64 `json:"timestamp"`
}

// WhoIsEvent represents the payload of a WhoIs lookup operation.
// This event provides details about the WhoIs information gathered for a target.
type WhoIsEvent struct {
	// ScanID is the unique identifier of the scan associated with this event.
	ScanID string `json:"scan_id"`

	// TargetResult contains the WhoIs lookup results for the target.
	TargetResult results.TargetResult `json:"target_result"`

	// Timestamp is the Unix timestamp when the scan started
	Timestamp int64 `json:"timestamp"`
}
