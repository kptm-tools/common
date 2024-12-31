package events

import "github.com/kptm-tools/common/common/results"

// ScanStartedEvent represents the payload for a scan initiation event.
// This event signals that a scan has begun for a specific target.
type ScanStartedEvent struct {
	// ScanID is the unique ideantifier of the scan
	ScanID string `json:"scan_id"`

	// Target is the domain or IP being scanned
	Targets []string `json:"target"`

	// Timestamp is the Unix timestamp when the scan started
	Timestamp int64 `json:"timestamp"`
}

// DNSLookupEvent represents the payload of a DNSLookup operation.
// This event provides details about the DNS information gathered for scan targets.
type DNSLookupEvent struct {
	// ScanID is the unique identifier of the scan associated with this event.
	ScanID string `json:"scan_id"`

	// Results contains the DNS lookup results for the target.
	Result []results.TargetResult `json:"results"`

	// Timestamp is the Unix timestamp when the scan started
	Timestamp int64 `json:"timestamp"`
}

// WhoIsEvent represents the payload of a WhoIs lookup operation.
// This event provides details about the WhoIs information gathered for scan targets.
type WhoIsEvent struct {
	// ScanID is the unique identifier of the scan associated with this event.
	ScanID string `json:"scan_id"`

	// Results contains the WhoIs lookup results for the target.
	Results []results.TargetResult `json:"results"`

	// Timestamp is the Unix timestamp when the scan started
	Timestamp int64 `json:"timestamp"`
}

// HarvesterEvent represents the payload of a Harvester scan operation.
// This event provides details about the Harvester information gathered for scan targets.
type HarvesterEvent struct {
	// ScanID is the unique identifier of the scan associated with this event.
	ScanID string `json:"scan_id"`

	// TargetResult contains the WhoIs lookup results for the target.
	Results []results.TargetResult `json:"results"`

	// Timestamp is the Unix timestamp when the scan started
	Timestamp int64 `json:"timestamp"`
}

// NmapEvent represents the payload of a Harvester scan operation.
// This event provides details about the Harvester information gathered for scan targets.
type NmapEvent struct {
	// ScanID is the unique identifier of the scan associated with this event.
	ScanID string `json:"scan_id"`

	// TargetResult contains the WhoIs lookup results for the target.
	Results []results.TargetResult `json:"results"`

	// Timestamp is the Unix timestamp when the scan started
	Timestamp int64 `json:"timestamp"`
}
