package events

import "github.com/kptm-tools/common/common/results"

// TargetType defines the type of the target being scanned, such as IP or Domain
type TargetType string

const (
	// IP represents a target of type IP address
	IP TargetType = "IP"

	// Domain represents a target of type domain name
	Domain TargetType = "Domain"
)

// Target represents a scan target with its alias, value and type.
type Target struct {
	// Alias is a user-friendly name for the target
	Alias string `json:"alias"`

	// Value is the actual IP address or domain name of the target.
	Value string `json:"value"`

	// Type specifies whether the target is an IP or a Domain.
	Type TargetType `json:"type"`
}

// ScanStartedEvent represents the payload for a scan initiation event.
// This event signals that a scan has begun for a specific target.
type ScanStartedEvent struct {
	// ScanID is the unique ideantifier of the scan
	ScanID string `json:"scan_id"`

	// Target is the domain or IP being scanned
	Targets []Target `json:"target"`

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

func (e *ScanStartedEvent) GetDomainValues() []string {
	domains := make([]string, 0)
	for _, target := range e.Targets {
		if target.Type == Domain {
			domains = append(domains, target.Value)
		}
	}
	return domains
}

func (e *ScanStartedEvent) GetIPValues() []string {
	ips := make([]string, 0)
	for _, target := range e.Targets {
		if target.Type == IP {
			ips = append(ips, target.Value)
		}
	}
	return ips
}
