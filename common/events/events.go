package events

import (
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/kptm-tools/common/common/enums"
	"github.com/kptm-tools/common/common/results"
	"golang.org/x/net/publicsuffix"
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
	ToolResult results.ToolResult
}

func (e *ScanStartedEvent) HasDomainTarget() bool {
	if e.Target.Type == enums.Domain {
		normalizedURL := NormalizeURL(e.Target.Value)
		if IsURL(normalizedURL) {
			return true
		}
	}
	return false
}

func (e *ScanStartedEvent) HasIPTarget() bool {
	if e.Target.Type == enums.IP && IsValidIPv4(e.Target.Value) {
		return true
	}
	return false
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

// IsURL checks if a string is a valid URL
func IsURL(str string) bool {
	u, err := url.ParseRequestURI(str)
	return err == nil && u.Scheme != "" && u.Host != ""
}

// IsValidIPv4 validates whether a string is a valid IPv4 address.
func IsValidIPv4(ip string) bool {
	return net.ParseIP(ip) != nil && net.ParseIP(ip).To4() != nil

}

// ExtractDomain extracts the host part from a given URI
func ExtractDomain(rawURL string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", fmt.Errorf("invalid URL: %w", err)
	}

	hostName := u.Hostname()
	domain, err := publicsuffix.EffectiveTLDPlusOne(hostName)
	if err != nil {
		return "", fmt.Errorf("failed to parse top domain: %w", err)
	}

	return domain, nil
}

// NormalizeURL prefixes the protocol if it's missing in the URL
func NormalizeURL(url string) string {
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		url = "http://" + url
	}
	return url
}
