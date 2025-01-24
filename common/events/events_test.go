package events

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/kptm-tools/common/common/enums"
	"github.com/kptm-tools/common/common/results"
)

func Test_HasDomainTarget(t *testing.T) {
	var testCases = []struct {
		name     string
		event    ScanStartedEvent
		expected bool
	}{
		{
			name: "Valid domain target with URL",
			event: ScanStartedEvent{
				BaseEvent: BaseEvent{
					ScanID:    uuid.New(),
					Timestamp: time.Now().UTC(),
				},
				Target: results.Target{
					Alias: "Google",
					Value: "https://google.com",
					Type:  enums.Domain,
				},
			},
			expected: true,
		},
		{
			name: "Valid domain target without URL",
			event: ScanStartedEvent{
				BaseEvent: BaseEvent{
					ScanID:    uuid.New(),
					Timestamp: time.Now().UTC(),
				},
				Target: results.Target{
					Alias: "Example",
					Value: "example.com",
					Type:  enums.Domain,
				},
			},
			expected: true,
		},
		{
			name: "Empty domain target",
			event: ScanStartedEvent{
				BaseEvent: BaseEvent{
					ScanID:    uuid.New(),
					Timestamp: time.Now().UTC(),
				},
				Target: results.Target{
					Alias: "Empty",
					Value: "",
					Type:  enums.Domain,
				},
			},
			expected: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := tc.event.HasDomainTarget()
			if result != tc.expected {
				t.Errorf("expected %v, got %v", tc.expected, result)
			}
		})
	}
}

func Test_HasIPTarget(t *testing.T) {
	var testCases = []struct {
		name     string
		event    ScanStartedEvent
		expected bool
	}{
		{
			name: "Valid IPv4 address",
			event: ScanStartedEvent{
				BaseEvent: BaseEvent{
					ScanID:    uuid.New(),
					Timestamp: time.Now().UTC(),
				},
				Target: results.Target{
					Alias: "Localhost",
					Value: "127.0.0.1",
					Type:  enums.IP,
				},
			},
			expected: true,
		},
		{
			name: "Invalid IPv4 address (out of range)",
			event: ScanStartedEvent{
				BaseEvent: BaseEvent{
					ScanID:    uuid.New(),
					Timestamp: time.Now().UTC(),
				},
				Target: results.Target{
					Alias: "Invalid",
					Value: "256.256.256.256",
					Type:  enums.IP,
				},
			},
			expected: false,
		},
		{
			name: "Empty IP target",
			event: ScanStartedEvent{
				BaseEvent: BaseEvent{
					ScanID:    uuid.New(),
					Timestamp: time.Now().UTC(),
				},
				Target: results.Target{
					Alias: "Empty",
					Value: "",
					Type:  enums.IP,
				},
			},
			expected: false,
		},
		{
			name: "Domain instead of IP",
			event: ScanStartedEvent{
				BaseEvent: BaseEvent{
					ScanID:    uuid.New(),
					Timestamp: time.Now().UTC(),
				},
				Target: results.Target{
					Alias: "Google",
					Value: "google.com",
					Type:  enums.Domain,
				},
			},
			expected: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := tc.event.HasIPTarget()
			if result != tc.expected {
				t.Errorf("expected %v, got %v", tc.expected, result)
			}
		})
	}
}

func Test_IsURL(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{name: "Valid URL with http", input: "http://example.com", expected: true},
		{name: "Valid URL with https", input: "https://example.com", expected: true},
		{name: "Invalid URL", input: "http://", expected: false},
		{name: "Empty string", input: "", expected: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsURL(tt.input)
			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestIsValidIPv4(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{name: "Valid IPv4 address", input: "192.168.1.1", expected: true},
		{name: "Invalid IPv4 address (out of range)", input: "256.256.256.256", expected: false},
		{name: "Invalid IPv4 address (not enough octets)", input: "192.168.1", expected: false},
		{name: "Empty string", input: "", expected: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsValidIPv4(tt.input)
			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func compareTargets(t1, t2 []results.Target) bool {
	if len(t1) != len(t2) {
		return false
	}

	// Convert slices to maps for comparison
	map1 := make(map[string]results.Target)
	map2 := make(map[string]results.Target)

	for _, target := range t1 {
		map1[target.Value] = target
	}
	for _, target := range t2 {
		map2[target.Value] = target
	}

	for key, val := range map1 {
		if map2[key] != val {
			return false
		}
	}
	return true
}
