package events

import (
	"testing"
	"time"

	"github.com/kptm-tools/common/common/enums"
	"github.com/kptm-tools/common/common/results"
)

func Test_GetDomainTargets(t *testing.T) {
	var testCases = []struct {
		name     string
		event    ScanStartedEvent
		expected []results.Target
	}{
		{
			name: "ScanStartedEvent with domains and ips",
			event: ScanStartedEvent{
				ScanID: "738a4212-265a-464c-8b04-64fd1e1b66a1",
				Targets: []results.Target{
					{
						Alias: "google",
						Value: "https://google.com",
						Type:  enums.Domain,
					},
					{
						Alias: "My IP",
						Value: "192.168.1.1",
						Type:  enums.IP,
					},
					{
						Alias: "My Domain",
						Value: "mydomain.com",
						Type:  enums.Domain,
					},
				},
				Timestamp: time.Now().Unix(),
			},
			expected: []results.Target{
				{
					Alias: "google",
					Value: "google.com",
					Type:  enums.Domain,
				},
				{
					Alias: "My Domain",
					Value: "mydomain.com",
					Type:  enums.Domain,
				},
			},
		},
		{
			name: "ScanStartedEvent with only ips",
			event: ScanStartedEvent{
				ScanID: "738a4212-265a-464c-8b04-64fd1e1b66a1",
				Targets: []results.Target{
					{
						Alias: "My IP",
						Value: "192.168.1.1",
						Type:  enums.IP,
					},
				},
				Timestamp: time.Now().Unix(),
			},
			expected: []results.Target{},
		},
		{
			name: "ScanStartedEvent with no targets",
			event: ScanStartedEvent{
				ScanID:    "738a4212-265a-464c-8b04-64fd1e1b66a1",
				Targets:   []results.Target{},
				Timestamp: time.Now().Unix(),
			},
			expected: []results.Target{},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			res := tc.event.GetDomainTargets()

			if len(res) != len(tc.expected) {
				t.Errorf("Incorrect result, expected `%v`, got `%v`", tc.expected, res)
			}

			if !compareTargets(res, tc.expected) {
				t.Errorf("Incorrect result, expected `%v`, got `%v`", tc.expected, res)
			}
		})
	}
}

func Test_GetIPTargets(t *testing.T) {
	var testCases = []struct {
		name     string
		event    ScanStartedEvent
		expected []results.Target
	}{
		{
			name: "ScanStartedEvent with domains and ips",
			event: ScanStartedEvent{
				ScanID: "738a4212-265a-464c-8b04-64fd1e1b66a1",
				Targets: []results.Target{
					{
						Alias: "google",
						Value: "google.com",
						Type:  enums.Domain,
					},
					{
						Alias: "My IP",
						Value: "192.168.1.1",
						Type:  enums.IP,
					},
					{
						Alias: "My Domain",
						Value: "mydomain.com",
						Type:  enums.Domain,
					},
					{
						Alias: "My Invalid IP",
						Value: "256.256.256.256",
						Type:  enums.IP,
					},
				},
				Timestamp: time.Now().Unix(),
			},
			expected: []results.Target{
				{
					Alias: "My IP",
					Value: "192.168.1.1",
					Type:  enums.IP,
				},
			},
		},
		{
			name: "ScanStartedEvent with only domains",
			event: ScanStartedEvent{
				ScanID: "738a4212-265a-464c-8b04-64fd1e1b66a1",
				Targets: []results.Target{
					{
						Alias: "My Domain",
						Value: "mydomain.com",
						Type:  enums.Domain,
					},
					{
						Alias: "google",
						Value: "google.com",
						Type:  enums.Domain,
					},
				},
				Timestamp: time.Now().Unix(),
			},
			expected: []results.Target{},
		},
		{
			name: "ScanStartedEvent with no targets",
			event: ScanStartedEvent{
				ScanID:    "738a4212-265a-464c-8b04-64fd1e1b66a1",
				Targets:   []results.Target{},
				Timestamp: time.Now().Unix(),
			},
			expected: []results.Target{},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			res := tc.event.GetIPTargets()

			if !compareTargets(res, tc.expected) {
				t.Errorf("Incorrect result, expected `%v`, got `%v`", tc.expected, res)
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
