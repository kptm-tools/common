package events

import (
	"reflect"
	"testing"
	"time"
)

func Test_GetDomainValues(t *testing.T) {
	var testCases = []struct {
		name     string
		event    ScanStartedEvent
		expected []string
	}{
		{
			name: "ScanStartedEvent with domains and ips",
			event: ScanStartedEvent{
				ScanID: "738a4212-265a-464c-8b04-64fd1e1b66a1",
				Targets: []Target{
					{
						Alias: "google",
						Value: "google.com",
						Type:  Domain,
					},
					{
						Alias: "My IP",
						Value: "192.168.1.1",
						Type:  IP,
					},
					{
						Alias: "My Domain",
						Value: "mydomain.com",
						Type:  Domain,
					},
				},
				Timestamp: time.Now().Unix(),
			},
			expected: []string{"google.com", "mydomain.com"},
		},
		{
			name: "ScanStartedEvent with only ips",
			event: ScanStartedEvent{
				ScanID: "738a4212-265a-464c-8b04-64fd1e1b66a1",
				Targets: []Target{
					{
						Alias: "My IP",
						Value: "192.168.1.1",
						Type:  IP,
					},
				},
				Timestamp: time.Now().Unix(),
			},
			expected: []string{},
		},
		{
			name: "ScanStartedEvent with no targets",
			event: ScanStartedEvent{
				ScanID:    "738a4212-265a-464c-8b04-64fd1e1b66a1",
				Targets:   []Target{},
				Timestamp: time.Now().Unix(),
			},
			expected: []string{},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			res := tc.event.GetDomainValues()

			if len(res) != len(tc.expected) {
				t.Errorf("Incorrect result, expected `%v`, got `%v`", tc.expected, res)
			}

			if !reflect.DeepEqual(res, tc.expected) {
				t.Errorf("Incorrect result, expected `%v`, got `%v`", tc.expected, res)
			}
		})
	}
}

func Test_GetIPValues(t *testing.T) {
	var testCases = []struct {
		name     string
		event    ScanStartedEvent
		expected []string
	}{
		{
			name: "ScanStartedEvent with domains and ips",
			event: ScanStartedEvent{
				ScanID: "738a4212-265a-464c-8b04-64fd1e1b66a1",
				Targets: []Target{
					{
						Alias: "google",
						Value: "google.com",
						Type:  Domain,
					},
					{
						Alias: "My IP",
						Value: "192.168.1.1",
						Type:  IP,
					},
					{
						Alias: "My Domain",
						Value: "mydomain.com",
						Type:  Domain,
					},
				},
				Timestamp: time.Now().Unix(),
			},
			expected: []string{"192.168.1.1"},
		},
		{
			name: "ScanStartedEvent with only domains",
			event: ScanStartedEvent{
				ScanID: "738a4212-265a-464c-8b04-64fd1e1b66a1",
				Targets: []Target{
					{
						Alias: "My Domain",
						Value: "mydomain.com",
						Type:  Domain,
					},
					{
						Alias: "google",
						Value: "google.com",
						Type:  Domain,
					},
				},
				Timestamp: time.Now().Unix(),
			},
			expected: []string{},
		},
		{
			name: "ScanStartedEvent with no targets",
			event: ScanStartedEvent{
				ScanID:    "738a4212-265a-464c-8b04-64fd1e1b66a1",
				Targets:   []Target{},
				Timestamp: time.Now().Unix(),
			},
			expected: []string{},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			res := tc.event.GetIPValues()

			if len(res) != len(tc.expected) {
				t.Errorf("Incorrect result, expected `%v`, got `%v`", tc.expected, res)
			}

			if !reflect.DeepEqual(res, tc.expected) {
				t.Errorf("Incorrect result, expected `%v`, got `%v`", tc.expected, res)
			}
		})
	}
}
