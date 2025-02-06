package validation

import "testing"

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
