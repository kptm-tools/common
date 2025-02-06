package validation

import (
	"testing"
)

func Test_IsURL(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{name: "Valid URL with http", input: "http://example.com", expected: true},
		{name: "Valid URL with https", input: "https://example.com", expected: true},
		{name: "URL with Port", input: "https://localhost:8000", expected: true},
		{name: "Invalid URL: Only scheme", input: "http://", expected: false},
		{name: "Invalid URL: No scheme", input: "example.com", expected: false},
		{name: "Empty string", input: "", expected: false},
		{name: "Invalid URL: malformed", input: "not a url", expected: false},
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

func Test_ExtractHostName(t *testing.T) {
	testCases := []struct {
		name         string
		input        string
		expectedHost string
		expectError  bool
	}{
		{
			name:         "Standard HTTP URL",
			input:        "http://www.example.com/path",
			expectedHost: "www.example.com",
			expectError:  false,
		},
		{
			name:         "HTTPS URL with Subdomain",
			input:        "http://api.example.org/v1",
			expectedHost: "api.example.org",
			expectError:  false,
		},
		{
			name:         "HTTPS URL with Subdomain",
			input:        "http://api.example.org/v1",
			expectedHost: "api.example.org",
			expectError:  false,
		},
		{
			name:         "URL with Port",
			input:        "http://localhost:8000",
			expectedHost: "localhost",
			expectError:  false,
		},
		{
			name:         "Invalid URL",
			input:        "not a valid url",
			expectedHost: "",
			expectError:  true,
		},
		{
			name:         "Empty URL",
			input:        "",
			expectedHost: "",
			expectError:  true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := ExtractHostName(tc.input)
			if err != nil {
				if !tc.expectError {
					t.Errorf("got unexpected error: %v", err)
				}
			}

			if result != tc.expectedHost {
				t.Errorf("expected %q, got %q", tc.expectedHost, result)
			}
		})
	}
}

func Test_NormalizeURL(t *testing.T) {
	testCases := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "URL without Protocol",
			input:    "example.com",
			expected: "http://example.com",
		},
		{
			name:     "URL without Protocol",
			input:    "example.com",
			expected: "http://example.com",
		},
		{
			name:     "URL with HTTPS",
			input:    "https://example.com",
			expected: "https://example.com",
		},
		{
			name:     "URL with HTTP",
			input:    "http://example.com",
			expected: "http://example.com",
		},
		{
			name:     "Complex URL without protocol",
			input:    "subdomain.example.co.uk/path",
			expected: "http://subdomain.example.co.uk/path",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := NormalizeURL(tc.input)
			if result != tc.expected {
				t.Errorf("expected %q, got %q", tc.expected, result)
			}
		})
	}
}
