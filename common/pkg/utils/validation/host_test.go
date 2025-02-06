package validation

import (
	"testing"

	"github.com/kptm-tools/common/common/pkg/enums"
	"github.com/stretchr/testify/assert"
)

func Test_ClassifyHostValue(t *testing.T) {
	testCases := []struct {
		name               string
		input              string
		expectedType       enums.TargetType
		expectedClassif    string
		expectedNormalized string
		expectError        bool
	}{
		// IPv4 Classification Tests
		{
			name:               "Valid IPv4 Address",
			input:              "192.168.1.1",
			expectedType:       enums.IP,
			expectedClassif:    "IPv4",
			expectedNormalized: "http://192.168.1.1",
			expectError:        false,
		},
		// Top-Level Domain Tests
		{
			name:               "Simple Domain",
			input:              "example.com",
			expectedType:       enums.Domain,
			expectedClassif:    "Top-Level Domain",
			expectedNormalized: "http://example.com",
			expectError:        false,
		},
		{
			name:               "Domain with HTTP Protocol",
			input:              "http://example.com",
			expectedType:       enums.Domain,
			expectedClassif:    "Top-Level Domain",
			expectedNormalized: "http://example.com",
			expectError:        false,
		},
		{
			name:               "Domain with HTTPS Protocol",
			input:              "https://example.com",
			expectedType:       enums.Domain,
			expectedClassif:    "Top-Level Domain",
			expectedNormalized: "https://example.com",
			expectError:        false,
		},
		// Subdomain Tests
		{
			name:               "Simple Subdomain",
			input:              "www.example.com",
			expectedType:       enums.Subdomain,
			expectedClassif:    "Subdomain",
			expectedNormalized: "http://www.example.com",
			expectError:        false,
		},
		{
			name:               "Complex Subdomain",
			input:              "api.service.example.co.uk",
			expectedType:       enums.Subdomain,
			expectedClassif:    "Subdomain",
			expectedNormalized: "http://api.service.example.co.uk",
			expectError:        false,
		},
		// Edge Cases and Error Scenarios
		{
			name:        "Invalid Domain Format",
			input:       "localhost",
			expectError: true,
		},
		{
			name:        "Empty Input",
			input:       "",
			expectError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := ClassifyHostValue(tc.input)

			if tc.expectError {
				assert.Error(t, err, "Expected an error for input %q", tc.input)
				return
			}

			assert.NoError(t, err, "Unexpected error for input %q", tc.input)

			assert.NotNil(t, result, "Classification result should not be nil")

			assert.Equal(t, tc.input, result.RawValue,
				"RawValue does not match expected")

			assert.Equal(t, tc.expectedNormalized, result.NormalizedValue,
				"Normalized value does not match expected")

			assert.Equal(t, tc.expectedType, result.Type,
				"Type does not match expected")

			assert.Equal(t, tc.expectedClassif, result.Classification,
				"Classification does not match expected")

		})
	}

}
