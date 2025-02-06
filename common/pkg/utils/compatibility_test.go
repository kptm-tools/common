package utils

import (
	"testing"

	"github.com/kptm-tools/common/common/pkg/enums"
	"github.com/kptm-tools/common/common/pkg/utils/validation"
	"github.com/stretchr/testify/assert"
)

func Test_CanRunTool(t *testing.T) {
	// Mock a checker
	checker := NewToolCompatibilityChecker()

	testCases := []struct {
		name           string
		tool           enums.ToolName
		hostType       enums.TargetType
		expectedResult bool
	}{
		{
			name:           "WhoIs on Domain",
			tool:           enums.ToolWhoIs,
			hostType:       enums.Domain,
			expectedResult: true,
		},
		{
			name:           "WhoIs on Subdomain",
			tool:           enums.ToolWhoIs,
			hostType:       enums.Subdomain,
			expectedResult: false,
		},
		{
			name:           "WhoIs on IP",
			tool:           enums.ToolWhoIs,
			hostType:       enums.IP,
			expectedResult: false,
		},
		{
			name:           "DNSLookup on Domain",
			tool:           enums.ToolDNSLookup,
			hostType:       enums.Domain,
			expectedResult: true,
		},
		{
			name:           "DNSLookup on Subdomain",
			tool:           enums.ToolDNSLookup,
			hostType:       enums.Subdomain,
			expectedResult: false,
		},
		{
			name:           "DNSLookup on IP",
			tool:           enums.ToolDNSLookup,
			hostType:       enums.IP,
			expectedResult: false,
		},
		{
			name:           "Harvester on Domain",
			tool:           enums.ToolHarvester,
			hostType:       enums.Domain,
			expectedResult: true,
		},
		{
			name:           "Harvester on Subdomain",
			tool:           enums.ToolHarvester,
			hostType:       enums.Subdomain,
			expectedResult: true,
		},
		{
			name:           "DNSLookup on IP",
			tool:           enums.ToolHarvester,
			hostType:       enums.IP,
			expectedResult: false,
		},
		// Nmap Tool Compatibility (most flexible)
		{
			name:           "Nmap on Domain",
			tool:           enums.ToolNmap,
			hostType:       enums.Domain,
			expectedResult: true,
		},
		{
			name:           "Nmap on Subdomain",
			tool:           enums.ToolNmap,
			hostType:       enums.Subdomain,
			expectedResult: true,
		},
		{
			name:           "Nmap on IP",
			tool:           enums.ToolNmap,
			hostType:       enums.IP,
			expectedResult: true,
		},
		{
			name:           "Unknown Tool",
			tool:           enums.ToolName("UnknownTool"),
			hostType:       enums.Domain,
			expectedResult: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := checker.CanRunTool(tc.tool, &validation.HostClassification{
				Type: tc.hostType,
			})

			assert.Equal(t, tc.expectedResult, result,
				"Unexpected compatibility for tool %v on host type %v",
				tc.tool, tc.hostType)

		})
	}
}

func Test_ValidateHostForTool(t *testing.T) {
	testCases := []struct {
		name        string
		value       string
		tool        enums.ToolName
		expectError bool
	}{
		// Valid scenarios
		{
			name:        "Valid Domain for WhoIs",
			value:       "example.com",
			tool:        enums.ToolWhoIs,
			expectError: false,
		},
		{
			name:        "Valid IP for Nmap",
			value:       "192.168.1.1",
			tool:        enums.ToolNmap,
			expectError: false,
		},
		// Invalid scenarios
		{
			name:        "Subdomain for WhoIs",
			value:       "www.example.com",
			tool:        enums.ToolWhoIs,
			expectError: true,
		},
		{
			name:        "IP for WhoIs",
			value:       "192.168.1.1",
			tool:        enums.ToolWhoIs,
			expectError: true,
		},
		{
			name:        "Invalid Host",
			value:       "invalid",
			tool:        enums.ToolNmap,
			expectError: true,
		},
	}

	// Run each test case
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Validate host for the given tool
			err := ValidateHostForTool(tc.value, tc.tool)

			// Check error expectation
			if tc.expectError {
				assert.Error(t, err, "Expected an error for %q with tool %v",
					tc.value, tc.tool)
			} else {
				assert.NoError(t, err, "Unexpected error for %q with tool %v",
					tc.value, tc.tool)
			}
		})
	}
}
