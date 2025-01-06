package results

import "testing"

func Test_buildVulnersReference(t *testing.T) {
	testCases := []struct {
		name     string
		input    Vulnerability
		expected string
	}{
		{
			name: "Vulnerability with ID and Type",
			input: Vulnerability{
				ID:   "ID123",
				Type: "cve",
			},
			expected: "https://vulners.com/cve/ID123",
		},
		{
			name: "Vulnerability with only ID",
			input: Vulnerability{
				ID: "ID123",
			},
			expected: "https://vulners.com//ID123",
		},
		{
			name: "Vulnerability with only Type",
			input: Vulnerability{
				Type: "cve",
			},
			expected: "https://vulners.com/cve/",
		},
		{
			name:     "Vulnerability without ID or Type",
			input:    Vulnerability{},
			expected: "https://vulners.com//",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			res := buildVulnersReference(tc.input.ID, tc.input.Type)
			if res != tc.expected {
				t.Errorf("Expected `%s`, got `%s`", tc.expected, res)
			}
		})
	}
}
