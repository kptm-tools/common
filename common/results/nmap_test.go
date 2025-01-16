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

func Test_GetSeverityCounts(t *testing.T) {
	testCases := []struct {
		name     string
		input    []Vulnerability
		expected SeverityCounts
	}{

		{
			name: "Vulnerabilities with CVSS within range",
			input: []Vulnerability{
				{
					ID:   "ID123",
					Type: "cve",
					CVSS: 0.9,
				},
				{
					ID:   "ID123",
					Type: "cve",
					CVSS: 4.9,
				},
				{
					ID:   "ID123",
					Type: "cve",
					CVSS: 9.9,
				},
				{
					ID:   "ID123",
					Type: "cve",
					CVSS: 7.9,
				},
			},
			expected: SeverityCounts{
				Low:      1,
				Medium:   1,
				High:     1,
				Critical: 1,
			},
		},
		{
			name: "Vulnerabilities with CVSS outside range",
			input: []Vulnerability{
				{
					ID:   "ID123",
					Type: "cve",
					CVSS: 0.9,
				},
				{
					ID:   "ID123",
					Type: "cve",
					CVSS: 4.9,
				},
				{
					ID:   "ID123",
					Type: "cve",
					CVSS: 9.9,
				},
				{
					ID:   "ID123",
					Type: "cve",
					CVSS: 11.9,
				},
				{
					ID:   "ID123",
					Type: "cve",
					CVSS: 12.9,
				},
			},
			expected: SeverityCounts{
				Low:      1,
				Medium:   1,
				High:     0,
				Critical: 3,
			},
		},
		{
			name: "Vulnerabilities with negative CVSS outside range",
			input: []Vulnerability{
				{
					ID:   "ID123",
					Type: "cve",
					CVSS: 0.9,
				},
				{
					ID:   "ID123",
					Type: "cve",
					CVSS: 4.9,
				},
				{
					ID:   "ID123",
					Type: "cve",
					CVSS: 9.9,
				},
				{
					ID:   "ID123",
					Type: "cve",
					CVSS: -11.9,
				},
				{
					ID:   "ID123",
					Type: "cve",
					CVSS: -12.9,
				},
			},
			expected: SeverityCounts{
				Low:      3,
				Medium:   1,
				High:     0,
				Critical: 1,
			},
		},
		{
			name:  "Empty Vulnerability Array",
			input: []Vulnerability{},
			expected: SeverityCounts{
				Low:      0,
				Medium:   0,
				High:     0,
				Critical: 0,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			res := GetSeverityCounts(tc.input)
			if res != tc.expected {
				t.Errorf("Expected `%+v`, got `%+v`", tc.expected, res)
			}
		})
	}
}
