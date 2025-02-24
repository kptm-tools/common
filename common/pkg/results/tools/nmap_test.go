package tools

import (
	"testing"

	"github.com/kptm-tools/common/common/pkg/enums"
)

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
					ID:           "ID123",
					Type:         "cve",
					BaseSeverity: enums.SeverityTypeLow,
				},
				{
					ID:           "ID123",
					Type:         "cve",
					BaseSeverity: enums.SeverityTypeMedium,
				},
				{
					ID:           "ID123",
					Type:         "cve",
					BaseSeverity: enums.SeverityTypeCritical,
				},
				{
					ID:           "ID123",
					Type:         "cve",
					BaseSeverity: enums.SeverityTypeHigh,
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
			name: "Vulnerabilities with Unknown severities",
			input: []Vulnerability{
				{
					ID:           "ID123",
					Type:         "cve",
					BaseSeverity: enums.SeverityTypeLow,
				},
				{
					ID:           "ID123",
					Type:         "cve",
					BaseSeverity: enums.SeverityTypeMedium,
				},
				{
					ID:           "ID123",
					Type:         "cve",
					BaseSeverity: enums.SeverityTypeCritical,
				},
				{
					ID:           "ID123",
					Type:         "cve",
					BaseSeverity: enums.SeverityTypeUnknown,
				},
				{
					ID:           "ID123",
					Type:         "cve",
					BaseSeverity: enums.SeverityTypeUnknown,
				},
			},
			expected: SeverityCounts{
				Low:      1,
				Medium:   1,
				High:     0,
				Critical: 1,
				Unknown:  2,
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

func Test_TotalVulnerabilities(t *testing.T) {
	testCases := []struct {
		name     string
		input    NmapResult
		expected int
	}{
		{
			name: "NmapResult with no vulnerabilities",
			input: NmapResult{
				ScannedPorts: []PortData{
					{ID: 80, Vulnerabilities: []Vulnerability{}},
					{ID: 443, Vulnerabilities: []Vulnerability{}},
				},
			},
			expected: 0,
		},
		{
			name: "NmapResult with single vulnerability on one port",
			input: NmapResult{
				ScannedPorts: []PortData{
					{ID: 80, Vulnerabilities: []Vulnerability{
						{ID: "CVE-1234", BaseCVSSScore: 5.0},
					}},
					{ID: 443, Vulnerabilities: []Vulnerability{}},
				},
			},
			expected: 1,
		},
		{
			name: "Multiple vulnerabilities on multiple ports",
			input: NmapResult{
				ScannedPorts: []PortData{
					{ID: 80, Vulnerabilities: []Vulnerability{
						{ID: "CVE-1234", BaseCVSSScore: 5.0},
						{ID: "CVE-5678", BaseCVSSScore: 7.5},
					}},
					{ID: 443, Vulnerabilities: []Vulnerability{
						{ID: "CVE-91011", BaseCVSSScore: 9.8},
					}},
				},
			},
			expected: 3,
		},
		{
			name: "No scanned ports",
			input: NmapResult{
				ScannedPorts: []PortData{},
			},
			expected: 0,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			res := tc.input.TotalVulnerabilities()
			if res != tc.expected {
				t.Errorf("Expected `%d`, got `%d`", tc.expected, res)
			}
		})
	}
}

func TestGetSeverityPerTypeMap(t *testing.T) {
	result := NmapResult{
		ScannedPorts: []PortData{
			{Vulnerabilities: []Vulnerability{
				{Type: "Tipo A", BaseCVSSScore: 5.0},
				{Type: "Tipo B", BaseCVSSScore: 3.0},
				{Type: "Tipo A", BaseCVSSScore: 9.5}, // Higher severity for Tipo A
			}},
			{Vulnerabilities: []Vulnerability{
				{Type: "Tipo C", BaseCVSSScore: 4.0},
				{Type: "Tipo B", BaseCVSSScore: 7.0}, // Higher severity for Tipo B
			}},
		},
	}

	expected := map[string]int{
		"Tipo A": SeverityCritical,
		"Tipo B": SeverityHigh,
		"Tipo C": SeverityMedium,
	}

	actual := result.GetSeverityPerTypeMap()

	for key, expectedValue := range expected {
		if actual[key] != expectedValue {
			t.Errorf("expected %d for %s, got %d", expectedValue, key, actual[key])
		}
	}
}
