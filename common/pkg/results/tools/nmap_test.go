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
					CveID:        "ID123",
					Type:         enums.OwaspCategorySSRF,
					BaseSeverity: enums.SeverityTypeLow,
				},
				{
					CveID:        "ID123",
					Type:         enums.OwaspCategoryBrokenAccessControl,
					BaseSeverity: enums.SeverityTypeMedium,
				},
				{
					CveID:        "ID123",
					Type:         enums.OwaspCategoryBrokenAccessControl,
					BaseSeverity: enums.SeverityTypeCritical,
				},
				{
					CveID:        "ID123",
					Type:         enums.OwaspCategoryBrokenAccessControl,
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
					CveID:        "ID123",
					Type:         enums.OwaspCategoryBrokenAccessControl,
					BaseSeverity: enums.SeverityTypeLow,
				},
				{
					CveID:        "ID123",
					Type:         enums.OwaspCategoryBrokenAccessControl,
					BaseSeverity: enums.SeverityTypeMedium,
				},
				{
					CveID:        "ID123",
					Type:         enums.OwaspCategoryBrokenAccessControl,
					BaseSeverity: enums.SeverityTypeCritical,
				},
				{
					CveID:        "ID123",
					Type:         enums.OwaspCategoryBrokenAccessControl,
					BaseSeverity: enums.SeverityTypeUnknown,
				},
				{
					CveID:        "ID123",
					Type:         enums.OwaspCategoryBrokenAccessControl,
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
						{CveID: "CVE-1234", BaseCVSSScore: 5.0},
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
						{CveID: "CVE-1234", BaseCVSSScore: 5.0},
						{CveID: "CVE-5678", BaseCVSSScore: 7.5},
					}},
					{ID: 443, Vulnerabilities: []Vulnerability{
						{CveID: "CVE-91011", BaseCVSSScore: 9.8},
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
				{Type: enums.OwaspCategoryInjection, BaseCVSSScore: 5.0},
				{Type: enums.OwaspCategorySecurityLoggingAndMonitoringFailures, BaseCVSSScore: 3.0},
				{Type: enums.OwaspCategoryBrokenAccessControl, BaseCVSSScore: 9.5}, // Higher severity for Tipo A
			}},
			{Vulnerabilities: []Vulnerability{
				{Type: enums.OwaspCategoryBrokenAccessControl, BaseCVSSScore: 4.0},
				{Type: enums.OwaspCategoryInjection, BaseCVSSScore: 7.0}, // Higher severity for Tipo B
			}},
		},
	}

	expected := map[enums.OwaspCategory]int{
		enums.OwaspCategoryBrokenAccessControl:                  SeverityCritical,
		enums.OwaspCategoryInjection:                            SeverityHigh,
		enums.OwaspCategorySecurityLoggingAndMonitoringFailures: SeverityLow,
	}

	actual := result.GetSeverityPerTypeMap()

	for key, expectedValue := range expected {
		if actual[key] != expectedValue {
			t.Errorf("expected %d for %s, got %d", expectedValue, key, actual[key])
		}
	}
}
