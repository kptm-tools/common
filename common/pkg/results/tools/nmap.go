package tools

import (
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/kptm-tools/common/common/pkg/enums"
)

const (
	SeverityLow      = 1
	SeverityMedium   = 2
	SeverityHigh     = 3
	SeverityCritical = 4
)

type NmapResult struct {
	HostName     string     `json:"host_name"`
	HostAddress  string     `json:"host_address"`
	ScannedPorts []PortData `json:"scanned_ports"`
	MostLikelyOS string     `json:"most_likely_os"`
}

type PortData struct {
	ID              uint16          `xml:"portid,attr" json:"id"`
	Protocol        string          `xml:"protocol,attr" json:"protocol"`
	Service         Service         `xml:"service" json:"service"`
	Product         string          `xml:"product" json:"product"`
	State           string          `xml:"state" json:"state"`
	Vulnerabilities []Vulnerability `xml:"vulnerabilities" json:"vulnerabilities"`
}

type Service struct {
	Name       string `json:"name"`
	Version    string `json:"version"`
	Confidence int    `json:"confidence"`
	CPE        string `json:"cpe"`
}

type Vulnerability struct {
	ID            string   `json:"id"`
	Type          string   `json:"type"`
	BaseCVSSScore float64  `json:"cvss"`
	References    []string `json:"reference"`
	Exploitable   bool     `json:"has_exploit"`

	Description        string                       `json:"description,omitempty"`
	Access             enums.AccessType             `json:"access,omitempty"`
	Complexity         enums.ComplexityType         `json:"complexity,omitempty"`
	PrivilegesRequired enums.PrivilegesRequiredType `json:"privileges_required"`
	Likelihood         string                       `json:"likelihood,omitempty"`
	RiskScore          float64                      `json:"risk_score,omitempty"`
	ImpactScore        float64                      `json:"impact_score,omitempty"`

	IntegrityImpact    enums.ImpactType   `json:"integrity_impact"`
	AvailabilityImpact enums.ImpactType   `json:"availabilityImpact"`
	BaseSeverity       enums.SeverityType `json:"base_severity"`

	Published   string `json:"published"`
	LastUpdated string `json:"last_updated"`
}

type SeverityCounts struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	None     int `json:"none"`
	Unknown  int `json:"unknown"`
}

// ScannedPortsSummary returns a concise summary of the NmapResult for logging purposes.
func (r *NmapResult) ScannedPortsSummary() string {
	severityCounts := GetSeverityCounts(r.GetAllVulnerabilites())
	return fmt.Sprintf(
		"Host %s (%s), Ports: %d, Vulnerabilities (Critical: %d, High %d, Medium: %d, Low: %d), OS: %s",
		r.HostName,
		r.HostAddress,
		len(r.ScannedPorts),
		severityCounts.Critical,
		severityCounts.High,
		severityCounts.Medium,
		severityCounts.Low,
		r.MostLikelyOS,
	)
}

// LogValue creates a standard structured log representation for logging.
func (r *NmapResult) LogValue() slog.Value {
	severityCounts := GetSeverityCounts(r.GetAllVulnerabilites())
	return slog.GroupValue(
		slog.String("host_name", r.HostName),
		slog.String("host_address", r.HostAddress),
		slog.Int("ports_scanned", len(r.ScannedPorts)),
		slog.String("most_likely_os", r.MostLikelyOS),
		slog.Int("vulnerabilities_critical", severityCounts.Critical),
		slog.Int("vulnerabilities_high", severityCounts.High),
		slog.Int("vulnerabilities_medium", severityCounts.Medium),
		slog.Int("vulnerabilities_low", severityCounts.Low),
	)
}

func (r *NmapResult) ToJSON() string {
	data, err := json.MarshalIndent(r, "", " ")
	if err != nil {
		return ""
	}
	return string(data)
}

func (r *NmapResult) GetAllVulnerabilites() []Vulnerability {
	var vulns []Vulnerability
	for _, portData := range r.ScannedPorts {
		vulns = append(vulns, portData.Vulnerabilities...)
	}
	return vulns
}

func (r *NmapResult) TotalVulnerabilities() int {
	return len(r.GetAllVulnerabilites())
}

func (r *NmapResult) GetSeverityPerTypeMap() map[string]int {
	severityMap := make(map[string]int)

	for _, port := range r.ScannedPorts {
		for _, vuln := range port.Vulnerabilities {
			currentSeverity := MapCVSS(vuln.BaseCVSSScore).Int()
			if maxSeverity, exists := severityMap[vuln.Type]; exists {
				if currentSeverity > maxSeverity {
					severityMap[vuln.Type] = currentSeverity
				}
			} else {
				severityMap[vuln.Type] = currentSeverity
			}
		}
	}

	return severityMap
}

func (r *NmapResult) GetOpenPorts() []PortData {
	var openPorts []PortData
	for _, port := range r.ScannedPorts {
		if port.State == "open" {
			openPorts = append(openPorts, port)
		}
	}
	return openPorts
}

func (r *NmapResult) GetToolName() enums.ToolName {
	return enums.ToolNmap
}

func (v *Vulnerability) BuildVulnersReferences() {
	if v.Type != "" && v.ID != "" {
		reference := buildVulnersReference(v.ID, v.Type)
		v.References = append(v.References, reference)
	}
}

func GetSeverityCounts(vulns []Vulnerability) SeverityCounts {
	counts := SeverityCounts{}

	for _, vuln := range vulns {
		switch MapCVSS(vuln.BaseCVSSScore) {
		case enums.SeverityTypeNone:
			counts.None++
		case enums.SeverityTypeLow:
			counts.Low++
		case enums.SeverityTypeMedium:
			counts.Medium++
		case enums.SeverityTypeHigh:
			counts.High++
		case enums.SeverityTypeCritical:
			counts.Critical++
		default:
			counts.Unknown++
		}
	}

	return counts
}

func MapCVSS(cvss float64) enums.SeverityType {
	// CVSS thresholds
	const (
		none      = 0.0
		lowMax    = 4.0
		mediumMax = 7.0
		highMax   = 9.0
	)

	switch {
	case cvss == none:
		return enums.SeverityTypeNone
	case cvss < lowMax:
		return enums.SeverityTypeLow
	case cvss < mediumMax:
		return enums.SeverityTypeMedium
	case cvss < highMax:
		return enums.SeverityTypeHigh
	default:
		return enums.SeverityTypeCritical
	}
}

func buildVulnersReference(id, vulnType string) string {
	return fmt.Sprintf("https://vulners.com/%s/%s", vulnType, id)
}
