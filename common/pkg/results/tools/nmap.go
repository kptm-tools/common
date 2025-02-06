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
}

type Vulnerability struct {
	ID          string   `json:"id"`
	Type        string   `json:"type"`
	CVSS        float64  `json:"cvss"`
	References  []string `json:"reference"`
	Exploitable bool     `json:"has_exploit"`
}

type SeverityCounts struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
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
			currentSeverity := MapCVSS(vuln.CVSS)
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
		switch MapCVSS(vuln.CVSS) {
		case SeverityLow:
			counts.Low++
		case SeverityMedium:
			counts.Medium++
		case SeverityHigh:
			counts.High++
		case SeverityCritical:
			counts.Critical++
		default:
			counts.Critical++
		}
	}

	return counts
}

func MapCVSS(cvss float64) int {
	// CVSS thresholds
	const (
		lowMax    = 4.0
		mediumMax = 7.0
		highMax   = 9.0
	)

	switch {
	case cvss < lowMax:
		return SeverityLow
	case cvss < mediumMax:
		return SeverityMedium
	case cvss < highMax:
		return SeverityHigh
	default:
		return SeverityCritical
	}
}

func buildVulnersReference(id, vulnType string) string {
	return fmt.Sprintf("https://vulners.com/%s/%s", vulnType, id)
}
