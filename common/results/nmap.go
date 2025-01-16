package results

import (
	"encoding/json"
	"fmt"
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

func (r *NmapResult) String() string {
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
			currentSeverity := mapCVSS(vuln.CVSS)
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

func (v *Vulnerability) BuildVulnersReferences() {
	if v.Type != "" && v.ID != "" {
		reference := buildVulnersReference(v.ID, v.Type)
		v.References = append(v.References, reference)
	}
}

func GetSeverityCounts(vulns []Vulnerability) SeverityCounts {
	counts := SeverityCounts{}

	for _, vuln := range vulns {
		switch mapCVSS(vuln.CVSS) {
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

func mapCVSS(cvss float64) int {
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
