package results

import (
	"encoding/json"
	"fmt"
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

func (r *NmapResult) String() string {
	data, err := json.MarshalIndent(r, "", " ")
	if err != nil {
		return ""
	}
	return string(data)
}

func (v *Vulnerability) BuildVulnersReferences() {
	if v.Type != "" && v.ID != "" {
		reference := buildVulnersReference(v.ID, v.Type)
		v.References = append(v.References, reference)
	}
}

func buildVulnersReference(id, vulnType string) string {
	return fmt.Sprintf("https://vulners.com/%s/%s", vulnType, id)
}
