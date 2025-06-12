package tools

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
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
	MostLikelyOS OSData     `json:"most_likely_os"`
}

type OSData struct {
	Name            string          `json:"name"`
	Accuracy        int             `json:"accuracy"`
	Family          string          `json:"family"`
	Type            string          `json:"type"`
	FingerPrint     string          `json:"fingerprint"`
	CPE             string          `json:"cpe"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
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

type CVSSMetric struct {
	Version             enums.CVSSVersion
	BaseScore           float64
	ImpactScore         float64
	Severity            enums.SeverityType
	Access              enums.AccessType
	Complexity          enums.ComplexityType
	PrivilegesRequired  enums.PrivilegesRequiredType
	IntegrityImpact     enums.ImpactType
	AvailabilityImpact  enums.ImpactType
	ExploitabilityScore float64
	Exploitability      enums.ExploitabilityType
}

type Vulnerability struct {
	ID     uuid.UUID `json:"id"`
	HostID uuid.UUID `json:"host_id"`
	ScanID uuid.UUID `json:"scan_id"`
	CveID  string    `json:"cve_id"`

	Type          enums.OwaspCategory `json:"type"`
	BaseCVSSScore float64             `json:"cvss"`
	References    []string            `json:"reference"`

	Metrics []CVSSMetric `json:"metrics"`

	CWERemediation []CWERemediation `json:"remediation"`

	Description        string                       `json:"description,omitempty"`
	Access             enums.AccessType             `json:"access,omitempty"`
	Complexity         enums.ComplexityType         `json:"complexity,omitempty"`
	PrivilegesRequired enums.PrivilegesRequiredType `json:"privileges_required"`
	Likelihood         enums.LikelyhoodType         `json:"likelihood,omitempty"`
	RiskScore          float64                      `json:"risk_score,omitempty"`
	ImpactScore        float64                      `json:"impact_score,omitempty"`

	Exploit Exploit `json:"exploit"`

	IntegrityImpact    enums.ImpactType   `json:"integrity_impact"`
	AvailabilityImpact enums.ImpactType   `json:"availabilityImpact"`
	BaseSeverity       enums.SeverityType `json:"base_severity"`

	AnalystComment string          `json:"analyst_comment,omitempty"`
	VendorComments []VendorComment `json:"vendor_comments,omitempty"`

	Published   time.Time `json:"published"`
	LastUpdated time.Time `json:"last_updated"`

	EPSSScore      float64   `json:"epss_score,omitempty"`
	EPSSPercentile float64   `json:"epss_percentile,omitempty"`
	EPSSDate       time.Time `json:"epss_date,omitempty"`
}

type Exploit struct {
	Score          float64                  `json:"exploit_score"`
	Exploitability enums.ExploitabilityType `json:"exploitability"`
}

type VendorComment struct {
	Organization string    `json:"organization"`
	Comment      string    `json:"comment"`
	LastModified time.Time `json:"last_modified"`
}

type SeverityCounts struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	None     int `json:"none"`
	Unknown  int `json:"unknown"`
}

type CWERemediation struct {
	ID                 string    `json:"cwe_id"`
	MitigationID       string    `json:"mitigation_id"`
	Title              string    `json:"title"`
	Phase              []string  `json:"phase"`
	Description        string    `json:"description"`
	Effectiveness      string    `json:"effectiveness"`
	EffectivenessNotes string    `json:"effectiveness_notes"`
	LastUpdated        time.Time `json:"last_updated"`
}

// ScannedPortsSummary returns a concise summary of the NmapResult for logging purposes.
func (r *NmapResult) ScannedPortsSummary() string {
	severityCounts := GetSeverityCounts(r.GetAllVulnerabilities())
	return fmt.Sprintf(
		"Host %s (%s), Ports: %d, Vulnerabilities (Critical: %d, High %d, Medium: %d, Low: %d), OS: %+v",
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
	severityCounts := GetSeverityCounts(r.GetAllVulnerabilities())
	return slog.GroupValue(
		slog.String("host_name", r.HostName),
		slog.String("host_address", r.HostAddress),
		slog.Int("ports_scanned", len(r.ScannedPorts)),
		slog.Group("most_likely_os",
			slog.String("name", r.MostLikelyOS.Name),
			slog.Int("accuracy", r.MostLikelyOS.Accuracy),
			slog.String("family", r.MostLikelyOS.Family),
			slog.String("fingerprint", r.MostLikelyOS.FingerPrint),
			slog.String("cpe", r.MostLikelyOS.CPE),
			slog.Int("vulnerabilities", len(r.MostLikelyOS.Vulnerabilities))),
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

func (r *NmapResult) GetAllVulnerabilities() []Vulnerability {
	var vulns []Vulnerability
	for _, portData := range r.ScannedPorts {
		vulns = append(vulns, portData.Vulnerabilities...)
	}
	return vulns
}

func (r *NmapResult) TotalVulnerabilities() int {
	return len(r.GetAllVulnerabilities())
}

func (r *NmapResult) GetSeverityPerTypeMap() map[enums.OwaspCategory]int {
	severityMap := make(map[enums.OwaspCategory]int)

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

func GetSeverityCounts(vulns []Vulnerability) SeverityCounts {
	counts := SeverityCounts{}

	for _, vuln := range vulns {
		switch vuln.BaseSeverity {
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
