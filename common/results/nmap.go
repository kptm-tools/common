package results

type NmapResult struct {
	HostName     string     `json:"host_name"`
	HostAddress  string     `json:"host_address"`
	ScannedPorts []PortData `json:"scanned_ports"`
	OSFamily     string     `json:"os_family"`
}

type PortData struct {
	ID       uint16  `xml:"portid,attr" json:"id"`
	Protocol string  `xml:"protocol,attr" json:"protocol"`
	Service  Service `xml:"service" json:"service"`
	Product  string  `xml:"product" json:"product"`
	State    string  `xml:"state" json:"state"`
}

type Service struct {
	Name       string `json:"name"`
	Version    string `json:"version"`
	Confidence int    `json:"confidence"`
}

type Vulnerability struct {
	ID         string   `json:"id"`
	CVSS       float64  `json:"cvss"`
	References []string `json:"reference"`
	HasExploit bool     `json:"has_exploit"`
}
