package results

type NmapResult struct {
	HostName     string         `json:"host_name"`
	HostAddress  string         `json:"host_address"`
	ScannedPorts []NmapPortData `json:"scanned_ports"`
	OSFamily     string         `json:"os_family"`
}

type NmapPortData struct {
	ID       uint16  `xml:"portid,attr" json:"id"`
	Protocol string  `xml:"protocol,attr" json:"protocol"`
	Service  Service `xml:"service" json:"service"`
	State    string  `xml:"state" json:"state"`
}

type Service struct {
	Name       string `json:"name"`
	Version    string `json:"version"`
	Confidence int    `json:"confidence"`
}
