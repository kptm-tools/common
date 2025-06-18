package enums

import (
	"fmt"
)

type ToolName string

const (
	ToolWhoIs     ToolName = "WhoIs"
	ToolHarvester ToolName = "Harvester"
	ToolDNSLookup ToolName = "DNSLookup"
	ToolNmap      ToolName = "Nmap"
	ToolWebScan   ToolName = "WebScan"
)

var ToolSubjectMap = map[ToolName]EventSubjectName{
	ToolWhoIs:     WhoIsEventSubject,
	ToolHarvester: HarvesterEventSubject,
	ToolDNSLookup: DNSLookupEventSubject,
	ToolNmap:      NmapEventSubject,
	ToolWebScan:   WebScanEventSubject,
}

func (t ToolName) String() string {
	return string(t)
}

func GetToolSubjectName(toolName ToolName) (string, error) {
	subject, exists := ToolSubjectMap[toolName]
	if !exists {
		return "", fmt.Errorf("invalid tool: %s", toolName)
	}
	return string(subject), nil
}
