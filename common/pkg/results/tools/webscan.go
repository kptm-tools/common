package tools

import "github.com/kptm-tools/common/common/pkg/enums"

type InstanceAlert struct {
	ID        string           `json:"id"`
	URI       string           `json:"uri"`
	Method    enums.MethodType `json:"method"`
	Param     string           `json:"param"`
	Attack    string           `json:"attack"`
	Evidence  string           `json:"evidence"`
	OtherInfo string           `json:"other_info"`
}

type WebVulnerability struct {
	Name       string                      `json:"name"`
	Risk       enums.RiskCodeType          `json:"risk"`
	Instances  []InstanceAlert             `json:"instances"`
	Confidence enums.ConfidenceWebScanType `json:"confidence"`
	Solution   string                      `json:"solution"`
	Reference  string                      `json:"reference"`
	CweID      string                      `json:"cwe_id"`
	WascID     string                      `json:"wasc_id"`
}

type WebScanResult struct {
	ScanType           string             `json:"type"`
	WebVulnerabilities []WebVulnerability `json:"result"`
}

func (r *WebScanResult) GetToolName() enums.ToolName {
	return enums.ToolWebScan
}
