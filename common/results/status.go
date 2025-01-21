package results

import "github.com/kptm-tools/common/common/enums"

type ScanStatus struct {
	// ScanID is the unique ideantifier of the scan
	ScanID string

	// Status of the overall scan
	Status string

	// Status of each individual service in the scan
	ServicesStatus map[enums.ToolName]enums.ScanStatus

	// Error details of each tool in the scan
	ErrorDetail map[enums.ToolName]string
}
