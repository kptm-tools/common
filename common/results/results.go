package results

import (
	"encoding/json"
	"fmt"
)

// ScanResult represents the result of a scan operation.
// It contains the scan's unique ID and a collection of target-specific results.
type ScanResult struct {
	// ScanID is the unique identifier of the scan.
	ScanID string `json:"scan_id"`

	// Targets contains the results for each target included in the scan.
	Targets []TargetResult `json:"targets"`
}

// TargetResult represents the scan result for a specific target.
// It includes the target identifier and any data gathered during the scan.
type TargetResult struct {
	// Target is the domain or IP address being scanned.
	Target string `json:"target"`

	// Results holds the technical detailes gathered for the target,
	// stored as key-value pairs to accomodate varied scan types
	Results map[string]interface{} `json:"results"`
}

// String returns a formatted string representation of the TargetResult.
// It serializes the result to JSON for easy readability and debugging.
func (r *TargetResult) String() string {
	data, err := json.MarshalIndent(r, "", " ")
	if err != nil {
		return fmt.Sprintf("Error marshalling TargetResult: %v", err)
	}
	return fmt.Sprintf("Result\n%s", string(data))
}
