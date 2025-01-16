package results

import (
	"encoding/json"
	"fmt"

	"github.com/kptm-tools/common/common/enums"
)

// TargetResult represents the scan result for a specific target.
// It includes the target identifier and any data gathered during the scan.
type TargetResult struct {
	// Target is the domain or IP address being scanned.
	Target string `json:"target"`

	// Results holds the technical detailes gathered for the target,
	// stored as key-value pairs to accomodate varied scan types
	Results map[enums.ServiceName]interface{} `json:"results"`
}

// ToJSON returns a detailed JSON representation of the TargetResult.
func (r *TargetResult) ToJSON() (string, error) {
	data, err := json.MarshalIndent(r, "", " ")
	if err != nil {
		return "", fmt.Errorf("Error marshalling TargetResult: %w", err)
	}
	return string(data), nil
}
