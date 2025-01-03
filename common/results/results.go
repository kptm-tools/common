package results

import (
	"encoding/json"
	"fmt"
)

type ServiceName string

const (
	ServiceWhoIs     ServiceName = "WhoIs"
	ServiceHarvester ServiceName = "Harvester"
	ServiceDNSLookup ServiceName = "DNSLookup"
	ServiceNmap      ServiceName = "Nmap"
)

// TargetResult represents the scan result for a specific target.
// It includes the target identifier and any data gathered during the scan.
type TargetResult struct {
	// Target is the domain or IP address being scanned.
	Target string `json:"target"`

	// Results holds the technical detailes gathered for the target,
	// stored as key-value pairs to accomodate varied scan types
	Results map[ServiceName]interface{} `json:"results"`
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
