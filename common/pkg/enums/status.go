package enums

import "fmt"

// ComponentStatus represents the status of a scan Service
type ScanStatus int

const (
	StatusPending    ScanStatus = iota
	StatusInProgress            // The scan is currently running.
	StatusCompleted             // The scan completed successfully.
	StatusFailed                // The scan failed due to an error.
	StatusCancelled             // The scan was cancelled before completion.
)

var statusStrings = map[ScanStatus]string{
	StatusPending:    "Pending",
	StatusInProgress: "InProgress",
	StatusCompleted:  "Completed",
	StatusFailed:     "Failed",
	StatusCancelled:  "Cancelled",
}

func (ss ScanStatus) String() string {
	if str, exists := statusStrings[ss]; exists {
		return str
	}
	return "Unknown"
}

func ParseServiceStatus(status string) (ScanStatus, error) {
	for k, v := range statusStrings {
		if v == status {
			return k, nil
		}
	}
	return -1, fmt.Errorf("invalid ServiceStatus: %s", status)
}
