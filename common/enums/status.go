package enums

import "fmt"

// ComponentStatus represents the status of a scan Service
type ServiceStatus int

const (
	StatusPending    ServiceStatus = iota
	StatusInProgress               // The service is currently running.
	StatusCompleted                // The service completed successfully.
	StatusFailed                   // The service failed due to an error.
	StatusCancelled                // The service was cancelled before completion.
)

var statusStrings = map[ServiceStatus]string{
	StatusPending:    "Pending",
	StatusInProgress: "InProgress",
	StatusCompleted:  "Completed",
	StatusFailed:     "Failed",
	StatusCancelled:  "Cancelled",
}

func (ss ServiceStatus) String() string {
	if str, exists := statusStrings[ss]; exists {
		return str
	}
	return "Unknown"
}

func ParseServiceStatus(status string) (ServiceStatus, error) {
	for k, v := range statusStrings {
		if v == status {
			return k, nil
		}
	}
	return -1, fmt.Errorf("invalid ServiceStatus: %s", status)
}
