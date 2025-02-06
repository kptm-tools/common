package results

import "github.com/kptm-tools/common/common/pkg/enums"

// Target represents a scan target with its alias, value and type.
type Target struct {
	// Alias is a user-friendly name for the target
	Alias string `json:"alias"`

	// Value is the actual IP address or domain name of the target.
	Value string `json:"value"`

	// Type specifies whether the target is an IP or a Domain.
	Type enums.TargetType `json:"type"`
}
