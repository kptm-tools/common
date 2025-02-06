package utils

import (
	"fmt"

	"github.com/kptm-tools/common/common/pkg/enums"
	"github.com/kptm-tools/common/common/pkg/utils/validation"
)

type ToolCompatibilityChecker interface {
	// CanRunTool checks if a specific tool can be run on a given host classification
	CanRunTool(toolName enums.ToolName, hc *validation.HostClassification) bool
}

// DefaultToolCompatibilityChecker provides a standard implementation
type DefaultToolCompatibilityChecker struct{}

func (c *DefaultToolCompatibilityChecker) CanRunTool(toolName enums.ToolName, hc *validation.HostClassification) bool {

	switch toolName {
	case enums.ToolWhoIs:
		// Only works with top-level domains
		return hc.Type == enums.Domain
	case enums.ToolDNSLookup:
		return hc.Type == enums.Domain
	case enums.ToolHarvester:
		return hc.Type == enums.Domain || hc.Type == enums.Subdomain
	case enums.ToolNmap:
		return hc.Type == enums.IP ||
			hc.Type == enums.Domain ||
			hc.Type == enums.Subdomain

	default:
		return false
	}
}

// NewToolCompatibilityChecker creates a new default compatibility checker
func NewToolCompatibilityChecker() ToolCompatibilityChecker {
	return &DefaultToolCompatibilityChecker{}
}

// ValidateHostForTool validates a host value for a specific tool
func ValidateHostForTool(value string, tool enums.ToolName) error {
	// Classify the host
	hostClass, err := validation.ClassifyHostValue(value)
	if err != nil {
		return fmt.Errorf("failed to classify host value: %w", err)
	}

	// Check tool compatibility
	checker := NewToolCompatibilityChecker()
	if !checker.CanRunTool(tool, hostClass) {
		return fmt.Errorf("tool %s cannot run on host type %s",
			tool.String(),
			hostClass.Type.String())
	}

	return nil
}
