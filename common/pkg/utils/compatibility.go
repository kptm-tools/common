package utils

import (
	"errors"
	"fmt"

	"github.com/kptm-tools/common/common/pkg/customerrors"
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
		return hc.Type == enums.Domain || hc.Type == enums.Subdomain
	case enums.ToolDNSLookup:
		return hc.Type == enums.Domain || hc.Type == enums.Subdomain
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

// ValidateHostForTool validates a host value for a specific tool,
// *including* domain extraction and validation for tools.
func ValidateHostForTool(value string, tool enums.ToolName) (string, error) {
	// Classify the host
	hostClass, err := validation.ClassifyHostValue(value)
	if err != nil {
		return "", fmt.Errorf("failed to classify host value '%s': %w", value, err)
	}

	// Check tool compatibility
	checker := NewToolCompatibilityChecker()
	if !checker.CanRunTool(tool, hostClass) {
		return "", customerrors.NewToolIncompatibleError(tool, hostClass.Type.String())
	}
	if tool == enums.ToolDNSLookup || tool == enums.ToolWhoIs || tool == enums.ToolHarvester {
		domain, err := hostClass.GetBaseDomain()
		if err != nil {
			return "", fmt.Errorf("failed to extract and validate domain %w", err)
		}
		return domain, nil
	}

	return value, nil
}

func ClassifyValidationErrorCode(err error) enums.ErrorCode {
	var errIncompatibleTool *customerrors.ToolIncompatibleError
	if errors.As(err, &errIncompatibleTool) {
		return enums.ToolSkippedError
	}
	return enums.ValidationError
}
