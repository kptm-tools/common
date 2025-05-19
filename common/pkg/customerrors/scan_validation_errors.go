package customerrors

import (
	"fmt"

	"github.com/kptm-tools/common/common/pkg/enums"
)

// ToolIncompatibleError indicates that a specific tool is not compatible with
// the host's classification.
type ToolIncompatibleError struct {
	ToolName string // String representation of the tool name
	HostType string // String representation of the host type (e.g., "IP", "Domain", "Subdomain")
	Reason   string // Brief explanation of the incompatibility.
}

func (e *ToolIncompatibleError) Error() string {
	return fmt.Sprintf("tools '%s' is incompatible with host type '%s': %s", e.ToolName, e.HostType, e.Reason)
}

// NewToolIncompatibleError creates a new ToolIncompatibleError.
func NewToolIncompatibleError(tool enums.ToolName, hostType string) error {
	return &ToolIncompatibleError{
		ToolName: tool.String(),
		HostType: hostType,
		Reason:   "type mismatch for tool operation",
	}
}
