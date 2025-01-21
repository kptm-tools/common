package results

import (
	"encoding/json"
	"fmt"

	"github.com/kptm-tools/common/common/enums"
)

// ToolResult represents the scan result for a specific tool.
type ToolResult struct {
	Tool      enums.ToolName `json:"tool_name"`
	Success   bool           `json:"success"`
	Result    interface{}    `json:"result"`
	Err       error          `json:"error"`
	Timestamp int64          `json:"timestamp"`
}

// ToJSON returns a detailed JSON representation of the TargetResult.
func (r *ToolResult) ToJSON() (string, error) {
	data, err := json.MarshalIndent(r, "", " ")
	if err != nil {
		return "", fmt.Errorf("Error marshalling ToolResult: %w", err)
	}
	return string(data), nil
}
