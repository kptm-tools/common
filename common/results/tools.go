package results

import (
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/kptm-tools/common/common/enums"
)

// ToolError represents a structured error for tool results
type ToolError struct {
	Code    enums.ErrorCode `json:"code"`
	Message string          `json:"message"`
}

// ToolResult represents the scan result for a specific tool.
type ToolResult struct {
	Tool      enums.ToolName `json:"tool_name"`
	Result    interface{}    `json:"result,omitempty"`
	Err       *ToolError     `json:"error,omitempty"`
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

// LogValue creates a standard structured log representation for logging.
func (r *ToolResult) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("tool_name", string(r.Tool)),
		slog.Any("result", r.Result),
		slog.Any("error", slog.GroupValue(
			slog.String("code", string(r.Err.Code)),
			slog.String("message", r.Err.Message),
		)),
		slog.Int64("timestamp", r.Timestamp),
	)
}
