package tools

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/kptm-tools/common/common/pkg/enums"
)

type IToolResult interface {
	GetToolName() enums.ToolName
}

// ToolError represents a structured error for tool results
type ToolError struct {
	Code    enums.ErrorCode `json:"code"`
	Message string          `json:"message"`
}

func (t *ToolError) Error() string {
	return t.Message
}

// ToolResult represents the scan result for a specific tool.
type ToolResult struct {
	Tool      enums.ToolName `json:"tool_name"`
	Result    IToolResult    `json:"result,omitempty"`
	Err       *ToolError     `json:"error,omitempty"`
	Timestamp time.Time      `json:"timestamp"`
}

// ToJSON returns a detailed JSON representation of the TargetResult.
func (r *ToolResult) ToJSON() (string, error) {
	data, err := json.MarshalIndent(r, "", " ")
	if err != nil {
		return "", fmt.Errorf("Error marshalling ToolResult: %w", err)
	}
	return string(data), nil
}

func (r *ToolResult) UnmarshalJSON(data []byte) error {
	// Create a temp struct to unmarshal the base fields
	type Alias ToolResult
	aux := &struct {
		Result json.RawMessage `json:"result,omitempty"`
		*Alias
	}{
		Alias: (*Alias)(r),
	}

	if err := json.Unmarshal(data, aux); err != nil {
		return fmt.Errorf("failed to unmarshal ToolResult: %w", err)
	}

	// Determine the concrete type for Result based on the Tool field
	switch r.Tool {
	case enums.ToolWhoIs:
		var whoisResult WhoIsResult
		if err := json.Unmarshal(aux.Result, &whoisResult); err != nil {
			return fmt.Errorf("failed to unmarshal WhoIsResult: %w", err)
		}
		r.Result = &whoisResult
	case enums.ToolHarvester:
		var harvesterResult HarvesterResult
		if err := json.Unmarshal(aux.Result, &harvesterResult); err != nil {
			return fmt.Errorf("failed to unmarshal HarvesterResult: %w", err)
		}
		r.Result = &harvesterResult
	case enums.ToolDNSLookup:
		var dnsLookupResult DNSLookupResult
		if err := json.Unmarshal(aux.Result, &dnsLookupResult); err != nil {
			return fmt.Errorf("failed to unmarshal DNSLookupResult: %w", err)
		}
		r.Result = &dnsLookupResult
	case enums.ToolNmap:
		var nmapResult NmapResult
		if err := json.Unmarshal(aux.Result, &nmapResult); err != nil {
			return fmt.Errorf("failed to unmarshal NmapResult: %w", err)
		}
		r.Result = &nmapResult
	default:
		return fmt.Errorf("unsupported tool name: %s", r.Tool)
	}

	return nil
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
		slog.Time("timestamp", r.Timestamp),
	)
}
