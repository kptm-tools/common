package results

import (
	"encoding/json"
	"log/slog"
)

type HarvesterResult struct {
	Emails     []string `json:"emails"`          // A list of harvested emails
	Subdomains []string `json:"subdomains"`      // A list of harvested subdomains
	Error      string   `json:"error,omitempty"` // String contianing encountered errors
}

// LogValue creates a standard structured log representation for logging.
func (r *HarvesterResult) LogValue() slog.Value {
	return slog.GroupValue(
		slog.Any("error", r.Error),
		slog.Int("email_count", len(r.Emails)),
		slog.Any("emails", r.Emails),
		slog.Int("subdomain_count", len(r.Subdomains)),
		slog.Any("subdomains", r.Subdomains),
	)
}

// ToJSON returns a visually friendly JSON string which can be displayed with fmt.
func (r *HarvesterResult) ToJSON() string {
	data, err := json.MarshalIndent(r, "", " ")
	if err != nil {
		return ""
	}
	return string(data)
}
