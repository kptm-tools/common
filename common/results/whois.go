package results

import (
	"encoding/json"

	whoisparser "github.com/likexian/whois-parser"
	"golang.org/x/exp/slog"
)

type WhoIsResult struct {
	RawData *whoisparser.WhoisInfo `json:"raw_data"`
	Error   string                 `json:"error,omitempty"`
}

// LogValue creates a standard structured log representation for logging.
func (r *WhoIsResult) LogValue() slog.Value {
	if r.RawData == nil {
		return slog.GroupValue(
			slog.String("error", r.Error),
		)
	}

	domain := r.RawData.Domain
	registrar := r.RawData.Registrar
	registrant := r.RawData.Registrant

	return slog.GroupValue(
		slog.Group("domain",
			slog.String("id", domain.ID),
			slog.String("domain", domain.Domain),
			slog.String("punycode", domain.Punycode),
			slog.String("name", domain.Name),
			slog.String("extension", domain.Extension),
			slog.String("whois_server", domain.WhoisServer),
			slog.Any("status", domain.Status),
			slog.Any("name_servers", domain.NameServers),
			slog.Bool("dnssec", domain.DNSSec),
			slog.String("created_date", domain.CreatedDate),
			slog.String("updated_date", domain.UpdatedDate),
			slog.String("expiration_date", domain.ExpirationDate),
		),
		slog.Group("registrar",
			slog.String("name", registrar.Name),
			slog.String("organization", registrar.Organization),
			slog.String("email", registrar.Email),
			slog.String("phone", registrar.Phone),
		),
		slog.Group("registrant",
			slog.String("name", registrant.Name),
			slog.String("organization", registrant.Organization),
			slog.String("city", registrant.City),
			slog.String("country", registrant.Country),
			slog.String("email", registrant.Email),
		),
		slog.String("error", r.Error),
	)
}

// ToJSON returns a visually friendly JSON string which can be displayed with fmt.
func (r *WhoIsResult) ToJSON() string {
	data, err := json.MarshalIndent(r, "", " ")
	if err != nil {
		return ""
	}
	return string(data)
}
