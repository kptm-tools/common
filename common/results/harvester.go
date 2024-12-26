package results

type HarvesterResult struct {
	Emails     []string `json:"emails"`          // A list of harvested emails
	Subdomains []string `json:"subdomains"`      // A list of harvested subdomains
	Error      string   `json:"error,omitempty"` // String contianing encountered errors
}
