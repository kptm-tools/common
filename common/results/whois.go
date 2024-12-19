package results

import whoisparser "github.com/likexian/whois-parser"

type WhoIsResult struct {
	RawData *whoisparser.WhoisInfo `json:"raw_data"`
	Error   string                 `json:"error,omitempty"`
}
