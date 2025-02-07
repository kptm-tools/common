package validation

import (
	"fmt"
	"strings"

	"github.com/kptm-tools/common/common/pkg/enums"
)

type HostClassification struct {
	// Original input value
	RawValue string `json:"raw_value"`

	// Normalized and cleaned value
	NormalizedValue string `json:"normalized_value"`

	// The type of host (Domain, IP, or Subdomain)
	Type enums.TargetType `json:"type"`

	// Specific classification details
	Classification string `json:"classification"`

	// Resolved IP addresses
	ResolvedIPs []string `json:"resolved_ips,omitempty"`
}

func ClassifyHostValue(value string) (*HostClassification, error) {
	// Normalize the input
	normalizedValue := NormalizeURL(value)

	// Extract the base value (remove protocol)
	baseValue := strings.TrimPrefix(strings.TrimPrefix(normalizedValue, "http://"), "https://")

	// Check IP first
	if IsValidIPv4(baseValue) {
		return &HostClassification{
			RawValue:        value,
			NormalizedValue: normalizedValue,
			Type:            enums.IP,
			Classification:  "IPv4",
		}, nil
	}

	// Extract host name
	domain, err := ExtractHostName(normalizedValue)
	if err != nil {
		return nil, fmt.Errorf("failed to extract domain: %w", err)
	}

	// Split domain parts to check if we're dealing with a subdomain
	parts := strings.Split(domain, ".")

	// Determine host type
	switch {
	case len(parts) == 2:
		// Top-level domain (example.com)
		return &HostClassification{
			RawValue:        value,
			NormalizedValue: normalizedValue,
			Type:            enums.Domain,
			Classification:  "Top-Level Domain",
		}, nil

	case len(parts) > 2:
		// Subdomain (sub.example.com)
		return &HostClassification{
			RawValue:        value,
			NormalizedValue: normalizedValue,
			Type:            enums.Subdomain,
			Classification:  "Subdomain",
		}, nil
	default:
		return nil, fmt.Errorf("invalid domain format: %s", domain)
	}
}

func (hc *HostClassification) ExtractAndValidateDomain() (string, error) {
	var domain string
	var err error

	hostName, err := ExtractHostName(hc.NormalizedValue)
	if err != nil {
		return "", fmt.Errorf("failed to extract host name: %w", err)
	}

	if hc.Type == enums.Subdomain {
		domain, err = ExtractTopLevelDomain(hostName)
		if err != nil {
			return "", fmt.Errorf("failed to extract top level domain: %w", err)
		}
	} else {
		domain = hostName
	}

	if !IsValidDomain(domain) {
		return "", fmt.Errorf("invalid domain: %s", domain)
	}

	return domain, nil

}
