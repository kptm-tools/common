package results

import (
	"time"
)

const GoogleResolver = "8.8.8.8:53" // Google DNS Server

type DNSRecordType string

const (
	ARecord      DNSRecordType = "A"
	AAAARecord   DNSRecordType = "AAAA"
	CNAMERecord  DNSRecordType = "CNAME"
	TXTRecord    DNSRecordType = "TXT"
	NSRecord     DNSRecordType = "NS"
	MXRecord     DNSRecordType = "MX"
	SOARecord    DNSRecordType = "SOA"
	DNSKeyRecord DNSRecordType = "DNSKey"
)

// DNSLookupResult represents the result of a DNS Lookup.
type DNSLookupResult struct {
	Domain         string        `json:"domain"`          // The domain name being queried
	DNSRecords     []DNSRecord   `json:"dns_records"`     // A list of DNS records
	DNSSECEnabled  bool          `json:"dnssec_enabled"`  // Indicated if DNSSEC is enabled
	LookupDuration time.Duration `json:"lookup_duration"` // Time taken to perform the lookup
	CreatedAt      time.Time     `json:"created_at"`      // Timestamp when the lookup was performed
	Error          string        `json:"error,omitempty"` // String containing encountered errors
}

// DNSRecord represents a DNS (Domain Name Service) record.
type DNSRecord struct {
	Type     DNSRecordType `json:"type"`               // Record type (A, AAAA, MX, etc.)
	Name     string        `json:"name"`               // The queried domain name
	TTL      int           `json:"ttl"`                // Time-to-live in seconds
	Value    interface{}   `json:"value"`              // Record-specific value (string, struct, etc.)
	Priority *int          `json:"priority,omitempty"` // Optional priority for MX records
}

// MailExchange represents an MX (Mail Exchange) record.
type MailExchange struct {
	Host     string `json:"host"`     // The mail server host
	Priority int    `json:"priority"` // Preference for mail server
}

// StartOfAuthority represents an SOA (Start of Authority) record.
type StartOfAuthority struct {
	PrimaryNS  string `json:"primary_ns"`  // Primary name server
	AdminEmail string `json:"admin_email"` // Admin email address
	Serial     int    `json:"serial"`      // Serial number
	Refresh    int    `json:"refresh"`     // Refresh interval (in seconds)
	Retry      int    `json:"retry"`       // Retry interval (in seconds)
	Expire     int    `json:"expire"`      // Expiration limit (in seconds)
	MinimumTTL int    `json:"minimum_ttl"` // Minimum TTL (in seconds)
}

// DNSKey represents a DNSKEY record.
type DNSKey struct {
	Flags     int `json:"flags"`     // Flags of the key
	Protocol  int `json:"protocol"`  // Protocol of the key
	Algorithm int `json:"algorithm"` // Algorithm of the key
}

func HasDNSKeyRecord(records []DNSRecord) bool {
	for _, record := range records {
		if record.Type == DNSKeyRecord {
			return true
		}
	}
	return false
}
