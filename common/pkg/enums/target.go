package enums

// TargetType defines the type of the target being scanned, such as IP or Domain
type TargetType string

const (
	// IP represents a target of type IP address
	IP TargetType = "IP"

	// Domain represents a target of type domain name
	Domain TargetType = "Domain"

	// Subdomain represents a target of type subdomain
	Subdomain TargetType = "Subdomain"
)

func (tt TargetType) String() string {
	return string(tt)
}
