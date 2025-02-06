package validation

import "net"

// IsValidIPv4 validates whether a string is a valid IPv4 address.
func IsValidIPv4(ip string) bool {
	return net.ParseIP(ip) != nil && net.ParseIP(ip).To4() != nil

}
