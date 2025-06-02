package enums

import "fmt"

// CVSSVersion representa la versión de CVSS que aceptamos en nuestros métricos.
type CVSSVersion string

const (
	CVSSv31 CVSSVersion = "3.1"
	CVSSv30 CVSSVersion = "3.0"
	CVSSv20 CVSSVersion = "2.0"
)

func IsValidVersion(v CVSSVersion) bool {
	switch v {
	case CVSSv31, CVSSv30, CVSSv20:
		return true
	default:
		return false
	}
}

// ParseCVSSVersion convierte un string a CVSSVersion, o devuelve error si no existe
func ParseCVSSVersion(s string) (CVSSVersion, error) {
	switch CVSSVersion(s) {
	case CVSSv31:
		return CVSSv31, nil
	case CVSSv30:
		return CVSSv30, nil
	case CVSSv20:
		return CVSSv20, nil
	}
	return "", fmt.Errorf("versión CVSS inválida: %q", s)
}
