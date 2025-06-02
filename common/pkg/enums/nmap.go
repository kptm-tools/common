package enums

// CVSSVersion representa la versión de CVSS que aceptamos en nuestros métricos.
type CVSSVersion string

const (
	CVSSv31 CVSSVersion = "3.1"
	CVSSv30 CVSSVersion = "3.0"
	CVSSv20 CVSSVersion = "2.0"
)
