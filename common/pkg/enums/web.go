package enums

type MethodType string

const (
	MethodGet    MethodType = "GET"
	MethodPost   MethodType = "POST"
	MethodPut    MethodType = "PUT"
	MethodPatch  MethodType = "PATCH"
	MethodDelete MethodType = "DELETE"
)

type RiskCodeType string

const (
	RiskCodeInformational RiskCodeType = "Informational"
	RiskCodeLow           RiskCodeType = "Low"
	RiskCodeMedium        RiskCodeType = "Medium"
	RiskCodeHigh          RiskCodeType = "High"
)

func (r RiskCodeType) String() string {
	return string(r)
}

type ConfidenceWebScanType string

const (
	ConfidenceFalsePositive ConfidenceWebScanType = "FalsePositive"
	ConfidenceLow           ConfidenceWebScanType = "Low"
	ConfidenceMedium        ConfidenceWebScanType = "Medium"
	ConfidenceHigh          ConfidenceWebScanType = "High"
)

func (c ConfidenceWebScanType) String() string { return string(c) }
