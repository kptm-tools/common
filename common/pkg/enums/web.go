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
	RiskCodeInformational RiskCodeType = "0"
	RiskCodeLow           RiskCodeType = "1"
	RiskCodeMedium        RiskCodeType = "2"
	RiskCodeHigh          RiskCodeType = "3"
)

type ConfidenceWebScanType string

const (
	ConfidenceFalsePositive ConfidenceWebScanType = "0"
	ConfidenceLow           ConfidenceWebScanType = "1"
	ConfidenceMedium        ConfidenceWebScanType = "2"
	ConfidenceHigh          ConfidenceWebScanType = "3"
)
