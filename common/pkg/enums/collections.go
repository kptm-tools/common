package enums

var (
	AllOwaspCategories = []OwaspCategory{
		OwaspCategoryBrokenAccessControl,
		OwaspCategoryCryptographicFailures,
		OwaspCategoryInjection,
		OwaspCategoryInsecureDesign,
		OwaspCategorySecurityMisconfiguration,
		OwaspCategoryVulnerableAndOutdatedComponents,
		OwaspCategoryIdentificationAndAuthenticationFailures,
		OwaspCategorySoftwareAndDataIntegrityFailures,
		OwaspCategorySecurityLoggingAndMonitoringFailures,
		OwaspCategorySSRF,
		OwaspCategoryOther,
		OwaspCategoryNoInfo,
	}
	AllScanStatus []ScanStatus
)

func init() {
	for i := 0; i <= int(StatusScheduled); i++ {
		AllScanStatus = append(AllScanStatus, ScanStatus(i))
	}
}
