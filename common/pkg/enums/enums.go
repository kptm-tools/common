package enums

var AllWeaknessTypes []WeaknessType
var AllScanStatus []ScanStatus

func init() {
	for i := 0; i <= int(WeaknessNoInfo); i++ {
		AllWeaknessTypes = append(AllWeaknessTypes, WeaknessType(i))
	}
	for i := 0; i <= int(StatusScheduled); i++ {
		AllScanStatus = append(AllScanStatus, ScanStatus(i))
	}
}
