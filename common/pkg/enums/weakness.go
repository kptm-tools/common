package enums

import "strings"

type WeaknessType int

const (
	WeaknessSSRF WeaknessType = iota
	WeaknessSoftwareAndDataIntegrityFailures
	WeaknessCryptographicFailures
	WeaknessIdentificationAndAuthenticationFailures
	WeaknessBrokenAccessControl
	WeaknessSecurityLoggingAndMonitoringFailures
	WeaknessInjection
	WeaknessVulnerableAndOutdatedComponents
	WeaknessInsecureDesign
	WeaknessSecurityMisconfiguration
	WeaknessOther
	WeaknessNoInfo
)

var weaknessStrings = map[WeaknessType]string{
	WeaknessSSRF:                                    "Server-Side Request Forgery (SSRF)",
	WeaknessSoftwareAndDataIntegrityFailures:        "Software and Data Integrity Failures",
	WeaknessCryptographicFailures:                   "Cryptographic Failures",
	WeaknessIdentificationAndAuthenticationFailures: "Identification and Authentication Failures",
	WeaknessBrokenAccessControl:                     "Broken Access Control",
	WeaknessSecurityLoggingAndMonitoringFailures:    "Security Logging and Monitoring Failures",
	WeaknessInjection:                               "Injection",
	WeaknessVulnerableAndOutdatedComponents:         "Vulnerable and Outdated Components",
	WeaknessInsecureDesign:                          "Insecure Design",
	WeaknessSecurityMisconfiguration:                "Security Misconfiguration",
	WeaknessOther:                                   "Other",
	WeaknessNoInfo:                                  "No Information Available",
}

func (w WeaknessType) String() string {
	if str, exists := weaknessStrings[w]; exists {
		return str
	}
	return "Unknown"
}

// Mapping for 2021 OWASP CWE Top 10 Groupings
var cweToWeaknessType = map[int]WeaknessType{
	918:  WeaknessSSRF,
	345:  WeaknessSoftwareAndDataIntegrityFailures,
	353:  WeaknessSoftwareAndDataIntegrityFailures,
	426:  WeaknessSoftwareAndDataIntegrityFailures,
	494:  WeaknessSoftwareAndDataIntegrityFailures,
	502:  WeaknessSoftwareAndDataIntegrityFailures,
	565:  WeaknessSoftwareAndDataIntegrityFailures,
	784:  WeaknessSoftwareAndDataIntegrityFailures,
	829:  WeaknessSoftwareAndDataIntegrityFailures,
	830:  WeaknessSoftwareAndDataIntegrityFailures,
	915:  WeaknessSoftwareAndDataIntegrityFailures,
	261:  WeaknessCryptographicFailures,
	296:  WeaknessCryptographicFailures,
	319:  WeaknessCryptographicFailures,
	321:  WeaknessCryptographicFailures,
	322:  WeaknessCryptographicFailures,
	323:  WeaknessCryptographicFailures,
	324:  WeaknessCryptographicFailures,
	325:  WeaknessCryptographicFailures,
	326:  WeaknessCryptographicFailures,
	327:  WeaknessCryptographicFailures,
	328:  WeaknessCryptographicFailures,
	329:  WeaknessCryptographicFailures,
	330:  WeaknessCryptographicFailures,
	331:  WeaknessCryptographicFailures,
	335:  WeaknessCryptographicFailures,
	336:  WeaknessCryptographicFailures,
	337:  WeaknessCryptographicFailures,
	338:  WeaknessCryptographicFailures,
	340:  WeaknessCryptographicFailures,
	347:  WeaknessCryptographicFailures,
	523:  WeaknessCryptographicFailures,
	757:  WeaknessCryptographicFailures,
	759:  WeaknessCryptographicFailures,
	760:  WeaknessCryptographicFailures,
	780:  WeaknessCryptographicFailures,
	916:  WeaknessCryptographicFailures,
	310:  WeaknessCryptographicFailures,
	720:  WeaknessCryptographicFailures,
	818:  WeaknessCryptographicFailures,
	259:  WeaknessIdentificationAndAuthenticationFailures,
	287:  WeaknessIdentificationAndAuthenticationFailures,
	288:  WeaknessIdentificationAndAuthenticationFailures,
	290:  WeaknessIdentificationAndAuthenticationFailures,
	294:  WeaknessIdentificationAndAuthenticationFailures,
	295:  WeaknessIdentificationAndAuthenticationFailures,
	297:  WeaknessIdentificationAndAuthenticationFailures,
	300:  WeaknessIdentificationAndAuthenticationFailures,
	302:  WeaknessIdentificationAndAuthenticationFailures,
	304:  WeaknessIdentificationAndAuthenticationFailures,
	306:  WeaknessIdentificationAndAuthenticationFailures,
	307:  WeaknessIdentificationAndAuthenticationFailures,
	346:  WeaknessIdentificationAndAuthenticationFailures,
	384:  WeaknessIdentificationAndAuthenticationFailures,
	521:  WeaknessIdentificationAndAuthenticationFailures,
	613:  WeaknessIdentificationAndAuthenticationFailures,
	620:  WeaknessIdentificationAndAuthenticationFailures,
	640:  WeaknessIdentificationAndAuthenticationFailures,
	798:  WeaknessIdentificationAndAuthenticationFailures,
	940:  WeaknessIdentificationAndAuthenticationFailures,
	1216: WeaknessIdentificationAndAuthenticationFailures,
	255:  WeaknessIdentificationAndAuthenticationFailures,
	1275: WeaknessBrokenAccessControl,
	200:  WeaknessBrokenAccessControl,
	201:  WeaknessBrokenAccessControl,
	219:  WeaknessBrokenAccessControl,
	22:   WeaknessBrokenAccessControl,
	23:   WeaknessBrokenAccessControl,
	276:  WeaknessBrokenAccessControl,
	284:  WeaknessBrokenAccessControl,
	285:  WeaknessBrokenAccessControl,
	35:   WeaknessBrokenAccessControl,
	352:  WeaknessBrokenAccessControl,
	359:  WeaknessBrokenAccessControl,
	377:  WeaknessBrokenAccessControl,
	402:  WeaknessBrokenAccessControl,
	425:  WeaknessBrokenAccessControl,
	441:  WeaknessBrokenAccessControl,
	497:  WeaknessBrokenAccessControl,
	538:  WeaknessBrokenAccessControl,
	540:  WeaknessBrokenAccessControl,
	548:  WeaknessBrokenAccessControl,
	552:  WeaknessBrokenAccessControl,
	566:  WeaknessBrokenAccessControl,
	59:   WeaknessBrokenAccessControl,
	601:  WeaknessBrokenAccessControl,
	639:  WeaknessBrokenAccessControl,
	651:  WeaknessBrokenAccessControl,
	668:  WeaknessBrokenAccessControl,
	706:  WeaknessBrokenAccessControl,
	862:  WeaknessBrokenAccessControl,
	863:  WeaknessBrokenAccessControl,
	913:  WeaknessBrokenAccessControl,
	922:  WeaknessBrokenAccessControl,
	264:  WeaknessBrokenAccessControl,
	275:  WeaknessBrokenAccessControl,
	117:  WeaknessSecurityLoggingAndMonitoringFailures,
	223:  WeaknessSecurityLoggingAndMonitoringFailures,
	532:  WeaknessSecurityLoggingAndMonitoringFailures,
	778:  WeaknessSecurityLoggingAndMonitoringFailures,
	113:  WeaknessInjection,
	116:  WeaknessInjection,
	138:  WeaknessInjection,
	184:  WeaknessInjection,
	20:   WeaknessInjection,
	470:  WeaknessInjection,
	471:  WeaknessInjection,
	564:  WeaknessInjection,
	610:  WeaknessInjection,
	643:  WeaknessInjection,
	644:  WeaknessInjection,
	652:  WeaknessInjection,
	74:   WeaknessInjection,
	75:   WeaknessInjection,
	77:   WeaknessInjection,
	78:   WeaknessInjection,
	79:   WeaknessInjection,
	80:   WeaknessInjection,
	83:   WeaknessInjection,
	87:   WeaknessInjection,
	88:   WeaknessInjection,
	89:   WeaknessInjection,
	90:   WeaknessInjection,
	91:   WeaknessInjection,
	917:  WeaknessInjection,
	93:   WeaknessInjection,
	94:   WeaknessInjection,
	95:   WeaknessInjection,
	96:   WeaknessInjection,
	97:   WeaknessInjection,
	98:   WeaknessInjection,
	99:   WeaknessInjection,
	1104: WeaknessVulnerableAndOutdatedComponents,
	1035: WeaknessVulnerableAndOutdatedComponents,
	937:  WeaknessVulnerableAndOutdatedComponents,
	1021: WeaknessInsecureDesign,
	1173: WeaknessInsecureDesign,
	183:  WeaknessInsecureDesign,
	209:  WeaknessInsecureDesign,
	213:  WeaknessInsecureDesign,
	235:  WeaknessInsecureDesign,
	256:  WeaknessInsecureDesign,
	257:  WeaknessInsecureDesign,
	266:  WeaknessInsecureDesign,
	269:  WeaknessInsecureDesign,
	280:  WeaknessInsecureDesign,
	311:  WeaknessInsecureDesign,
	312:  WeaknessInsecureDesign,
	313:  WeaknessInsecureDesign,
	316:  WeaknessInsecureDesign,
	419:  WeaknessInsecureDesign,
	430:  WeaknessInsecureDesign,
	434:  WeaknessInsecureDesign,
	444:  WeaknessInsecureDesign,
	451:  WeaknessInsecureDesign,
	472:  WeaknessInsecureDesign,
	501:  WeaknessInsecureDesign,
	522:  WeaknessInsecureDesign,
	525:  WeaknessInsecureDesign,
	539:  WeaknessInsecureDesign,
	579:  WeaknessInsecureDesign,
	598:  WeaknessInsecureDesign,
	602:  WeaknessInsecureDesign,
	642:  WeaknessInsecureDesign,
	646:  WeaknessInsecureDesign,
	650:  WeaknessInsecureDesign,
	653:  WeaknessInsecureDesign,
	656:  WeaknessInsecureDesign,
	657:  WeaknessInsecureDesign,
	73:   WeaknessInsecureDesign,
	799:  WeaknessInsecureDesign,
	807:  WeaknessInsecureDesign,
	841:  WeaknessInsecureDesign,
	927:  WeaknessInsecureDesign,
	840:  WeaknessInsecureDesign,
	1004: WeaknessSecurityMisconfiguration,
	11:   WeaknessSecurityMisconfiguration,
	1174: WeaknessSecurityMisconfiguration,
	13:   WeaknessSecurityMisconfiguration,
	15:   WeaknessSecurityMisconfiguration,
	260:  WeaknessSecurityMisconfiguration,
	315:  WeaknessSecurityMisconfiguration,
	520:  WeaknessSecurityMisconfiguration,
	526:  WeaknessSecurityMisconfiguration,
	537:  WeaknessSecurityMisconfiguration,
	541:  WeaknessSecurityMisconfiguration,
	547:  WeaknessSecurityMisconfiguration,
	611:  WeaknessSecurityMisconfiguration,
	614:  WeaknessSecurityMisconfiguration,
	756:  WeaknessSecurityMisconfiguration,
	776:  WeaknessSecurityMisconfiguration,
	942:  WeaknessSecurityMisconfiguration,
	1032: WeaknessSecurityMisconfiguration,
	16:   WeaknessSecurityMisconfiguration,
	2:    WeaknessSecurityMisconfiguration,
}

func GetWeaknessType(cweID int) WeaknessType {
	if weakness, exists := cweToWeaknessType[cweID]; exists {
		return weakness
	}
	return WeaknessOther
}

// ParseWeaknessFromString takes a weakness string and returns the corresponding WeaknessType.
// It performs a case-insensitive search.
func ParseWeaknessFromString(weaknessStr string) (WeaknessType, bool) {
	lowerStr := strings.ToLower(weaknessStr)
	for wt, str := range weaknessStrings {
		if strings.ToLower(str) == lowerStr {
			return wt, true
		}
	}
	return WeaknessNoInfo, false
}
