package enums

import (
	"log/slog"
	"strconv"
	"strings"
)

type OwaspCategory string

const (
	OwaspCategoryBrokenAccessControl                     OwaspCategory = "Broken Access Control"
	OwaspCategoryCryptographicFailures                   OwaspCategory = "Cryptographic Failures"
	OwaspCategoryInjection                               OwaspCategory = "Injection"
	OwaspCategoryInsecureDesign                          OwaspCategory = "Insecure Design"
	OwaspCategorySecurityMisconfiguration                OwaspCategory = "Security Misconfiguration"
	OwaspCategoryVulnerableAndOutdatedComponents         OwaspCategory = "Vulnerable and Outdated Components"
	OwaspCategoryIdentificationAndAuthenticationFailures OwaspCategory = "Identification and Authentication Failures"
	OwaspCategorySoftwareAndDataIntegrityFailures        OwaspCategory = "Software and Data Integrity Failures"
	OwaspCategorySecurityLoggingAndMonitoringFailures    OwaspCategory = "Security Logging and Monitoring Failures"
	OwaspCategorySSRF                                    OwaspCategory = "Server-Side Request Forgery (SSRF)"
	OwaspCategoryOther                                   OwaspCategory = "Other"   // For CWEs not in the Top 10
	OwaspCategoryNoInfo                                  OwaspCategory = "No Info" // For when no mapping is found
)

// owaspCategoryCWEs defines the relationship from the category to its list of associated CWE IDs.
// It is a bit more maintainable (and easier to read) than the old map we had.
// Mapping for 2021 OWASP CWE Top 10 Groupings
var owaspCategoryCWEs = map[OwaspCategory][]int{
	OwaspCategoryBrokenAccessControl:                     {22, 23, 35, 59, 200, 201, 219, 264, 275, 276, 284, 285, 352, 359, 377, 402, 425, 441, 497, 538, 540, 548, 552, 566, 601, 639, 651, 668, 706, 862, 863, 913, 922, 1275},
	OwaspCategoryCryptographicFailures:                   {261, 296, 310, 319, 321, 322, 323, 324, 325, 326, 327, 328, 329, 330, 331, 335, 336, 337, 338, 340, 347, 523, 720, 757, 759, 760, 780, 818, 916},
	OwaspCategoryInjection:                               {20, 74, 75, 77, 78, 79, 80, 83, 87, 88, 89, 90, 91, 93, 94, 95, 96, 97, 98, 99, 113, 116, 138, 184, 470, 471, 564, 610, 643, 644, 652, 917},
	OwaspCategoryInsecureDesign:                          {73, 183, 209, 213, 235, 256, 257, 266, 269, 280, 311, 312, 313, 316, 419, 430, 434, 444, 451, 472, 501, 522, 525, 539, 579, 598, 602, 642, 646, 650, 653, 656, 657, 799, 807, 840, 841, 927, 1021, 1173},
	OwaspCategorySecurityMisconfiguration:                {2, 11, 13, 15, 16, 260, 315, 520, 526, 537, 541, 547, 611, 614, 756, 776, 942, 1004, 1032, 1174},
	OwaspCategoryVulnerableAndOutdatedComponents:         {937, 1035, 1104},
	OwaspCategoryIdentificationAndAuthenticationFailures: {255, 259, 287, 288, 290, 294, 295, 297, 300, 302, 304, 306, 307, 346, 384, 521, 613, 620, 640, 798, 940, 1216},
	OwaspCategorySoftwareAndDataIntegrityFailures:        {345, 353, 426, 494, 502, 565, 784, 829, 830, 915},
	OwaspCategorySecurityLoggingAndMonitoringFailures:    {117, 223, 532, 778},
	OwaspCategorySSRF:                                    {918},
}

// cweIDToOwaspCategoryMap is a reverse map for efficient O(1) lookups.
// It is generated once at package startup with the init() function.
var cweIDToOwaspCategoryMap = map[int]OwaspCategory{}

func init() {
	cweIDToOwaspCategoryMap = make(map[int]OwaspCategory)
	for category, cweIDs := range owaspCategoryCWEs {
		for _, id := range cweIDs {
			if existingCat, exists := cweIDToOwaspCategoryMap[id]; exists {
				slog.Warn("Duplicate CWE ID found in OWASP mapping, did you make an accident copying and pasting?", "cwe_id", id, "existing_category", existingCat, "new_category", category)
			}
			cweIDToOwaspCategoryMap[id] = category
		}
	}
}

func (w OwaspCategory) String() string {
	return string(w)
}

// GetOwaspCategoryForCWE finds the OWASP Top 10 category for a given CWE ID string (e.g., "CWE-719").
// It returns the specific category or GetOwaspCategoryOther if it's not part of the Top 10 list.
func GetOwaspCategoryForCWE(cweID string) OwaspCategory {
	cweSuffix := strings.TrimPrefix(strings.ToUpper(cweID), "CWE-")
	// First check if it's a 'Other' Weakness
	if cweSuffix == "Other" {
		return OwaspCategoryOther
	}

	id, err := strconv.Atoi(cweSuffix)
	if err != nil {
		// Invalid
		return OwaspCategoryNoInfo
	}
	if category, ok := cweIDToOwaspCategoryMap[id]; ok {
		return category
	}

	return OwaspCategoryOther
}

func ParseOwaspCategory(s string) (OwaspCategory, bool) {
	val := OwaspCategory(s)
	switch val {
	case OwaspCategoryBrokenAccessControl,
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
		OwaspCategoryNoInfo:
		return val, true
	default:
		return OwaspCategoryNoInfo, false
	}
}
