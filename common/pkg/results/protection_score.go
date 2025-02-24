package results

import (
	"log/slog"
	"math"

	"github.com/kptm-tools/common/common/pkg/results/tools"
)

func CalculateProtectionScore(
	whoisResult tools.WhoIsResult,
	dnsLookupResult tools.DNSLookupResult,
	harvesterResult tools.HarvesterResult,
	nmapResult tools.NmapResult,
) (float64, error) {
	const (
		maxEmails      = 50
		maxSubdomains  = 100
		openPortsLimit = 50
		vulnLimit      = 50
	)

	var emailCount, subdomainCount, dnsRecordCount int
	var whoisSuccessful bool
	var vulnResults []tools.Vulnerability
	var osDetectionPenalty float64

	// Extract relevant data
	emailCount = len(harvesterResult.Emails)
	subdomainCount = len(harvesterResult.Subdomains)
	dnsRecordCount = len(dnsLookupResult.DNSRecords)
	whoisSuccessful = whoisResult.Error == ""
	openPorts := len(nmapResult.GetOpenPorts())

	// Extract vulnerability data
	vulners := nmapResult.GetAllVulnerabilites()
	vulnResults = append(vulnResults, vulners...)
	vulnCounts := tools.GetSeverityCounts(vulnResults)

	// Calculate penalties
	if nmapResult.MostLikelyOS.Accuracy > 1 {
		osDetectionPenalty = 10.0
	}

	// Calculate protection sub-scores
	emailScore := normalizeScore(float64(emailCount), maxEmails)
	subdomainScore := normalizeScore(float64(subdomainCount), maxSubdomains)
	whoisScore := 20 * boolToFloat(whoisSuccessful)
	dnsScore := normalizeScore(float64(dnsRecordCount)*10, 1)
	openPortsScore := normalizeScore(float64(openPorts), openPortsLimit)

	// Vulnerability score (severity-weighted)
	vulnScore := normalizeScore(float64(vulnCounts.Low*1+vulnCounts.Medium*3+vulnCounts.High*7+vulnCounts.Critical*15), vulnLimit)

	slog.Debug("Protection Score Calculation Data",
		slog.Int("email_count", emailCount),
		slog.Int("subdomain_count", subdomainCount),
		slog.Int("dns_record_count", dnsRecordCount),
		slog.Bool("whois_successful", whoisSuccessful),
		slog.Int("open_ports", openPorts),
		slog.Int("vuln_low", vulnCounts.Low),
		slog.Int("vuln_medium", vulnCounts.Medium),
		slog.Int("vuln_high", vulnCounts.High),
		slog.Int("vuln_critical", vulnCounts.Critical),
	)

	slog.Debug("Individual Component Scores",
		slog.Float64("email_score", emailScore),
		slog.Float64("subdomain_score", subdomainScore),
		slog.Float64("whois_score", whoisScore),
		slog.Float64("dns_score", dnsScore),
		slog.Float64("vuln_score", vulnScore),
		slog.Float64("open_ports_score", openPortsScore),
		slog.Float64("os_detection_penalty", osDetectionPenalty),
	)

	// Calculate final protection score (higher sub-scores decrease protection)
	finalScore := 100 - (0.2*emailScore +
		0.2*subdomainScore +
		0.1*whoisScore +
		0.1*dnsScore +
		0.4*vulnScore +
		0.2*openPortsScore +
		osDetectionPenalty)

	// Normalize between [0,1]
	finalScore = math.Max(0, math.Min(finalScore/100, 1))

	return finalScore, nil
}

// normalizeScore is a utility function to normalize a score
// (higher values indicate higher risk)
func normalizeScore(value, max float64) float64 {
	return 100 * (math.Min(value/max, 1))
}

func boolToFloat(value bool) float64 {
	if value {
		return 1.0
	}
	return 0.0
}
