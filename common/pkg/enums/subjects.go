package enums

type EventSubjectName string

const (
	ScanStartedEventSubject   EventSubjectName = "event.scanstarted"
	ScanCancelledEventSubject EventSubjectName = "event.scancancelled"
	ScanFailedEventSubject    EventSubjectName = "event.scanfailed"
	WhoIsEventSubject         EventSubjectName = "event.whois"
	DNSLookupEventSubject     EventSubjectName = "event.dnslookup"
	HarvesterEventSubject     EventSubjectName = "event.harvester"
	NmapEventSubject          EventSubjectName = "event.nmap"
	WebScanEventSubject       EventSubjectName = "event.webscan"
)
