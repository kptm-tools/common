package enums

type EventSubjectName string

const (
	ScanStartedEventSubject   EventSubjectName = "event.scanstarted"
	ScanCancelledEventSubject EventSubjectName = "event.scancancelled"
	WhoIsEventSubject         EventSubjectName = "event.whois"
	DNSLookupEventSubject     EventSubjectName = "event.dnslookup"
	HarvesterEventSubject     EventSubjectName = "event.harvester"
	NmapEventSubject          EventSubjectName = "event.nmap"
)
