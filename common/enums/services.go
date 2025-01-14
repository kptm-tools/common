package enums

type ServiceName string

const (
	ServiceWhoIs     ServiceName = "WhoIs"
	ServiceHarvester ServiceName = "Harvester"
	ServiceDNSLookup ServiceName = "DNSLookup"
	ServiceNmap      ServiceName = "Nmap"
)
