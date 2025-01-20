package events

import (
	"encoding/json"
	"time"

	"github.com/kptm-tools/common/common/enums"
	"github.com/kptm-tools/common/common/results"
)

// EventFactoryRegistry holds the mapping between services and their respective factories.
var EventFactoryRegistry = map[enums.ServiceName]EventFactory{
	enums.ServiceWhoIs:     &WhoIsEventFactory{},
	enums.ServiceDNSLookup: &DNSLookupEventFactory{},
	enums.ServiceHarvester: &HarvesterEventFactory{},
	enums.ServiceNmap:      &NmapEventFactory{},
}

type EventFactory interface {
	BuildEvent(result results.ServiceResult) ([]byte, error)
}

// WhoIsEventFactory builds payloads for WhoIs Events
type WhoIsEventFactory struct{}

func (f *WhoIsEventFactory) BuildEvent(result results.ServiceResult) ([]byte, error) {
	evt := WhoIsEvent{
		BaseEvent: BaseEvent{
			ScanID:    result.ScanID,
			Timestamp: time.Now().Unix(),
			Error:     getEventError(result.Err),
		},
		Results: result.Result,
	}
	return json.Marshal(evt)
}

// DNSLookupEventFactory builds payloads for DNSLookup Events
type DNSLookupEventFactory struct{}

func (f *DNSLookupEventFactory) BuildEvent(result results.ServiceResult) ([]byte, error) {
	evt := DNSLookupEvent{
		BaseEvent: BaseEvent{
			ScanID:    result.ScanID,
			Timestamp: time.Now().Unix(),
			Error:     getEventError(result.Err),
		},
		Results: result.Result,
	}
	return json.Marshal(evt)
}

// HarvesterEventFactory builds payloads for Harvester Events
type HarvesterEventFactory struct{}

func (f *HarvesterEventFactory) BuildEvent(result results.ServiceResult) ([]byte, error) {
	evt := HarvesterEvent{
		BaseEvent: BaseEvent{
			ScanID:    result.ScanID,
			Timestamp: time.Now().Unix(),
			Error:     getEventError(result.Err),
		},
		Results: result.Result,
	}
	return json.Marshal(evt)
}

// NmapEventFactory builds payloads for Nmap Events
type NmapEventFactory struct{}

func (f *NmapEventFactory) BuildEvent(result results.ServiceResult) ([]byte, error) {
	evt := NmapEvent{
		BaseEvent: BaseEvent{
			ScanID:    result.ScanID,
			Timestamp: time.Now().Unix(),
			Error:     getEventError(result.Err),
		},
		Results: result.Result,
	}
	return json.Marshal(evt)
}

// getEventError is a helper function to map the error result to a Service EventError
func getEventError(err error) *EventError {
	if err != nil {
		return &EventError{
			Code:    enums.ServiceError,
			Message: err.Error(),
		}
	}
	return nil
}
