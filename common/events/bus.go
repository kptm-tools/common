package events

import (
	"fmt"
	"log/slog"

	"github.com/nats-io/nats.go"
)

// EventBus defines the interface for event buses in the system.
// It includes methods for initializing subscriptions, subscribing to events,
// and publishing events.
type EventBus interface {
	// Init initializes the event bus with any necessary subscription setup logic.
	Init(setupSubscriptions func() error) error

	// Subscribe subscribes to an event subject with a provided handler function.
	// The handler is invoked when a message is received.
	Subscribe(subject string, handler func(msg *nats.Msg)) error

	// Publish publishes a message to the specified subject.
	// It sends the payload to the NATS server.
	Publish(subject string, payload []byte) error
}

// NatsEventBus implements the EventBus interface using NATS as the message broker.
// It provides functionality for subscribing to events, publishing messages,
// and managing connections to NATS servers.
type NatsEventBus struct {
	nc     *nats.Conn   // NATS connection object.
	Logger *slog.Logger // Logger used for logging event-related information
}

// NewNatsEventBus creates a new nats event bus with the specified connStr
// e.g., NewNatsEventBus("http://nats:4222")
func NewNatsEventBus(connStr string) (*NatsEventBus, error) {
	nc, err := nats.Connect(connStr)
	if err != nil {
		return nil, err
	}

	return &NatsEventBus{
		nc:     nc,
		Logger: slog.New(slog.Default().Handler()),
	}, nil
}

// Init sets up the event bus by subscribing to necessary events
// using the provided setupSubscriptions function.
// The setupSubscriptions function allows customization of event subscriptions
// based on the specific service's requirements.
func (n *NatsEventBus) Init(setupSubscriptions func() error) error {
	// Subscribing to events the system listens for
	return setupSubscriptions()
}

// Subscribe subscribes to the given event subject and specifies a handler function
// to process the incoming messages for that event. The handler is invoked whenever
// a message is received on the specified subject.
//
// subject: The subject/topic to subscribe to.
// handler: The callback function to handle incoming messages for the subject.
//
// Returns an error if the subscription fails.
func (n *NatsEventBus) Subscribe(subject string, handler func(msg *nats.Msg)) error {
	_, err := n.nc.Subscribe(subject, handler)
	if err != nil {
		return fmt.Errorf("Failed to subscribe to `%s`: %s", subject, err.Error())
	}

	n.Logger.Info("Subscribed to subject successfully.", slog.String("subject", subject))
	return nil
}

// Publish sends a message to the specified subject with the given payload.
//
// subject: The subject/topic to publish the message to.
// payload: The message payload to be sent with the event.
//
// Returns an error if the publishing process fails.
func (n *NatsEventBus) Publish(subject string, payload []byte) error {

	err := n.nc.Publish(subject, payload)
	if err != nil {
		return err
	}

	n.Logger.Debug("Published message", slog.String("subject", subject), slog.String("payload", string(payload)))
	return nil
}
