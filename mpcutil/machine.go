package mpcutil

import "github.com/renproject/surge"

// The Machine interface represents one of the players in a distributed
// network. Every machine must have a unique ID, and be able to handle incoming
// messages.
type Machine interface {
	surge.MarshalUnmarshaler

	ID() ID

	// InitialMessages should return the messages that a Machine sends at the
	// start of a network run, i.e. those messages that it would send before
	// having received any, if there are such messages.
	InitialMessages() []Message

	// Handle processes an incoming message and returns response messages, if
	// any.
	Handle(Message) []Message
}

// An OfflineMachine represents a player that is offline. It does not send any
// messages.
type OfflineMachine ID

// ID implements the Machine interface.
func (m OfflineMachine) ID() ID { return ID(m) }

// InitialMessages implements the Machine interface.
func (m OfflineMachine) InitialMessages() []Message { return nil }

// Handle implements the Machine interface.
func (m OfflineMachine) Handle(_ Message) []Message { return nil }

// SizeHint implements the surge.SizeHinter interface.
func (m OfflineMachine) SizeHint() int {
	return ID(m).SizeHint()
}

// Marshal implements the surge.Marshaler interface.
func (m OfflineMachine) Marshal(buf []byte, rem int) ([]byte, int, error) {
	return ID(m).Marshal(buf, rem)
}

// Unmarshal implements the surge.Unmarshaler interface.
func (m *OfflineMachine) Unmarshal(buf []byte, rem int) ([]byte, int, error) {
	return (*ID)(m).Unmarshal(buf, rem)
}
