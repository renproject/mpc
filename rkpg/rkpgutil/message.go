package rkpgutil

import (
	"github.com/renproject/mpc/mpcutil"
	"github.com/renproject/shamir"
)

// A Message is sent between machines during a RKPG simulation.
type Message struct {
	ToID, FromID mpcutil.ID
	ShareBatch   shamir.Shares
}

// To implements the mpcutil.Message interface.
func (msg Message) To() mpcutil.ID { return msg.ToID }

// From implements the mpcutil.Message interface.
func (msg Message) From() mpcutil.ID { return msg.FromID }

// SizeHint implements the surge.SizeHinter interface.
func (msg Message) SizeHint() int {
	return msg.ToID.SizeHint() +
		msg.FromID.SizeHint() +
		msg.ShareBatch.SizeHint()
}

// Marshal implements the surge.Marshaler interface.
func (msg Message) Marshal(buf []byte, rem int) ([]byte, int, error) {
	buf, rem, err := msg.ToID.Marshal(buf, rem)
	if err != nil {
		return buf, rem, err
	}
	buf, rem, err = msg.FromID.Marshal(buf, rem)
	if err != nil {
		return buf, rem, err
	}
	return msg.ShareBatch.Marshal(buf, rem)
}

// Unmarshal implements the surge.Unmarshaler interface.
func (msg *Message) Unmarshal(buf []byte, rem int) ([]byte, int, error) {
	buf, rem, err := msg.ToID.Unmarshal(buf, rem)
	if err != nil {
		return buf, rem, err
	}
	buf, rem, err = msg.FromID.Unmarshal(buf, rem)
	if err != nil {
		return buf, rem, err
	}
	return msg.ShareBatch.Unmarshal(buf, rem)
}
