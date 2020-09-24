package openutil

import (
	"github.com/renproject/mpc/mpcutil"
	"github.com/renproject/shamir"
)

// The Message type used for network testing the opener.
type Message struct {
	shares   shamir.VerifiableShares
	from, to mpcutil.ID
}

// From implements the mpcutil.Message interface.
func (msg Message) From() mpcutil.ID { return msg.from }

// To implements the mpcutil.Message interface.
func (msg Message) To() mpcutil.ID { return msg.to }

// SizeHint implements the surge.SizeHinter interface.
func (msg Message) SizeHint() int {
	return msg.shares.SizeHint() + msg.from.SizeHint() + msg.to.SizeHint()
}

// Marshal implements the surge.Marshaler interface.
func (msg Message) Marshal(buf []byte, rem int) ([]byte, int, error) {
	buf, rem, err := msg.shares.Marshal(buf, rem)
	if err != nil {
		return buf, rem, err
	}
	buf, rem, err = msg.from.Marshal(buf, rem)
	if err != nil {
		return buf, rem, err
	}
	buf, rem, err = msg.to.Marshal(buf, rem)
	return buf, rem, err
}

// Unmarshal implements the surge.Unmarshaler interface.
func (msg *Message) Unmarshal(buf []byte, rem int) ([]byte, int, error) {
	buf, rem, err := msg.shares.Unmarshal(buf, rem)
	if err != nil {
		return buf, rem, err
	}
	buf, rem, err = msg.from.Unmarshal(buf, rem)
	if err != nil {
		return buf, rem, err
	}
	buf, rem, err = msg.to.Unmarshal(buf, rem)
	return buf, rem, err
}
