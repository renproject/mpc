package invutil

import (
	"github.com/renproject/mpc/mpcutil"
	"github.com/renproject/mpc/mulopen"
	"github.com/renproject/surge"
)

// Message is the message type that players send to eachother during an
// instance of inversion.
type Message struct {
	FromID, ToID mpcutil.ID
	Messages     []mulopen.Message
}

// From implements the mpcutil.Message interface.
func (msg Message) From() mpcutil.ID { return msg.FromID }

// To implements the mpcutil.Message interface.
func (msg Message) To() mpcutil.ID { return msg.ToID }

// SizeHint implements the surge.SizeHinter interface.
func (msg Message) SizeHint() int {
	return msg.FromID.SizeHint() +
		msg.ToID.SizeHint() +
		surge.SizeHint(msg.Messages)
}

// Marshal implements the surge.Marshaler interface.
func (msg Message) Marshal(buf []byte, rem int) ([]byte, int, error) {
	buf, rem, err := msg.FromID.Marshal(buf, rem)
	if err != nil {
		return buf, rem, err
	}
	buf, rem, err = msg.ToID.Marshal(buf, rem)
	if err != nil {
		return buf, rem, err
	}
	return surge.Marshal(msg.Messages, buf, rem)
}

// Unmarshal implements the surge.Unmarshaler interface.
func (msg *Message) Unmarshal(buf []byte, rem int) ([]byte, int, error) {
	buf, rem, err := msg.FromID.Unmarshal(buf, rem)
	if err != nil {
		return buf, rem, err
	}
	buf, rem, err = msg.ToID.Unmarshal(buf, rem)
	if err != nil {
		return buf, rem, err
	}
	return surge.Unmarshal(&msg.Messages, buf, rem)
}
