package mulopenutil

import (
	"github.com/renproject/mpc/mpcutil"
	"github.com/renproject/mpc/mulopen"
)

// Message is the message type that players send to eachother during an
// instance of multiply and open.
type Message struct {
	FromID, ToID mpcutil.ID
	Messages     []mulopen.Message
}

// From implements the mpcutil.Message interface.
func (msg Message) From() mpcutil.ID { return msg.FromID }

// To implements the mpcutil.Message interface.
func (msg Message) To() mpcutil.ID { return msg.ToID }

func (msg Message) SizeHint() int                                       { return 0 }
func (msg Message) Marshal(buf []byte, rem int) ([]byte, int, error)    { return buf, rem, nil }
func (msg *Message) Unmarshal(buf []byte, rem int) ([]byte, int, error) { return buf, rem, nil }
