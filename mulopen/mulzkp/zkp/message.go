package zkp

import "github.com/renproject/secp256k1"

// The Message that is initially sent in the ZKP.
type Message struct {
	m, m1, m2 secp256k1.Point
}

// SizeHint implements the surge.SizeHinter interface.
func (msg Message) SizeHint() int {
	return msg.m.SizeHint() + msg.m1.SizeHint() + msg.m2.SizeHint()
}

// Marshal implements the surge.Marshaler interface.
func (msg Message) Marshal(buf []byte, rem int) ([]byte, int, error) {
	buf, rem, err := msg.m.Marshal(buf, rem)
	if err != nil {
		return buf, rem, err
	}

	buf, rem, err = msg.m1.Marshal(buf, rem)
	if err != nil {
		return buf, rem, err
	}

	return msg.m2.Marshal(buf, rem)
}

// Unmarshal implements the surge.UnUnmarshaler interface.
func (msg *Message) Unmarshal(buf []byte, rem int) ([]byte, int, error) {
	buf, rem, err := msg.m.Unmarshal(buf, rem)
	if err != nil {
		return buf, rem, err
	}

	buf, rem, err = msg.m1.Unmarshal(buf, rem)
	if err != nil {
		return buf, rem, err
	}

	return msg.m2.Unmarshal(buf, rem)
}
