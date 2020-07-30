package openutil

import (
	"github.com/renproject/mpc/mpcutil"
	"github.com/renproject/mpc/open"
	"github.com/renproject/secp256k1"
	"github.com/renproject/shamir"
	"github.com/renproject/surge"
)

// The Machine type used for the opener network test.
type Machine struct {
	id                     mpcutil.ID
	n                      uint32
	shares                 shamir.VerifiableShares
	commitments            []shamir.Commitment
	opener                 open.Opener
	Secrets, Decommitments []secp256k1.Fn
}

// NewMachine constructs a new Machine.
func NewMachine(
	id mpcutil.ID,
	n uint32,
	shares shamir.VerifiableShares,
	commitments []shamir.Commitment,
	opener open.Opener,
) Machine {
	secrets, decommitments, _ := opener.HandleShareBatch(shares)
	return Machine{id, n, shares, commitments, opener, secrets, decommitments}
}

// ID implements the mpcutil.Machine interface.
func (m Machine) ID() mpcutil.ID {
	return m.id
}

// InitialMessages implements the mpcutil.Machine interface.
func (m Machine) InitialMessages() []mpcutil.Message {
	messages := make([]mpcutil.Message, m.n-1)[:0]
	for i := uint32(0); i < m.n; i++ {
		if mpcutil.ID(i) == m.id {
			continue
		}
		messages = append(messages, &Message{
			shares: m.shares,
			from:   m.id,
			to:     mpcutil.ID(i),
		})
	}
	return messages
}

// Handle implements the mpcutil.Machine interface.
func (m *Machine) Handle(msg mpcutil.Message) []mpcutil.Message {
	message := msg.(*Message)
	secrets, decommitments, _ := m.opener.HandleShareBatch(message.shares)
	if secrets != nil && decommitments != nil {
		m.Secrets, m.Decommitments = secrets, decommitments
	}
	return nil
}

// SizeHint implements the surge.SizeHinter interface.
func (m Machine) SizeHint() int {
	return m.id.SizeHint() +
		4 +
		m.shares.SizeHint() +
		surge.SizeHint(m.commitments) +
		m.opener.SizeHint()
}

// Marshal implements the surge.Marshaler interface.
func (m Machine) Marshal(buf []byte, rem int) ([]byte, int, error) {
	buf, rem, err := m.id.Marshal(buf, rem)
	if err != nil {
		return buf, rem, err
	}
	buf, rem, err = surge.MarshalU32(m.n, buf, rem)
	if err != nil {
		return buf, rem, err
	}
	buf, rem, err = m.shares.Marshal(buf, rem)
	if err != nil {
		return buf, rem, err
	}
	buf, rem, err = surge.Marshal(m.commitments, buf, rem)
	if err != nil {
		return buf, rem, err
	}
	return m.opener.Marshal(buf, rem)
}

// Unmarshal implements the surge.Unmarshaler interface.
func (m *Machine) Unmarshal(buf []byte, rem int) ([]byte, int, error) {
	buf, rem, err := m.id.Unmarshal(buf, rem)
	if err != nil {
		return buf, rem, err
	}
	buf, rem, err = surge.UnmarshalU32(&m.n, buf, rem)
	if err != nil {
		return buf, rem, err
	}
	buf, rem, err = m.shares.Unmarshal(buf, rem)
	if err != nil {
		return buf, rem, err
	}
	buf, rem, err = surge.Unmarshal(&m.commitments, buf, rem)
	if err != nil {
		return buf, rem, err
	}
	return m.opener.Unmarshal(buf, rem)
}
