package mulopenutil

import (
	"github.com/renproject/mpc/mpcutil"
	"github.com/renproject/mpc/mulopen"
	"github.com/renproject/secp256k1"
	"github.com/renproject/shamir"
	"github.com/renproject/surge"
)

// Machine represents a player that honestly carries out the multiply and open
// protocol.
type Machine struct {
	OwnID mpcutil.ID
	mulopen.MulOpener
	InitMsgs []Message
	Output   []secp256k1.Fn
}

// NewMachine constructs a new honest machine for a multiply and open network
// test. It will have the given inputs and ID.
func NewMachine(
	aShareBatch, bShareBatch, rzgShareBatch shamir.VerifiableShares,
	aCommitmentBatch, bCommitmentBatch, rzgCommitmentBatch []shamir.Commitment,
	ids []mpcutil.ID, ownID mpcutil.ID, indices []secp256k1.Fn, h secp256k1.Point,
) Machine {
	mulopener, msgs := mulopen.New(
		aShareBatch, bShareBatch, rzgShareBatch,
		aCommitmentBatch, bCommitmentBatch, rzgCommitmentBatch,
		indices, h,
	)
	initialMessages := make([]Message, 0, len(ids)-1)
	for _, id := range ids {
		if id == ownID {
			continue
		}
		initialMessages = append(initialMessages, Message{
			FromID:   ownID,
			ToID:     id,
			Messages: msgs,
		})
	}
	return Machine{
		OwnID:     ownID,
		MulOpener: mulopener,
		InitMsgs:  initialMessages,
	}
}

// SizeHint implements the surge.SizeHinter interface.
func (m Machine) SizeHint() int {
	return m.OwnID.SizeHint() +
		m.MulOpener.SizeHint() +
		surge.SizeHint(m.InitMsgs) +
		surge.SizeHint(m.Output)
}

// Marshal implements the surge.Marshaler interface.
func (m Machine) Marshal(buf []byte, rem int) ([]byte, int, error) {
	buf, rem, err := m.OwnID.Marshal(buf, rem)
	if err != nil {
		return buf, rem, err
	}
	buf, rem, err = m.MulOpener.Marshal(buf, rem)
	if err != nil {
		return buf, rem, err
	}
	buf, rem, err = surge.Marshal(m.InitMsgs, buf, rem)
	if err != nil {
		return buf, rem, err
	}
	return surge.Marshal(m.Output, buf, rem)
}

// Unmarshal implements the surge.Unmarshaler interface.
func (m *Machine) Unmarshal(buf []byte, rem int) ([]byte, int, error) {
	buf, rem, err := m.OwnID.Unmarshal(buf, rem)
	if err != nil {
		return buf, rem, err
	}
	buf, rem, err = m.MulOpener.Unmarshal(buf, rem)
	if err != nil {
		return buf, rem, err
	}
	buf, rem, err = surge.Unmarshal(&m.InitMsgs, buf, rem)
	if err != nil {
		return buf, rem, err
	}
	return surge.Unmarshal(&m.Output, buf, rem)
}

// ID implements the Machine interface.
func (m Machine) ID() mpcutil.ID { return m.OwnID }

// InitialMessages implements the Machine interface.
func (m Machine) InitialMessages() []mpcutil.Message {
	msgs := make([]mpcutil.Message, len(m.InitMsgs))
	for i := range m.InitMsgs {
		msgs[i] = &m.InitMsgs[i]
	}
	return msgs
}

// Handle implements the Machine interface.
func (m *Machine) Handle(msg mpcutil.Message) []mpcutil.Message {
	output, _ := m.MulOpener.HandleShareBatch(msg.(*Message).Messages)
	if output != nil {
		m.Output = output
	}
	return nil
}
