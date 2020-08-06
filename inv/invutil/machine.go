package invutil

import (
	"github.com/renproject/mpc/inv"
	"github.com/renproject/mpc/mpcutil"
	"github.com/renproject/secp256k1"
	"github.com/renproject/shamir"
	"github.com/renproject/surge"
)

// Machine represents a player that honestly carries out the inversion
// protocol.
type Machine struct {
	OwnID mpcutil.ID
	inv.Inverter
	InitMsgs          []Message
	OutputShares      shamir.VerifiableShares
	OutputCommitments []shamir.Commitment
}

// NewMachine constructs a new honest machine for an inversion network test. It
// will have the given inputs and ID.
func NewMachine(
	aShareBatch, bShareBatch, rzgShareBatch shamir.VerifiableShares,
	aCommitmentBatch, bCommitmentBatch, rzgCommitmentBatch []shamir.Commitment,
	ids []mpcutil.ID, ownID mpcutil.ID, indices []secp256k1.Fn, h secp256k1.Point,
) Machine {
	inverter, msgs := inv.New(
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
		OwnID:    ownID,
		Inverter: inverter,
		InitMsgs: initialMessages,
	}
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
	outputShares, outputCommitments, _ := m.Inverter.HandleMulOpenMessageBatch(msg.(*Message).Messages)
	if outputShares != nil && outputCommitments != nil {
		m.OutputShares = outputShares
		m.OutputCommitments = outputCommitments
	}
	return nil
}

// SizeHint implements the surge.SizeHinter interface.
func (m Machine) SizeHint() int {
	return m.OwnID.SizeHint() +
		m.Inverter.SizeHint() +
		surge.SizeHint(m.InitMsgs) +
		surge.SizeHint(m.OutputShares) +
		surge.SizeHint(m.OutputCommitments)
}

// Marshal implements the surge.Marshaler interface.
func (m Machine) Marshal(buf []byte, rem int) ([]byte, int, error) {
	buf, rem, err := m.OwnID.Marshal(buf, rem)
	if err != nil {
		return buf, rem, err
	}
	buf, rem, err = m.Inverter.Marshal(buf, rem)
	if err != nil {
		return buf, rem, err
	}
	buf, rem, err = surge.Marshal(m.InitMsgs, buf, rem)
	if err != nil {
		return buf, rem, err
	}
	buf, rem, err = surge.Marshal(m.OutputShares, buf, rem)
	if err != nil {
		return buf, rem, err
	}
	return surge.Marshal(m.OutputCommitments, buf, rem)
}

// Unmarshal implements the surge.Unmarshaler interface.
func (m *Machine) Unmarshal(buf []byte, rem int) ([]byte, int, error) {
	buf, rem, err := m.OwnID.Unmarshal(buf, rem)
	if err != nil {
		return buf, rem, err
	}
	buf, rem, err = m.Inverter.Unmarshal(buf, rem)
	if err != nil {
		return buf, rem, err
	}
	buf, rem, err = surge.Unmarshal(&m.InitMsgs, buf, rem)
	if err != nil {
		return buf, rem, err
	}
	buf, rem, err = surge.Unmarshal(&m.OutputShares, buf, rem)
	if err != nil {
		return buf, rem, err
	}
	return surge.Unmarshal(&m.OutputCommitments, buf, rem)
}
