package mulopenutil

import (
	"github.com/renproject/mpc/mpcutil"
	"github.com/renproject/mpc/mulopen"
	"github.com/renproject/secp256k1"
	"github.com/renproject/shamir"
)

// Machine represents a player that honestly carries out the multiply and open
// protocol.
type Machine struct {
	OwnID mpcutil.ID
	mulopen.MulOpener
	InitMsgs []mpcutil.Message
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
	initialMessages := make([]mpcutil.Message, 0, len(ids)-1)
	for _, id := range ids {
		if id == ownID {
			continue
		}
		initialMessages = append(initialMessages, &Message{
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

func (m Machine) SizeHint() int                                       { return 0 }
func (m Machine) Marshal(buf []byte, rem int) ([]byte, int, error)    { return buf, rem, nil }
func (m *Machine) Unmarshal(buf []byte, rem int) ([]byte, int, error) { return buf, rem, nil }

// ID implements the Machine interface.
func (m Machine) ID() mpcutil.ID { return m.OwnID }

// InitialMessages implements the Machine interface.
func (m Machine) InitialMessages() []mpcutil.Message { return m.InitMsgs }

// Handle implements the Machine interface.
func (m *Machine) Handle(msg mpcutil.Message) []mpcutil.Message {
	output, _ := m.MulOpener.HandleShareBatch(msg.(*Message).Messages)
	if output != nil {
		m.Output = output
	}
	return nil
}
