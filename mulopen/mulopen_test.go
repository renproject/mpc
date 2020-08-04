package mulopen_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	. "github.com/renproject/mpc/mulopen"
	"github.com/renproject/mpc/rkpg/rkpgutil"
	"github.com/renproject/shamir"

	"github.com/renproject/mpc/mpcutil"
	"github.com/renproject/secp256k1"
	"github.com/renproject/shamir/shamirutil"
)

var _ = Describe("MulOpener", func() {
	Context("network", func() {
		n := 20
		k := 6
		b := 5

		Specify("all honest nodes should reconstruct the product of the secrets", func() {
			indices := shamirutil.RandomIndices(n)
			h := secp256k1.RandomPoint()
			machines := make([]mpcutil.Machine, n)

			aShares, aCommitments, aSecrets := rkpgutil.RNGOutputBatch(indices, k, b, h)
			bShares, bCommitments, bSecrets := rkpgutil.RNGOutputBatch(indices, k, b, h)
			rzgShares, rzgCommitments := rkpgutil.RZGOutputBatch(indices, k, b, h)

			ids := make([]mpcutil.ID, n)
			for i := range ids {
				ids[i] = mpcutil.ID(i + 1)
			}

			for i, id := range ids {
				machine := NewMachine(
					aShares[i], bShares[i], rzgShares[i],
					aCommitments, bCommitments, rzgCommitments,
					ids, id, indices, h,
				)
				machines[i] = &machine
			}

			shuffleMsgs, _ := mpcutil.MessageShufflerDropper(ids, 0)
			network := mpcutil.NewNetwork(machines, shuffleMsgs)
			network.SetCaptureHist(true)
			err := network.Run()
			Expect(err).ToNot(HaveOccurred())

			for i := 0; i < b; i++ {
				var product secp256k1.Fn
				product.Mul(&aSecrets[i], &bSecrets[i])

				for _, machine := range machines {
					output := machine.(*Machine).Output[i]
					Expect(output.Eq(&product)).To(BeTrue())
				}
			}
		})
	})
})

type Machine struct {
	OwnID mpcutil.ID
	MulOpener
	InitMsgs []mpcutil.Message
	Output   []secp256k1.Fn
}

func (m Machine) SizeHint() int                                       { return 0 }
func (m Machine) Marshal(buf []byte, rem int) ([]byte, int, error)    { return buf, rem, nil }
func (m *Machine) Unmarshal(buf []byte, rem int) ([]byte, int, error) { return buf, rem, nil }

func (m Machine) ID() mpcutil.ID                     { return m.OwnID }
func (m Machine) InitialMessages() []mpcutil.Message { return m.InitMsgs }

func (m *Machine) Handle(msg mpcutil.Message) []mpcutil.Message {
	output, _ := m.MulOpener.HandleShareBatch(msg.(*Msg).Messages)
	if output != nil {
		m.Output = output
	}
	return nil
}

func NewMachine(
	aShareBatch, bShareBatch, rzgShareBatch shamir.VerifiableShares,
	aCommitmentBatch, bCommitmentBatch, rzgCommitmentBatch []shamir.Commitment,
	ids []mpcutil.ID, ownID mpcutil.ID, indices []secp256k1.Fn, h secp256k1.Point,
) Machine {
	mulopener, msgs := New(
		aShareBatch, bShareBatch, rzgShareBatch,
		aCommitmentBatch, bCommitmentBatch, rzgCommitmentBatch,
		indices, h,
	)
	initialMessages := make([]mpcutil.Message, len(ids))
	for i, id := range ids {
		initialMessages[i] = &Msg{
			FromID:   ownID,
			ToID:     id,
			Messages: msgs,
		}
	}
	return Machine{
		OwnID:     ownID,
		MulOpener: mulopener,
		InitMsgs:  initialMessages,
	}
}

type Msg struct {
	FromID, ToID mpcutil.ID
	Messages     []Message
}

func (msg Msg) From() mpcutil.ID { return msg.FromID }
func (msg Msg) To() mpcutil.ID   { return msg.ToID }

func (msg Msg) SizeHint() int                                       { return 0 }
func (msg Msg) Marshal(buf []byte, rem int) ([]byte, int, error)    { return buf, rem, nil }
func (msg *Msg) Unmarshal(buf []byte, rem int) ([]byte, int, error) { return buf, rem, nil }
