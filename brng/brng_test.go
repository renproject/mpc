package brng_test

import (
	"errors"
	"fmt"
	"io"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	. "github.com/renproject/mpc/brng"
	"github.com/renproject/mpc/brng/testutil"
	. "github.com/renproject/mpc/testutil"
	"github.com/renproject/secp256k1-go"
	"github.com/renproject/shamir"
	"github.com/renproject/surge"

	mock "github.com/renproject/mpc/brng/mock"
	btu "github.com/renproject/mpc/brng/testutil"
	"github.com/renproject/shamir/curve"
	stu "github.com/renproject/shamir/testutil"
)

// The main properties that we want to test for the BRNGer state machine are
//
//	1. The state transition logic is as described in the documentation.
//	2. When the random shares are created, they are valid and consistent
//	(including the commitment), have the correct reconstruction threshold and
//	the correct batch size.
//	3. When processing a valid slice of shares from the consensus algorithm,
//	the BRNGer should output the correct summed shares and commitments.
//	4. When processing an invalid slice of shares from the consensus algorithm,
//	the BRNGer should correctly identify the incorrect shares.
//	5. In a network of n nodes, if all nodes are honest then the outputs shares
//	should constitute a valid sharing of a random number, and correspond
//	correctly the output commitments. In the presence of dishonest nodes, any
//	node that sends an incorrect share/commitment should be identified.
var _ = Describe("BRNG", func() {

	// Pedersem paramter.
	h := curve.Random()

	n := 20
	k := 7

	var (
		brnger  BRNGer
		indices []secp256k1.Secp256k1N
		b, t    int
		to      secp256k1.Secp256k1N
	)

	Setup := func() (BRNGer, int, int, secp256k1.Secp256k1N, []secp256k1.Secp256k1N) {
		b := 5
		t := k - 1
		indices := stu.RandomIndices(n)
		to := indices[0]
		brnger := New(indices, h)

		return brnger, t, b, to, indices
	}

	TransitionToWaiting := func(brnger *BRNGer, k, b int) Row {
		return brnger.TransitionStart(k, b)
	}

	TransitionToOk := func(
		brnger *BRNGer,
		to secp256k1.Secp256k1N,
		indices []secp256k1.Secp256k1N,
		k, b int,
	) {
		_ = TransitionToWaiting(brnger, k, b)
		slice := btu.RandomValidSlice(to, indices, h, k, b, k)
		_, _, _ = brnger.TransitionSlice(slice)
	}

	TransitionToError := func(
		brnger *BRNGer,
		to secp256k1.Secp256k1N,
		indices []secp256k1.Secp256k1N,
		k, t, b int,
	) {
		_ = TransitionToWaiting(brnger, k, b)
		slice, _ := testutil.RandomInvalidSlice(to, indices, h, n, k, b, k)
		_, _, _ = brnger.TransitionSlice(slice)
	}

	BeforeEach(func() {
		brnger, t, b, to, indices = Setup()
	})

	Context("State transitions (1)", func() {
		// Given that the BRNGer is in a particular state, it should transition
		// to the appropriate state or continue being in the same state
		// depending on the message supplied to it
		Context("Init state", func() {
			Specify("Start -> Waiting", func() {
				Expect(brnger.BatchSize()).To(Equal(uint32(0)))

				brnger.TransitionStart(k, b)

				Expect(brnger.State()).To(Equal(Waiting))
				Expect(brnger.BatchSize()).To(Equal(uint32(b)))
			})

			Specify("Slice -> Do nothing", func() {
				validSlice := btu.RandomValidSlice(to, indices, h, k, b, k)

				brnger.TransitionSlice(validSlice)

				Expect(brnger.State()).To(Equal(Init))
			})

			Specify("Reset -> Init", func() {
				brnger.Reset()

				Expect(brnger.State()).To(Equal(Init))
			})
		})

		Context("Waiting state", func() {
			JustBeforeEach(func() {
				TransitionToWaiting(&brnger, k, b)
			})

			Specify("Start -> Do nothing", func() {
				brnger.TransitionStart(k, b)

				Expect(brnger.State()).To(Equal(Waiting))
				Expect(brnger.BatchSize()).To(Equal(uint32(b)))
			})

			Specify("Valid Slice -> Ok", func() {
				validSlice := btu.RandomValidSlice(to, indices, h, k, b, k)
				brnger.TransitionSlice(validSlice)

				Expect(brnger.State()).To(Equal(Ok))
			})

			Specify("Invalid Slice -> Error", func() {
				invalidSlice, _ := btu.RandomInvalidSlice(to, indices, h, k, k, b, k-1)
				brnger.TransitionSlice(invalidSlice)

				Expect(brnger.State()).To(Equal(Error))
			})

			Specify("Reset -> Init", func() {
				brnger.Reset()

				Expect(brnger.State()).To(Equal(Init))
			})
		})

		Context("Ok state", func() {
			JustBeforeEach(func() {
				TransitionToOk(&brnger, to, indices, k, b)
			})

			Specify("Start -> Do nothing", func() {
				brnger.TransitionStart(k, b)

				Expect(brnger.State()).To(Equal(Ok))
			})

			Specify("Slice -> Do nothing", func() {
				validSlice := btu.RandomValidSlice(to, indices, h, k, b, k)
				brnger.TransitionSlice(validSlice)

				Expect(brnger.State()).To(Equal(Ok))
			})

			Specify("Reset -> Init", func() {
				brnger.Reset()

				Expect(brnger.State()).To(Equal(Init))
			})
		})

		Context("Error state", func() {
			JustBeforeEach(func() {
				TransitionToError(&brnger, to, indices, k, t, b)
			})

			Specify("Start -> Do nothing", func() {
				brnger.TransitionStart(k, b)

				Expect(brnger.State()).To(Equal(Error))
			})

			Specify("Slice -> Do nothing", func() {
				validSlice := btu.RandomValidSlice(to, indices, h, k, b, k)
				brnger.TransitionSlice(validSlice)

				Expect(brnger.State()).To(Equal(Error))
			})

			Specify("Reset -> Init", func() {
				brnger.Reset()

				Expect(brnger.State()).To(Equal(Init))
			})
		})
	})

	Context("Share creation (2)", func() {
		// On receiving a start message in the Init state, the state machine
		// should return a valid Row.
		Specify("the returned row should be valid", func() {
			row := brnger.TransitionStart(k, b)

			Expect(btu.RowIsValid(row, k, indices, h)).To(BeTrue())
		})

		Specify("the reconstruction threshold is correct", func() {
			row := brnger.TransitionStart(k, b)

			Expect(btu.RowIsValid(row, k-1, indices, h)).To(BeFalse())
			Expect(btu.RowIsValid(row, k, indices, h)).To(BeTrue())
		})

		Specify("the returned row should have the correct batch size", func() {
			row := brnger.TransitionStart(k, b)

			Expect(row.BatchSize()).To(Equal(b))
			Expect(brnger.BatchSize()).To(Equal(uint32(b)))
		})
	})

	Context("Valid slice processing (3)", func() {
		// On receiving a valid slice in the Waiting state, the state machine
		// should return the correct shares and commitment that correspond to
		// the slice.
		It("should correctly process a valid slice", func() {
			brnger.TransitionStart(k, b)

			expectedShares := make(shamir.VerifiableShares, b)
			expectedCommitments := make([]shamir.Commitment, b)
			validSlice := btu.RandomValidSlice(to, indices, h, k, b, k)

			for i, col := range validSlice {
				expectedShares[i], expectedCommitments[i] = col.Sum()
			}

			shares, commitments, _ := brnger.TransitionSlice(validSlice)

			Expect(len(shares)).To(Equal(b))
			Expect(len(commitments)).To(Equal(b))

			for i, share := range shares {
				Expect(share.Eq(&expectedShares[i])).To(BeTrue())
			}

			for i, commitment := range commitments {
				Expect(commitment.Eq(&expectedCommitments[i])).To(BeTrue())
			}
		})
	})

	Context("Invalid slice processing (4)", func() {
		// On receiving an invalid slice in the Waiting state, the state
		// machine should return a list of faults that correctly identifies the
		// invalid shares.
		It("should correctly identify faulty elements", func() {
			brnger.TransitionStart(k, b)

			invalidSlice, expectedFaults := btu.RandomInvalidSlice(to, indices, h, k, k, b, k-1)

			shares, commitments, faults := brnger.TransitionSlice(invalidSlice)

			Expect(len(shares)).To(Equal(0))
			Expect(len(commitments)).To(Equal(0))
			Expect(len(faults)).To(Equal(len(expectedFaults)))
			for i, expectedFault := range expectedFaults {
				Expect(faults[i]).To(Equal(expectedFault))
			}
		})
	})

	Context("Network (5)", func() {
		n = 20
		k = 7
		b = 5
		t = k - 1

		indices = stu.SequentialIndices(n)

		ids := make([]ID, 0, len(indices)+1)
		machines := make([]Machine, 0, len(indices)+1)
		for i := range indices {
			id := ID(i + 1)
			machine := newMachine(BrngTypePlayer, id, indices, h, k, b)

			ids = append(ids, id)
			machines = append(machines, &machine)
		}
		cmachine := newMachine(BrngTypeConsensus, ID(len(indices)+1), indices, h, k, b)
		ids = append(ids, ID(len(indices)))
		machines = append(machines, &cmachine)

		shuffleMsgs, _ := MessageShufflerDropper(ids, 0)

		network := NewNetwork(machines, shuffleMsgs)
		network.SetCaptureHist(true)

		Specify("correct execution of BRNG", func() {
			err := network.Run()
			Expect(err).ToNot(HaveOccurred())
		})
	})
})

type TypeID uint8

func (id TypeID) SizeHint() int { return 1 }

func (id TypeID) Marshal(w io.Writer, m int) (int, error) {
	return surge.Marshal(w, uint8(id), m)
}

func (id *TypeID) Unmarshal(r io.Reader, m int) (int, error) {
	return surge.Unmarshal(r, uint8(*id), m)
}

type PlayerMessage struct {
	from, to ID
	row      Row
}

func (pm PlayerMessage) From() ID {
	return pm.from
}

func (pm PlayerMessage) To() ID {
	return pm.to
}

func (pm PlayerMessage) Row() Row {
	return pm.row
}

func (msg PlayerMessage) SizeHint() int {
	return msg.from.SizeHint() + msg.to.SizeHint() + msg.row.SizeHint()
}

func (msg PlayerMessage) Marshal(w io.Writer, m int) (int, error) {
	m, err := msg.from.Marshal(w, m)
	if err != nil {
		return m, err
	}
	m, err = msg.to.Marshal(w, m)
	if err != nil {
		return m, err
	}
	m, err = msg.row.Marshal(w, m)
	return m, err
}

func (msg *PlayerMessage) Unmarshal(r io.Reader, m int) (int, error) {
	m, err := msg.from.Unmarshal(r, m)
	if err != nil {
		return m, err
	}
	m, err = msg.to.Unmarshal(r, m)
	if err != nil {
		return m, err
	}
	m, err = msg.row.Unmarshal(r, m)
	return m, err
}

type ConsensusMessage struct {
	from, to ID
	slice    Slice
}

func (cm ConsensusMessage) From() ID {
	return cm.from
}

func (cm ConsensusMessage) To() ID {
	return cm.to
}

func (msg ConsensusMessage) SizeHint() int {
	return msg.from.SizeHint() + msg.to.SizeHint() + msg.slice.SizeHint()
}

func (msg ConsensusMessage) Marshal(w io.Writer, m int) (int, error) {
	m, err := msg.from.Marshal(w, m)
	if err != nil {
		return m, err
	}
	m, err = msg.to.Marshal(w, m)
	if err != nil {
		return m, err
	}
	m, err = msg.slice.Marshal(w, m)
	return m, err
}

func (msg *ConsensusMessage) Unmarshal(r io.Reader, m int) (int, error) {
	m, err := msg.from.Unmarshal(r, m)
	if err != nil {
		return m, err
	}
	m, err = msg.to.Unmarshal(r, m)
	if err != nil {
		return m, err
	}
	m, err = msg.slice.Unmarshal(r, m)
	return m, err
}

const (
	BrngTypePlayer    = 1
	BrngTypeConsensus = 2
)

type BrngMessage struct {
	msgType TypeID
	pmsg    *PlayerMessage
	cmsg    *ConsensusMessage
}

func (bm BrngMessage) From() ID {
	if bm.pmsg != nil {
		return bm.pmsg.From()
	} else if bm.cmsg != nil {
		return bm.cmsg.From()
	} else {
		panic("BRNG Message not initialised")
	}
}

func (bm BrngMessage) To() ID {
	if bm.pmsg != nil {
		return bm.pmsg.To()
	} else if bm.cmsg != nil {
		return bm.cmsg.To()
	} else {
		panic("BRNG Message not initialised")
	}
}

func (bm BrngMessage) SizeHint() int {
	switch bm.msgType {
	case TypeID(BrngTypePlayer):
		return bm.msgType.SizeHint() + bm.pmsg.SizeHint()

	case TypeID(BrngTypeConsensus):
		return bm.msgType.SizeHint() + bm.cmsg.SizeHint()

	default:
		panic("uninitialised message")
	}
}

func (msg BrngMessage) Marshal(w io.Writer, m int) (int, error) {
	m, err := msg.msgType.Marshal(w, m)
	if err != nil {
		return m, err
	}

	if msg.pmsg != nil {
		return msg.pmsg.Marshal(w, m)
	} else if msg.cmsg != nil {
		return msg.cmsg.Marshal(w, m)
	} else {
		return m, errors.New("uninitialised message")
	}
}

func (msg *BrngMessage) Unmarshal(r io.Reader, m int) (int, error) {
	m, err := msg.msgType.Unmarshal(r, m)
	if err != nil {
		return m, err
	}

	if msg.msgType == TypeID(BrngTypePlayer) {
		return msg.pmsg.Unmarshal(r, m)
	} else if msg.msgType == TypeID(BrngTypeConsensus) {
		return msg.cmsg.Unmarshal(r, m)
	} else {
		return m, fmt.Errorf("invalid message type %v", msg.msgType)
	}
}

type PlayerMachine struct {
	id     ID
	row    Row
	brnger BRNGer

	shares      shamir.VerifiableShares
	commitments []shamir.Commitment
}

func (pm PlayerMachine) SizeHint() int {
	return pm.id.SizeHint() +
		pm.row.SizeHint() +
		pm.brnger.SizeHint()
}

func (pm PlayerMachine) Marshal(w io.Writer, m int) (int, error) {
	m, err := pm.id.Marshal(w, m)
	if err != nil {
		return m, err
	}
	m, err = pm.row.Marshal(w, m)
	if err != nil {
		return m, err
	}
	m, err = pm.brnger.Marshal(w, m)
	return m, err
}

func (pm *PlayerMachine) Unmarshal(r io.Reader, m int) (int, error) {
	m, err := pm.id.Unmarshal(r, m)
	if err != nil {
		return m, err
	}
	m, err = pm.row.Unmarshal(r, m)
	if err != nil {
		return m, err
	}
	m, err = pm.brnger.Unmarshal(r, m)
	return m, err
}

func (pm PlayerMachine) SetShares(shares shamir.VerifiableShares) {
	pm.shares = shares
}

func (pm PlayerMachine) SetCommitments(commitments []shamir.Commitment) {
	pm.commitments = commitments
}

func (pm PlayerMachine) ID() ID {
	return pm.id
}

func (pm PlayerMachine) Shares() shamir.VerifiableShares {
	return pm.shares
}

func (pm PlayerMachine) Commitments() []shamir.Commitment {
	return pm.commitments
}

type ConsensusMachine struct {
	id     ID
	engine mock.PullConsensus
}

func (cm ConsensusMachine) ID() ID {
	return cm.id
}

func (cm ConsensusMachine) SizeHint() int {
	return cm.id.SizeHint() + cm.engine.SizeHint()
}

func (cm ConsensusMachine) Marshal(w io.Writer, m int) (int, error) {
	m, err := cm.id.Marshal(w, m)
	if err != nil {
		return m, err
	}
	m, err = cm.engine.Marshal(w, m)
	return m, err
}

func (cm *ConsensusMachine) Unmarshal(r io.Reader, m int) (int, error) {
	m, err := cm.id.Unmarshal(r, m)
	if err != nil {
		return m, err
	}
	m, err = cm.engine.Unmarshal(r, m)
	return m, err
}

type BrngMachine struct {
	machineType TypeID
	n           uint32
	pm          *PlayerMachine
	cm          *ConsensusMachine
}

func newMachine(
	machineType int,
	id ID,
	indices []secp256k1.Secp256k1N,
	h curve.Point,
	k, b int,
) BrngMachine {
	if machineType == BrngTypePlayer {
		brnger := New(indices, h)
		row := brnger.TransitionStart(k, b)

		pmachine := PlayerMachine{
			id:          id,
			row:         row,
			brnger:      brnger,
			shares:      nil,
			commitments: nil,
		}

		return BrngMachine{
			machineType: TypeID(uint8(machineType)),
			n:           uint32(len(indices)),
			pm:          &pmachine,
			cm:          nil,
		}
	}

	if machineType == BrngTypeConsensus {
		engine := mock.NewPullConsensus(indices, k-1, h)

		cmachine := ConsensusMachine{
			id:     ID(id),
			engine: engine,
		}

		return BrngMachine{
			machineType: TypeID(uint8(machineType)),
			n:           uint32(len(indices)),
			pm:          nil,
			cm:          &cmachine,
		}
	}

	panic("unexpected machine type")
}

func (bm BrngMachine) SizeHint() int {
	switch bm.machineType {
	case TypeID(BrngTypePlayer):
		return bm.machineType.SizeHint() + 4 + bm.pm.SizeHint()

	case TypeID(BrngTypeConsensus):
		return bm.machineType.SizeHint() + 4 + bm.cm.SizeHint()

	default:
		panic("uninitialised machine")
	}
}

func (bm BrngMachine) Marshal(w io.Writer, m int) (int, error) {
	m, err := bm.machineType.Marshal(w, m)
	if err != nil {
		return m, err
	}

	m, err = surge.Marshal(w, uint32(bm.n), m)
	if err != nil {
		return m, err
	}

	if bm.pm != nil {
		return bm.pm.Marshal(w, m)
	} else if bm.cm != nil {
		return bm.cm.Marshal(w, m)
	} else {
		return m, errors.New("uninitialised machine")
	}
}

func (bm *BrngMachine) Unmarshal(r io.Reader, m int) (int, error) {
	m, err := bm.machineType.Unmarshal(r, m)
	if err != nil {
		return m, err
	}

	m, err = surge.Unmarshal(r, uint32(bm.n), m)
	if err != nil {
		return m, err
	}

	if bm.machineType == TypeID(BrngTypePlayer) {
		return bm.pm.Unmarshal(r, m)
	} else if bm.machineType == TypeID(BrngTypeConsensus) {
		return bm.cm.Unmarshal(r, m)
	} else {
		return m, fmt.Errorf("invalid message type %v", bm.machineType)
	}
}

func (bm BrngMachine) ID() ID {
	if bm.pm != nil {
		return bm.pm.ID()
	} else if bm.cm != nil {
		return bm.cm.ID()
	} else {
		panic("BRNG Machine not initialised")
	}
}

func (bm BrngMachine) InitialMessages() []Message {
	if bm.machineType == BrngTypePlayer {
		messages := make([]Message, 0, 1)

		// ids: [1, 2, ..., n-1, n] are reserved for the `n` players
		// id = n+1 is for the consensus machine
		consensusMachineId := ID(bm.n + 1)
		messages = append(messages, &BrngMessage{
			msgType: BrngTypePlayer,
			pmsg: &PlayerMessage{
				from: bm.pm.id,
				to:   consensusMachineId,
				row:  bm.pm.row,
			},
			cmsg: nil,
		})

		return messages
	}

	return nil
}

func (bm *BrngMachine) Handle(msg Message) []Message {
	bmsg := msg.(*BrngMessage)

	switch bmsg.msgType {
	case BrngTypeConsensus:
		if bmsg.cmsg != nil {
			shares, commitments, _ := bm.pm.brnger.TransitionSlice(bmsg.cmsg.slice)
			bm.pm.SetShares(shares)
			bm.pm.SetCommitments(commitments)
			return nil
		} else {
			panic("unexpected consensus message")
		}

	case BrngTypePlayer:
		if bmsg.pmsg != nil {
			bm.cm.engine.HandleRow(bmsg.pmsg.Row())
			return nil
		} else {
			panic("unexpected player message")
		}

	default:
		panic("unexpected message type")
	}
}

func (bm BrngMachine) Shares() shamir.VerifiableShares {
	if bm.machineType == BrngTypePlayer {
		if bm.pm != nil {
			return bm.pm.Shares()
		}
	}

	return nil
}

func (bm BrngMachine) Commitments() []shamir.Commitment {
	if bm.machineType == BrngTypePlayer {
		if bm.pm != nil {
			return bm.pm.Commitments()
		}
	}

	return nil
}
