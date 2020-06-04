package testutil

import (
	"fmt"
	"io"

	"github.com/renproject/shamir"
	"github.com/renproject/shamir/curve"
	"github.com/renproject/shamir/util"
	"github.com/renproject/surge"

	mtu "github.com/renproject/mpc/testutil"

	"github.com/renproject/mpc/open"
	"github.com/renproject/mpc/rng"
)

// RngMachine type represents the structure of an RNG machine
// in the execution of the RNG protocol
type RngMachine struct {
	id      mtu.ID
	index   open.Fn
	indices []open.Fn
	rnger   rng.RNGer
}

// NewRngMachine creates a new instance of RNG machine
// and transitions it to the WaitingOpen state by supplying its own shares
func NewRngMachine(
	id mtu.ID,
	index open.Fn,
	indices []open.Fn,
	b, k int,
	h curve.Point,
	ownSetsOfShares []shamir.VerifiableShares,
	ownSetsOfCommitments [][]shamir.Commitment,
) RngMachine {
	_, rnger := rng.New(index, indices, uint32(b), uint32(k), h)

	_ = rnger.TransitionShares(ownSetsOfShares, ownSetsOfCommitments)

	return RngMachine{
		id:      id,
		index:   index,
		indices: indices,
		rnger:   rnger,
	}
}

// ID returns the index of the RNG machine
func (machine RngMachine) ID() mtu.ID {
	return machine.id
}

// SizeHint implements surge SizeHinter
func (machine RngMachine) SizeHint() int {
	return machine.id.SizeHint() +
		machine.index.SizeHint() +
		surge.SizeHint(machine.indices) +
		machine.rnger.SizeHint()
}

// Marshal implements surge Marshaler
func (machine RngMachine) Marshal(w io.Writer, m int) (int, error) {
	m, err := machine.id.Marshal(w, m)
	if err != nil {
		return m, fmt.Errorf("marshaling id: %v", err)
	}
	m, err = machine.index.Marshal(w, m)
	if err != nil {
		return m, fmt.Errorf("marshaling index: %v", err)
	}
	m, err = surge.Marshal(w, machine.indices, m)
	if err != nil {
		return m, fmt.Errorf("marshaling indices: %v", err)
	}
	m, err = machine.rnger.Marshal(w, m)
	if err != nil {
		return m, fmt.Errorf("marshaling rnger: %v", err)
	}

	return m, nil
}

// Unmarshal implements surge Unmarshaler
func (machine *RngMachine) Unmarshal(r io.Reader, m int) (int, error) {
	m, err := machine.id.Unmarshal(r, m)
	if err != nil {
		return m, fmt.Errorf("unmarshaling id: %v", err)
	}
	m, err = machine.index.Unmarshal(r, m)
	if err != nil {
		return m, fmt.Errorf("unmarshaling index: %v", err)
	}
	m, err = machine.unmarshalIndices(r, m)
	if err != nil {
		return m, fmt.Errorf("unmarshaling indices: %v", err)
	}
	m, err = machine.rnger.Unmarshal(r, m)
	if err != nil {
		return m, fmt.Errorf("unmarshaling rnger: %v", err)
	}

	return m, nil
}

// UnbiasedRandomNumbers returns the unbiased random numbers reconstructed
func (machine RngMachine) UnbiasedRandomNumbers() []open.Fn {
	return machine.rnger.ReconstructedRandomNumbers()
}

// InitialMessages implements the interface as required by a Network machine
// It returns the initial messages to be sent by a machine to another machine
// participating in the said protocol
func (machine RngMachine) InitialMessages() []mtu.Message {
	messages := make([]mtu.Message, 0, len(machine.indices)-1)
	for i, to := range machine.indices {
		if machine.id == mtu.ID(i) {
			continue
		}

		openings, commitments := machine.rnger.DirectedOpenings(to)
		messages = append(messages, &RngMessage{
			from:        machine.id,
			to:          mtu.ID(i),
			fromIndex:   machine.index,
			openings:    openings,
			commitments: commitments,
		})
	}

	return messages
}

// Handle implements the interface as required by a Network machine
// It receives a message sent by another machine participating in the said
// protocol, and handles the message appropriately, and returns response
// messages if required
func (machine *RngMachine) Handle(msg mtu.Message) []mtu.Message {
	switch msg := msg.(type) {
	case *RngMessage:
		machine.rnger.TransitionOpen(msg.fromIndex, msg.openings, msg.commitments)
		return nil

	default:
		panic("unexpected message type")
	}
}

// Private methods
func (machine *RngMachine) unmarshalIndices(r io.Reader, m int) (int, error) {
	var l uint32
	m, err := util.UnmarshalSliceLen32(&l, shamir.FnSizeBytes, r, m)
	if err != nil {
		return m, err
	}

	machine.indices = (machine.indices)[:0]
	for i := uint32(0); i < l; i++ {
		machine.indices = append(machine.indices, open.Fn{})
		m, err = machine.indices[i].Unmarshal(r, m)
		if err != nil {
			return m, err
		}
	}

	return m, nil
}
