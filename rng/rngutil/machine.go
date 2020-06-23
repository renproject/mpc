package rngutil

import (
	"fmt"
	"io"

	"github.com/renproject/shamir"
	"github.com/renproject/shamir/curve"
	"github.com/renproject/shamir/util"
	"github.com/renproject/surge"

	"github.com/renproject/mpc/mpcutil"

	"github.com/renproject/mpc/open"
	"github.com/renproject/mpc/rng"
)

// RngMachine type represents the structure of an RNG machine
// in the execution of the RNG protocol
type RngMachine struct {
	id      mpcutil.ID
	index   open.Fn
	indices []open.Fn
	rnger   rng.RNGer
}

// NewRngMachine creates a new instance of RNG machine
// and transitions it to the WaitingOpen state by supplying its own shares
func NewRngMachine(
	id mpcutil.ID,
	index open.Fn,
	indices []open.Fn,
	b, k int,
	h curve.Point,
	isZero bool,
	ownSetsOfShares []shamir.VerifiableShares,
	ownSetsOfCommitments [][]shamir.Commitment,
	hasEmptyShares bool,
) RngMachine {
	_, rnger := rng.New(index, indices, uint32(b), uint32(k), h)

	if hasEmptyShares {
		_ = rnger.TransitionShares([]shamir.VerifiableShares{}, ownSetsOfCommitments, isZero)
	} else {
		_ = rnger.TransitionShares(ownSetsOfShares, ownSetsOfCommitments, isZero)
	}

	return RngMachine{
		id:      id,
		index:   index,
		indices: indices,
		rnger:   rnger,
	}
}

// ID returns the index of the RNG machine in the list of machines
func (machine RngMachine) ID() mpcutil.ID {
	return machine.id
}

// Index returns the index assigned to the machine in the network of RNG machines
func (machine RngMachine) Index() open.Fn {
	return machine.index
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

// RandomNumbersShares returns the reconstructed shares for the
// unbiased random numbers.
func (machine RngMachine) RandomNumbersShares() shamir.VerifiableShares {
	return machine.rnger.ReconstructedShares()
}

// Commitments returns the commitments for the batch of unbiased random numbers
func (machine RngMachine) Commitments() []shamir.Commitment {
	return machine.rnger.Commitments()
}

// InitialMessages implements the interface as required by a Network machine
// It returns the initial messages to be sent by a machine to another machine
// participating in the said protocol
func (machine RngMachine) InitialMessages() []mpcutil.Message {
	messages := make([]mpcutil.Message, 0, len(machine.indices)-1)
	for i, to := range machine.indices {
		if machine.id == mpcutil.ID(i) {
			continue
		}

		openings := machine.rnger.DirectedOpenings(to)
		messages = append(messages, &RngMessage{
			from:      machine.id,
			to:        mpcutil.ID(i),
			fromIndex: machine.index,
			openings:  openings,
		})
	}

	return messages
}

// Handle implements the interface as required by a Network machine
// It receives a message sent by another machine participating in the said
// protocol, and handles the message appropriately, and returns response
// messages if required
func (machine *RngMachine) Handle(msg mpcutil.Message) []mpcutil.Message {
	switch msg := msg.(type) {
	case *RngMessage:
		machine.rnger.TransitionOpen(msg.fromIndex, msg.openings)
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
