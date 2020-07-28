package rngutil

import (
	"fmt"

	"github.com/renproject/secp256k1"
	"github.com/renproject/shamir"
	"github.com/renproject/surge"

	"github.com/renproject/mpc/mpcutil"

	"github.com/renproject/mpc/rng"
)

// RngMachine type represents the structure of an RNG machine
// in the execution of the RNG protocol
type RngMachine struct {
	id      mpcutil.ID
	index   secp256k1.Fn
	indices []secp256k1.Fn
	rnger   rng.RNGer

	directedOpenings  map[secp256k1.Fn]shamir.VerifiableShares
	outputShares      shamir.VerifiableShares
	outputCommitments []shamir.Commitment
}

// NewRngMachine creates a new instance of RNG machine
// and transitions it to the WaitingOpen state by supplying its own shares
func NewRngMachine(
	id mpcutil.ID,
	index secp256k1.Fn,
	indices []secp256k1.Fn,
	b, k int,
	h secp256k1.Point,
	isZero bool,
	ownSetsOfShares []shamir.VerifiableShares,
	ownSetsOfCommitments [][]shamir.Commitment,
) RngMachine {
	_, rnger, directedOpenings, commitments := rng.New(index, indices, h, ownSetsOfShares, ownSetsOfCommitments, isZero)

	return RngMachine{
		id:      id,
		index:   index,
		indices: indices,
		rnger:   rnger,

		directedOpenings:  directedOpenings,
		outputShares:      nil,
		outputCommitments: commitments,
	}
}

// ID returns the index of the RNG machine in the list of machines
func (machine RngMachine) ID() mpcutil.ID {
	return machine.id
}

// Index returns the index assigned to the machine in the network of RNG machines
func (machine RngMachine) Index() secp256k1.Fn {
	return machine.index
}

// RandomNumbersShares returns the reconstructed shares for the
// unbiased random numbers.
func (machine RngMachine) RandomNumbersShares() shamir.VerifiableShares {
	return machine.outputShares
}

// Commitments returns the commitments for the batch of unbiased random numbers
func (machine RngMachine) Commitments() []shamir.Commitment {
	return machine.outputCommitments
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

		openings := machine.directedOpenings[to]
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
		_, shares := machine.rnger.TransitionOpen(msg.openings)
		if shares != nil {
			machine.outputShares = shares
		}
		return nil

	default:
		panic("unexpected message type")
	}
}

// SizeHint implements surge SizeHinter
func (machine RngMachine) SizeHint() int {
	return machine.id.SizeHint() +
		machine.index.SizeHint() +
		surge.SizeHint(machine.indices) +
		machine.rnger.SizeHint()
}

// Marshal implements surge Marshaler
func (machine RngMachine) Marshal(buf []byte, rem int) ([]byte, int, error) {
	buf, rem, err := machine.id.Marshal(buf, rem)
	if err != nil {
		return buf, rem, fmt.Errorf("marshaling id: %v", err)
	}
	buf, rem, err = machine.index.Marshal(buf, rem)
	if err != nil {
		return buf, rem, fmt.Errorf("marshaling index: %v", err)
	}
	buf, rem, err = surge.Marshal(machine.indices, buf, rem)
	if err != nil {
		return buf, rem, fmt.Errorf("marshaling indices: %v", err)
	}
	buf, rem, err = machine.rnger.Marshal(buf, rem)
	if err != nil {
		return buf, rem, fmt.Errorf("marshaling rnger: %v", err)
	}
	return buf, rem, nil
}

// Unmarshal implements surge Unmarshaler
func (machine *RngMachine) Unmarshal(buf []byte, rem int) ([]byte, int, error) {
	buf, rem, err := machine.id.Unmarshal(buf, rem)
	if err != nil {
		return buf, rem, fmt.Errorf("unmarshaling id: %v", err)
	}
	buf, rem, err = machine.index.Unmarshal(buf, rem)
	if err != nil {
		return buf, rem, fmt.Errorf("unmarshaling index: %v", err)
	}
	buf, rem, err = surge.Unmarshal(&machine.indices, buf, rem)
	if err != nil {
		return buf, rem, fmt.Errorf("unmarshaling indices: %v", err)
	}
	buf, rem, err = machine.rnger.Unmarshal(buf, rem)
	if err != nil {
		return buf, rem, fmt.Errorf("unmarshaling rnger: %v", err)
	}
	return buf, rem, nil
}
