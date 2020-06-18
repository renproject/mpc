package rkpgutil

import (
	"fmt"
	"io"

	"github.com/renproject/mpc/mpcutil"
	"github.com/renproject/mpc/open"
	"github.com/renproject/mpc/rkpg"
	"github.com/renproject/mpc/rng/rngutil"
	"github.com/renproject/shamir"
	"github.com/renproject/shamir/curve"
	"github.com/renproject/shamir/util"
	"github.com/renproject/surge"
)

// RkpgMachine type represents the structure of an RKPG machine
// in the execution of the RKPG protocol
type RkpgMachine struct {
	id             mpcutil.ID
	index          open.Fn
	indices        []open.Fn
	rkpger         rkpg.RKPGer
	rzgShares      []shamir.VerifiableShares
	rzgCommitments [][]shamir.Commitment
}

// NewRkpgMachine creates a new instance of RKPG machine and transitions it to
// the WaitingRNG state by feeding it with the BRNG outputs for RNG
func NewRkpgMachine(
	id mpcutil.ID,
	index open.Fn,
	indices []open.Fn,
	b, k int,
	h curve.Point,
	rngShares []shamir.VerifiableShares,
	rngCommitments [][]shamir.Commitment,
	rzgShares []shamir.VerifiableShares,
	rzgCommitments [][]shamir.Commitment,
) RkpgMachine {
	_, rkpger := rkpg.New(index, indices, uint32(b), uint32(k), h)

	_ = rkpger.TransitionRNGShares(rngShares, rngCommitments)

	return RkpgMachine{
		id:             id,
		index:          index,
		indices:        indices,
		rkpger:         rkpger,
		rzgShares:      rzgShares,
		rzgCommitments: rzgCommitments,
	}
}

// ID returns the index of the RKPG machine in the list of machines
func (machine RkpgMachine) ID() mpcutil.ID {
	return machine.id
}

// Index returns the index assigned to the machine in the network of RKPG machines
func (machine RkpgMachine) Index() open.Fn {
	return machine.index
}

// SizeHint implements surge SizeHinter
func (machine RkpgMachine) SizeHint() int {
	return machine.id.SizeHint() +
		machine.index.SizeHint() +
		surge.SizeHint(machine.indices) +
		machine.rkpger.SizeHint() +
		surge.SizeHint(machine.rzgShares) +
		surge.SizeHint(machine.rzgCommitments)
}

// Marshal implements surge Marshaler
func (machine RkpgMachine) Marshal(w io.Writer, m int) (int, error) {
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
	m, err = machine.rkpger.Marshal(w, m)
	if err != nil {
		return m, fmt.Errorf("marshaling rkpger: %v", err)
	}

	return m, nil
}

// Unmarshal implements surge Unmarshaler
func (machine *RkpgMachine) Unmarshal(r io.Reader, m int) (int, error) {
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
	m, err = machine.rkpger.Unmarshal(r, m)
	if err != nil {
		return m, fmt.Errorf("unmarshaling rkpger: %v", err)
	}

	return m, nil
}

// KeyPairs returns the random keypairs constructed by the machine at the
// end of the RKPG protocol
func (machine RkpgMachine) KeyPairs() ([]curve.Point, shamir.VerifiableShares) {
	return machine.rkpger.KeyPairs()
}

// InitialMessages implements the interface as required by a Network machine
// It returns the initial messages to be sent by a machine to other machines
// participating in the RKPG protocol
func (machine RkpgMachine) InitialMessages() []mpcutil.Message {
	messages := make([]mpcutil.Message, 0, len(machine.indices)-1)
	for i, to := range machine.indices {
		// Skip for machine's own index
		if machine.id == mpcutil.ID(i) {
			continue
		}

		rngOpenings := machine.rkpger.DirectedRNGOpenings(to)
		messages = append(messages, rngutil.NewRngMessage(
			machine.id, mpcutil.ID(i), machine.index, rngOpenings, false,
		))
	}

	return messages
}

// Handle implements the interface as required by a Network machine
// It receives a message sent by another machine participating in the RKPG
// protocol, and handles the message appropriately returning response
// messages if required
// An RKPG machine can receive the following messages:
// - "RNG Message" for its RNGer openings
//    - Supply these openings to the RKPGer
//    - If the RNG shares reconstruction is done, supply the RZG shares
//      and return the RZG directed openings
// - "RNG Message" for its RZGer openings
//    - Supply these openings to the RKPGer
//    - If the RZG shares reconstruction is done, return the hiding openings
//      in the form of RKPG Messages
// - "RKPG Message" for its hiding openings
//    - Supply these openings to the RKPGer
func (machine *RkpgMachine) Handle(msg mpcutil.Message) []mpcutil.Message {
	switch msg := msg.(type) {
	case *rngutil.RngMessage:
		if msg.IsZero() {
			event := machine.rkpger.TransitionRZGOpen(msg.FromIndex(), msg.Openings())
			if event == rkpg.RZGReady {
				return machine.formHidingOpenings()
			}
		} else {
			event := machine.rkpger.TransitionRNGOpen(msg.FromIndex(), msg.Openings())
			if event == rkpg.RNGReady {
				machine.rkpger.TransitionRZGShares(machine.rzgShares, machine.rzgCommitments)
				return machine.formRZGMessages()
			}
		}
		return nil

	case *RkpgMessage:
		machine.rkpger.TransitionHidingOpenings(msg.hidingOpenings)
		return nil

	default:
		panic("unexpected message type")
	}
}

// formRZGMessages constructs the RNG messages representing the
// RZG openings in the RKPG protocol
func (machine *RkpgMachine) formRZGMessages() []mpcutil.Message {
	messages := make([]mpcutil.Message, 0, len(machine.indices)-1)
	for i, to := range machine.indices {
		// Skip for machine's own index
		if machine.id == mpcutil.ID(i) {
			continue
		}

		rzgOpenings := machine.rkpger.DirectedRZGOpenings(to)
		messages = append(messages, rngutil.NewRngMessage(
			machine.id, mpcutil.ID(i), machine.index, rzgOpenings, true,
		))
	}

	return messages
}

// formHidingOpenings constructs the RKPG messages representing the
// share-hiding openings in the RKPG protocol
func (machine *RkpgMachine) formHidingOpenings() []mpcutil.Message {
	messages := make([]mpcutil.Message, 0, len(machine.indices)-1)
	for i := range machine.indices {
		// Skip for machine's own index
		if machine.id == mpcutil.ID(i) {
			continue
		}

		hidingOpenings := machine.rkpger.HidingOpenings()
		messages = append(messages, &RkpgMessage{
			from:           machine.id,
			to:             mpcutil.ID(i),
			hidingOpenings: hidingOpenings,
		})
	}

	return messages
}

// unmarshalIndices reads from the io.Reader and unmarshals the data into
// machine.indices
func (machine *RkpgMachine) unmarshalIndices(r io.Reader, m int) (int, error) {
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
