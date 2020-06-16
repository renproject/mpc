package rkpg

import (
	"fmt"
	"io"

	"github.com/renproject/surge"
)

// State is an enumeration of the possible states for the RKPG state machine
type State uint8

// Constants that represent the different possible states for RKPGer
const (
	// Init state signifies that the RKPGer is in the initialised state
	Init = State(iota)

	// WaitingRNG represents the state when the RKPGer is in progress constructing
	// the unbiased random numbers, it also coincides with the RNGer's state of
	// WaitingOpen as it waits for threshold number of openings from other machines
	WaitingRNG

	// RNGsReady represents the state when the RKPGer has successfully
	// constructed a batch of unbiased random numbers and is now waiting for
	// BRNG outputs to begin the random zero generation
	RNGsReady

	// WaitingRZG represents the state when the RKPGer has received BRNG outputs
	// for its random zero generation and is waiting for threshold number of
	// openings from other machines
	WaitingRZG

	// WaitingOpen signifies that the RKPGer has successfully completed random zero
	// generation. It is now participating in the share-hiding opening of the
	// decommitment field for the batch of unbiased random numbers. This coincides
	// with the RKPGer's opener's state of Waiting
	WaitingOpen

	// Done represents the state of RKPGer where it has successfully reconstructed
	// a batch of random Secp256k1 public keys. In this state, the RKPGer can
	// respond with the reconstructed public keys and its own verifiable shares
	// of the corresponding unbiased random numbers
	Done
)

// String implements the Stringer interface
func (s State) String() string {
	switch s {
	case Init:
		return "Init"
	case WaitingRNG:
		return "WaitingRNG"
	case RNGsReady:
		return "RNGsReady"
	case WaitingRZG:
		return "WaitingRZG"
	case WaitingOpen:
		return "WaitingOpen"
	case Done:
		return "Done"
	default:
		return fmt.Sprintf("Unknown state (%v)", uint8(s))
	}
}

// SizeHint implements the surge.SizeHinter interface
func (s State) SizeHint() int { return 1 }

// Marshal implements the surge.Marshaler interface
func (s State) Marshal(w io.Writer, m int) (int, error) {
	return surge.Marshal(w, uint8(s), m)
}

// Unmarshal implements the surge.Unmarshaler interface
func (s *State) Unmarshal(r io.Reader, m int) (int, error) {
	return surge.Unmarshal(r, (*uint8)(s), m)
}
