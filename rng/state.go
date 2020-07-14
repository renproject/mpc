package rng

import (
	"fmt"

	"github.com/renproject/surge"
)

// State is an enumeration of the possible states for the RNG state machine
type State uint8

// Constants that represent the different possible states for RNGer
const (
	// Init signifies that the RNG state machine is in the initialises state
	Init = State(iota)

	// WaitingOpen signifies that the RNG state machine is waiting for more
	// openings from other players in the network, it does not say anything about
	// whether or not the machine has not received shares to construct its own shares
	WaitingOpen

	// Done signifies that the RNG state machine has received `k` share openings,
	// that may or may not include the machine's own share. It also signifies
	// that the state machine now holds and can respond with `b` unbiased random numbers
	Done
)

// String implements the Stringer interface
func (s State) String() string {
	switch s {
	case Init:
		return "Init"
	case WaitingOpen:
		return "WaitingOpen"
	case Done:
		return "Done"
	default:
		return fmt.Sprintf("Unknown(%v)", uint8(s))
	}
}

// SizeHint implements the surge.SizeHinter interface
func (s State) SizeHint() int { return 1 }

// Marshal implements the surge.Marshaler interface
func (s State) Marshal(buf []byte, rem int) ([]byte, int, error) {
	return surge.Marshal(uint8(s), buf, rem)
}

// Unmarshal implements the surge.Unmarshaler interface
func (s *State) Unmarshal(buf []byte, rem int) ([]byte, int, error) {
	return surge.Unmarshal((*uint8)(s), buf, rem)
}
