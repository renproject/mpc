package rng

import (
	"fmt"
)

// TransitionEvent represents the different outcomes that can occur when
// the state machine receives and processes shares/openings
type TransitionEvent uint8

const (
	// Initialised represents the event returned when the RNG state machine
	// is initialised and hence is now in the Init state
	Initialised = TransitionEvent(iota)

	// SharesIgnored represents the event returned when the RNG state machine
	// received `b` sets of verifiable shares that were invalid in some way
	SharesIgnored

	// SharesConstructed represents the event returned when the RNG state machine
	// received `b` valid sets of verifiable shares and it was able to
	// construct its own shares successfully
	SharesConstructed

	// OpeningsIgnored represents the event returned when the RNG state machine
	// received directed openings that were invalid in some way
	OpeningsIgnored

	// OpeningsInconsistent represents the event returned when the RNG state machine
	// received directed openings from a player which are inconsistent with their
	// respective commitments
	OpeningsInconsistent

	// OpeningsAdded represents the event returned when the RNG state machine
	// received valid directed openings and hence added them to its sets of openings
	OpeningsAdded

	// RNGsReconstructed represents the event returned when the RNG state machine
	// received the `k` set of directed openings and hence was able to reconstruct
	// `b` random numbers. This also signifies that the RNG state machine has now
	// transitioned to the `Done` state and holds the reconstructed unbiased random numbers
	RNGsReconstructed
)

// String implements the Stringer interface
func (e TransitionEvent) String() string {
	switch e {
	case Initialised:
		return "Initialised"
	case SharesIgnored:
		return "SharesIgnored"
	case SharesConstructed:
		return "SharesConstructed"
	case OpeningsIgnored:
		return "OpeningsIgnored"
	case OpeningsInconsistent:
		return "OpeningsInconsistent"
	case OpeningsAdded:
		return "OpeningsAdded"
	case RNGsReconstructed:
		return "RNGsReconstructed"
	default:
		return fmt.Sprintf("Unknown transition event (%v)", uint8(e))
	}
}
