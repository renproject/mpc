package rkpg

import (
	"fmt"
)

// TransitionEvent represents the different outcomes that can occur when
// the RKPG state machine receives and processes shares/openings
type TransitionEvent uint8

const (
	// Initialised represents the event returned when the RKPG state machine
	// is initialised and hence is now in the Init state
	Initialised = TransitionEvent(iota)

	// RNGInputsIgnored represents the event returned when BRNG outputs were
	// fed to the embedded RNGer, and the inputs were ignored as being invalid
	// or RNGer/RKPGer not being in the appropriate state
	RNGInputsIgnored

	// RNGInputsAccepted represents the event returned when BRNG outputs were
	// fed to the embedded RNGer, and the inputs were processed successfully.
	// This also means the RKPGer must transition to the WaitingRNG state
	RNGInputsAccepted

	// RNGOpeningsIgnored represents the event returned when RNG openings from
	// another player failed the validity check or if any of the state machines
	// was not in appropriate state
	RNGOpeningsIgnored

	// RNGOpeningsAccepted represents the event returned when RNG openings from
	// another player were valid and added to the RNGer's opener. It also means
	// that the RKPGer's embedded RNGer still does not have enough openings to
	// be able to reconstruct its shares for the unbiased random numbers
	RNGOpeningsAccepted

	// RNGReady represents the event of RKPG's embedded RNGer being able to
	// successfully reconstruct its shares for the unbiased random numbers
	RNGReady

	// RZGInputsIgnored represents the event returned when BRNG outputs were
	// fed to the embedded RZGer, and the inputs were ignored as being invalid
	// or RZGer/RKPGer not being in the appropriate state
	RZGInputsIgnored

	// RZGInputsAccepted represents the event returned when BRNG outputs were
	// fed to the embedded RZGer, and the inputs were processed successfully.
	// This also means the RKPGer must transition to the WaitingRZG state
	RZGInputsAccepted

	// RZGOpeningsIgnored represents the event returned when RZG openings from
	// another player failed the validity check or if any of the state machines
	// was not in appropriate state
	RZGOpeningsIgnored

	// RZGOpeningsAccepted represents the event returned when RZG openings from
	// another player were valid and added to the RZGer's opener. It also means
	// that the RKPGer's embedded RZGer still does not have enough openings to
	// be able to reconstruct its shares for the random zeroes
	RZGOpeningsAccepted

	// RZGReady represents the event of RKPG's embedded RZGer being able to
	// successfully reconstruct its shares for the random zeroes
	RZGReady

	// ResetAborted is the event returned when a reset operation on the RKPGer
	// failed and hence transition to the Init state was aborted
	ResetAborted

	// ResetDone is the event returned when a reset operation on the RKPGer
	// was successful and hence it transitioned to the Init state
	ResetDone
)

// String implements the Stringer interface
func (e TransitionEvent) String() string {
	switch e {
	case Initialised:
		return "Initialised"
	case RNGInputsIgnored:
		return "RNGInputsIgnored"
	case RNGInputsAccepted:
		return "RNGInputsAccepted"
	case RNGOpeningsIgnored:
		return "RNGOpeningsIgnored"
	case RNGOpeningsAccepted:
		return "RNGOpeningsAccepted"
	case RNGReady:
		return "RNGReady"
	case RZGInputsIgnored:
		return "RZGInputsIgnored"
	case RZGInputsAccepted:
		return "RZGInputsAccepted"
	case RZGOpeningsIgnored:
		return "RZGOpeningsIgnored"
	case RZGOpeningsAccepted:
		return "RZGOpeningsAccepted"
	case RZGReady:
		return "RZGReady"
	default:
		return fmt.Sprintf("Unknown transition event (%v)", uint8(e))
	}
}
