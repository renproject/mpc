package rkpg

import "fmt"

// TransitionEvent represents a result of a state transition.
type TransitionEvent uint8

// Enumeration for state transition events.
const (
	WrongBatchSize = TransitionEvent(iota)
	InvalidIndex
	DuplicateIndex
	InconsistentShares
	ShareAdded
	TooManyErrors
	Reconstructed
)

// String implements the Stringer interface.
func (e TransitionEvent) String() string {
	switch e {
	case WrongBatchSize:
		return "WrongBatchSize"
	case InvalidIndex:
		return "InvalidIndex"
	case DuplicateIndex:
		return "DuplicateIndex"
	case InconsistentShares:
		return "InconsistentShares"
	case ShareAdded:
		return "ShareAdded"
	case TooManyErrors:
		return "TooManyErrors"
	case Reconstructed:
		return "Reconstructed"
	default:
		return fmt.Sprintf("Unknown(%v)", uint8(e))
	}
}
