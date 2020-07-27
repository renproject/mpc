package open

import "fmt"

// ShareEvent represents the different outcomes that can occur when the state
// machine processes a share.
type ShareEvent uint8

const (
	// Done signifies that the state machine now has transitioned to Done
	// because it now has enough shares to perform a reconstruction of the
	// secret. This therefore means that the secret was reconstructed and can
	// now be accessed for this sharing instance.
	Done = ShareEvent(iota)

	// Ignored signifies that the state machine is currently in the
	// Uninitialised state and so the share was ignored.
	Ignored

	// IndexDuplicate signifies that the received share has an index that is
	// the same as the index of one of the shares that is already in the list
	// of valid shares received for the current sharing instance. This can be
	// output in both the Waiting and Done states.
	IndexDuplicate

	// IndexOutOfRange signifies that the received share has an index that is
	// not in the set of indices that the state machine was constructed with.
	// This can be output in both the Waiting and Done states.
	IndexOutOfRange

	// InvalidShares signifies that at least one out of the received shares
	// is not valid with respect to the commitment for the current sharing
	// instance. This can be output in both the Waiting and Done states.
	InvalidShares

	// SharesAdded signifies that a set of shares was valid and added to the list of
	// set of valid shares. This can happen either in the Waiting state when there are
	// still not enough shares for reconstruction, or in the Done state.
	SharesAdded
)

// String implements the Stringer interface.
func (e ShareEvent) String() string {
	var s string
	switch e {
	case Done:
		s = "Done"
	case Ignored:
		s = "Ignored"
	case IndexDuplicate:
		s = "IndexDuplicate"
	case IndexOutOfRange:
		s = "IndexOutOfRange"
	case InvalidShares:
		s = "InvalidShares"
	case SharesAdded:
		s = "SharesAdded"
	default:
		s = fmt.Sprintf("Unknown(%v)", uint8(e))
	}
	return s
}

// ResetEvent repesents the different outcomes that can occur when the state
// machine processes a Reset input.
type ResetEvent uint8

const (
	// Aborted indicates that the state machine was reset without having reached
	// the Done state for the given sharing instance.
	Aborted = ResetEvent(iota)

	// Reset indicates that the state machine was either in the Uninitialised
	// state or the Done state for a sharing instance when it was reset.
	Reset
)

func (e ResetEvent) String() string {
	var s string
	switch e {
	case Aborted:
		s = "Aborted"
	case Reset:
		s = "Reset"
	default:
		s = fmt.Sprintf("Unknown(%v)", uint8(e))
	}
	return s
}
