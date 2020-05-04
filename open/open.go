package open

import (
	"fmt"

	"github.com/renproject/secp256k1-go"
	"github.com/renproject/shamir"
	"github.com/renproject/shamir/curve"
)

// Fn is a convenience type alias.
type Fn = secp256k1.Secp256k1N

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

	// InvalidShare signifies that the received share is not valid with respect
	// to the commitment for the current sharing instance. This can be output
	// in both the Waiting and Done states.
	InvalidShare

	// ShareAdded signifies that a share was valid and added to the list of
	// valid shares. This can happen either in the Waiting state when there are
	// still not enough shares for reconstruction, or in the Done state.
	ShareAdded
)

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
	case InvalidShare:
		s = "InvalidShare"
	case ShareAdded:
		s = "ShareAdded"
	default:
		s = "?"
	}
	return s
}

// ResetEvent repesents the different outcomes that can occur when the state
// machine processes a Reset input.
type ResetEvent uint8

const (
	// Aborted indicates that the state machine was reset without having reaced
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
		s = "?"
	}
	return s
}

// Opener is a state machine that handles the collecting of verifiable secret
// shares and the reconstruction (if possible) of these shares to yield the
// underlying secret. The state machine is designed to be resettable: the same
// instance of a Opener can be used to open many different sharings, as opposed
// to being one time use. However, each instance of the state machine is
// specific to a given set of indices of the parties (i.e. the set of possible
// indices that shares can have) and system parameter for the Pedersen
// commitments used in the verifiable secret sharing scheme.
//
// The state machine states and transitions are as follows. At a high level,
// the states need to capture:
//
//	- The current sharing instance
//	- Whether or not there are enough valid shares to perform a reconstruction
//
// The information needed for the sharing instance is captured by the
// commitment `c` for the verifiable secret sharing instance, and the
// associated reconstruction threshold `k`. The information that determines
// whether it is possible to reconstruct is simply the number of valid shares
// received `i`, and also `k`. The number of shares received is maintained
// indirectly by storing all valid shares received, the latter of course need
// to be saved in order to be able to perform a reconstruction. These three
// variables, `c`, `k` and `i`, represent the entirety of the state needed for
// the state transition logic. It is however convenient to group subsets of the
// possible states into higher level states that reflect the higher level
// operation of the state machine. The two main higher level states are Waiting
// and Done. Additionally, there is an additional state Uninitialised that the
// state machine is in upon construction and once moving to one of the other
// two states will never be in this state again. To summarise, the high level
// states (parameterised by the relevant parts of the lower level state) are
//
//	1. Uninitialised
//	2. Waiting(`c`, `k`, `i`)
//	3. Done(`c`)
//
// Now we consider the state transitions. There are only two triggers for state
// transitions:
//
//	- Receiving a new share
//	- Resetting for a new sharing instance
//
// All of the state transitions are listed in the following and are grouped by
// the current state. The condition Valid('c') for a share means that the share
// is valid with repect to the commitment `c` and also that the index for the
// share does not equal any of the indices in the current set of valid shares
// and that it is in the list of indices that the state machine was constructed
// with.
//
//	- Uninitialised
//		- New instance(`c`, `k`) 	-> Waiting(`c`, `k`, `0`)
//		- Otherwise 				-> Do nothing
//	- Waiting(`c`, `k`, `k-1`)
//		- New instance(`c`, `k`) 	-> Waiting(`c`, `k`, `0`)
//		- Share, Valid(`c`) 		-> Done(`c`)
//		- Otherwise -> Do nothing
//	- Waiting(`c`, `k`, `i`), `i` < `k-1`
//		- New instance(`c`, `k`) 	-> Waiting(`c`, `k`, `0`)
//		- Share, Valid(`c`) 		-> Waiting(`c`, `k`, `i+1`)
//		- Otherwise -> Do nothing
//	- Done(`c`)
//		- New instance(`c`, `k`) 	-> Waiting(`c`, `k`, `0`)
//		- Otherwise 				-> Do nothing
//
// Alternatively, the state transitions can be grouped by message.
//
//	- New instance(`c`, `k`)
//		- Any -> Waiting(`c`, `k`, `0`)
//	- Share, Valid(`c`)
//		- Waiting(`c`, `k`, `k-1`) 				-> Done(`c`)
//		- Waiting(`c`, `k`, `i`), `i` < `k-1` 	-> Waiting(`c`, `k`, `i+1`)
type Opener struct {
	// Event machine state
	commitment  shamir.Commitment
	k           int
	shareBuffer shamir.Shares

	// Other members
	secret        Fn
	checker       shamir.VSSChecker
	reconstructor shamir.Reconstructor
}

// K returns the reconstruction threshold for the current sharing instance.
func (opener *Opener) K() int {
	return opener.k
}

// I returns the current number of valid shares that the opener has received.
func (opener *Opener) I() int {
	return len(opener.shareBuffer)
}

// Secret returns the reconstructed secret for the current sharing instance,
// but only if the state is Done. Otherwise, it will return the secret for the
// last sharing instance that made it to state Done. If the state machine has
// never been in the state Done, then the zero share is returned.
func (opener *Opener) Secret() Fn {
	return opener.secret
}

// New returns a new instance of the Opener state machine for the given set of
// indices and the given Pedersen commitment system parameter. The state
// machine begins in the Uninitialised state.
func New(indices []Fn, h curve.Point) Opener {
	return Opener{
		commitment:    shamir.Commitment{},
		k:             0,
		shareBuffer:   make(shamir.Shares, len(indices))[:0],
		secret:        Fn{},
		checker:       shamir.NewVSSChecker(h),
		reconstructor: shamir.NewReconstructor(indices),
	}
}

// TransitionShare handles the state transition logic upon receiving a share,
// and returns a ShareEvent that describes the outcome of the state transition.
// See the documentation for the different ShareEvent possiblities for their
// significance.
func (opener *Opener) TransitionShare(share shamir.VerifiableShare) ShareEvent {
	// Do nothing when in the Uninitialised state. This can be checked by
	// seeing if k is zero, as Resetting the state machine can only be done if
	// k is greater than 0.
	if opener.k <= 0 {
		return Ignored
	}

	if !opener.checker.IsValid(&opener.commitment, &share) {
		return InvalidShare
	}

	// Check if a share with this index is already in the buffer. Note that
	// since we have already checked that the share is valid, it is necessarily
	// the case that if the index is a duplicate, so too will be the entire
	// share.
	//
	// TODO: These temporary variables are gross, and there will probably be an
	// easier way if we were using shares that assumed the indices of the
	// shares were sequential starting from 1. Look into enforcing this.
	var ind Fn
	innerShare := share.Share()
	for _, s := range opener.shareBuffer {
		ind = s.Index()
		if innerShare.IndexEq(&ind) {
			return IndexDuplicate
		}
	}

	// If the share buffer is full and the index is not a duplicate, it must be
	// out of range. Note that since this share has passed the above checks, it
	// must actually be a valid share. This requires knowledge of the sharing
	// polynomials which would imply either a malicious dealer or a malicious
	// player that contructs new valid shares after being able to open.
	if len(opener.shareBuffer) == cap(opener.shareBuffer) {
		return IndexOutOfRange
	}

	// At this stage we know that the share is allowed to be added to the
	// buffer.
	opener.shareBuffer = append(opener.shareBuffer, share.Share())

	// If we have just added the kth share, we can reconstruct.
	if len(opener.shareBuffer) == opener.k {
		var err error
		opener.secret, err = opener.reconstructor.CheckedOpen(opener.shareBuffer, opener.k)

		// The previous checks should ensure that the error does not occur.
		//
		// TODO: It seems wrong that we did the checks here, but then many of
		// the same checks get run in CheckedOpen. Think about whether this is
		// OK.
		if err != nil {
			panic(err)
		}

		return Done
	}

	// At this stage we have added the share to the buffer but we were not yet
	// able to reconstruct.
	return ShareAdded
}

// TransitionReset handles the state transition logic on receiving a Reset
// message, and returns a ResetEvent that describes the outcome of the state
// transition. See the documentation for the different ResetEvent possiblities
// for their significance.
func (opener *Opener) TransitionReset(c shamir.Commitment, k int) ResetEvent {
	// It is not valid for k to be less than 1
	if k < 1 {
		panic(fmt.Sprintf("k must be greater than 0: got %v", k))
	}

	var ret ResetEvent
	if len(opener.shareBuffer) < opener.k {
		ret = Aborted
	} else {
		ret = Reset
	}

	opener.shareBuffer = opener.shareBuffer[:0]
	opener.k = k
	opener.commitment = c

	return ret
}
