package open

import (
	"fmt"

	"github.com/renproject/secp256k1"
	"github.com/renproject/shamir"
	"github.com/renproject/surge"
)

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
// The Opener state machine functions in batches, and has a batch size
// associated with it. The number of shares it receives every time MUST be
// equal to the batch size. When it has received threshold number of sets
// of shares, it reconstructs all the secrets, a total of batch size in number.
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
//		- Otherwise 			-> Do nothing
//	- Waiting(`c`, `k`, `k-1`)
//		- New instance(`c`, `k`) 	-> Waiting(`c`, `k`, `0`)
//		- Share, Valid(`c`) 		-> Done(`c`)
//		- Otherwise 			-> Do nothing
//	- Waiting(`c`, `k`, `i`), `i` < `k-1`
//		- New instance(`c`, `k`) 	-> Waiting(`c`, `k`, `0`)
//		- Share, Valid(`c`) 		-> Waiting(`c`, `k`, `i+1`)
//		- Otherwise 			-> Do nothing
//	- Done(`c`)
//		- New instance(`c`, `k`) 	-> Waiting(`c`, `k`, `0`)
//		- Otherwise 			-> Do nothing
//
// Alternatively, the state transitions can be grouped by message.
//
//	- New instance(`c`, `k`)
//		- Any -> Waiting(`c`, `k`, `0`)
//	- Share, Valid(`c`)
//		- Waiting(`c`, `k`, `k-1`) 		-> Done(`c`)
//		- Waiting(`c`, `k`, `i`), `i` < `k-1` 	-> Waiting(`c`, `k`, `i+1`)
type Opener struct {
	// Event machine state
	batchSize    uint32
	commitments  []shamir.Commitment
	shareBuffers []shamir.Shares
	decomBuffers []shamir.Shares
	// The state variable `k` in the formal description can be computed using
	// the commitment alone.

	// Other members
	secrets       []secp256k1.Fn
	decommitments []secp256k1.Fn
	checker       shamir.VSSChecker
	reconstructor shamir.Reconstructor
}

// SizeHint implements the surge.SizeHinter interface.
func (opener Opener) SizeHint() int {
	return surge.SizeHint(opener.batchSize) +
		surge.SizeHint(opener.commitments) +
		surge.SizeHint(opener.shareBuffers) +
		surge.SizeHint(opener.decomBuffers) +
		surge.SizeHint(opener.secrets) +
		surge.SizeHint(opener.decommitments) +
		opener.checker.SizeHint() +
		opener.reconstructor.SizeHint()
}

// Marshal implements the surge.Marshaler interface.
func (opener Opener) Marshal(buf []byte, rem int) ([]byte, int, error) {
	buf, rem, err := surge.MarshalU32(opener.batchSize, buf, rem)
	if err != nil {
		return buf, rem, fmt.Errorf("marshaling batchSize: %v", err)
	}
	buf, rem, err = surge.Marshal(opener.commitments, buf, rem)
	if err != nil {
		return buf, rem, fmt.Errorf("marshaling commitments: %v", err)
	}
	buf, rem, err = surge.Marshal(opener.shareBuffers, buf, rem)
	if err != nil {
		return buf, rem, fmt.Errorf("marshaling share buffers: %v", err)
	}
	buf, rem, err = surge.Marshal(opener.decomBuffers, buf, rem)
	if err != nil {
		return buf, rem, fmt.Errorf("marshaling decommitment buffers: %v", err)
	}
	buf, rem, err = surge.Marshal(opener.secrets, buf, rem)
	if err != nil {
		return buf, rem, fmt.Errorf("marshaling secrets: %v", err)
	}
	buf, rem, err = surge.Marshal(opener.decommitments, buf, rem)
	if err != nil {
		return buf, rem, fmt.Errorf("marshaling decommitments: %v", err)
	}
	buf, rem, err = opener.checker.Marshal(buf, rem)
	if err != nil {
		return buf, rem, fmt.Errorf("marshaling checker: %v", err)
	}
	buf, rem, err = opener.reconstructor.Marshal(buf, rem)
	if err != nil {
		return buf, rem, fmt.Errorf("marshaling reconstructor: %v", err)
	}
	return buf, rem, nil
}

// Unmarshal implements the surge.Unmarshaler interface.
func (opener *Opener) Unmarshal(buf []byte, rem int) ([]byte, int, error) {
	buf, rem, err := surge.UnmarshalU32(&opener.batchSize, buf, rem)
	if err != nil {
		return buf, rem, fmt.Errorf("unmarshaling batchSize: %v", err)
	}
	buf, rem, err = surge.Unmarshal(&opener.commitments, buf, rem)
	if err != nil {
		return buf, rem, fmt.Errorf("unmarshaling commitment: %v", err)
	}
	buf, rem, err = surge.Unmarshal(&opener.shareBuffers, buf, rem)
	if err != nil {
		return buf, rem, fmt.Errorf("unmarshaling share buffers: %v", err)
	}
	buf, rem, err = surge.Unmarshal(&opener.decomBuffers, buf, rem)
	if err != nil {
		return buf, rem, fmt.Errorf("unmarshaling decommitment buffers: %v", err)
	}
	buf, rem, err = surge.Unmarshal(&opener.secrets, buf, rem)
	if err != nil {
		return buf, rem, fmt.Errorf("unmarshaling secrets: %v", err)
	}
	buf, rem, err = surge.Unmarshal(&opener.decommitments, buf, rem)
	if err != nil {
		return buf, rem, fmt.Errorf("unmarshaling decommitments: %v", err)
	}
	buf, rem, err = opener.checker.Unmarshal(buf, rem)
	if err != nil {
		return buf, rem, fmt.Errorf("unmarshaling checker: %v", err)
	}
	buf, rem, err = opener.reconstructor.Unmarshal(buf, rem)
	if err != nil {
		return buf, rem, fmt.Errorf("unmarshaling reconstructor: %v", err)
	}

	// Set the share buffer to have the correct capacity.
	for i := 0; i < int(opener.batchSize); i++ {
		shareBuffer := make(shamir.Shares, opener.reconstructor.N())
		decomBuffer := make(shamir.Shares, opener.reconstructor.N())
		n := copy(shareBuffer, opener.shareBuffers[i])
		if n < len(opener.shareBuffers[i]) {
			return buf, rem, fmt.Errorf(
				"invalid marshalled data: "+
					"%v shares in the share buffer but the reconstructor is instantiated for %v players",
				len(opener.shareBuffers[i]),
				opener.reconstructor.N(),
			)
		}
		n = copy(decomBuffer, opener.decomBuffers[i])
		if n < len(opener.decomBuffers[i]) {
			return buf, rem, fmt.Errorf(
				"invalid marshalled data: "+
					"%v shares in the decom buffer but the reconstructor is instantiated for %v players",
				len(opener.decomBuffers[i]),
				opener.reconstructor.N(),
			)
		}
		opener.shareBuffers[i] = shareBuffer[:n]
		opener.decomBuffers[i] = decomBuffer[:n]
	}

	return buf, rem, nil
}

// BatchSize returns the batch size of the opener machine
// That is, the number of secrets it can reconstruct in one successful execution
func (opener Opener) BatchSize() uint32 {
	return opener.batchSize
}

// K returns the reconstruction threshold for the current sharing instance.
func (opener Opener) K() int {
	return opener.commitments[0].Len()
}

// I returns the current number of valid shares that the opener has received.
func (opener Opener) I() int {
	return len(opener.shareBuffers[0])
}

// Secrets returns the reconstructed secrets for the current sharing instance,
// but only if the state is Done. Otherwise, it will return the secrets for the
// last sharing instance that made it to state Done. If the state machine has
// never been in the state Done, then the zero shares are returned.
func (opener Opener) Secrets() []secp256k1.Fn {
	return opener.secrets
}

// Decommitments returns the reconstructed decommitments for the current sharing instance,
// but only if the state is Done. Otherwise it will return the decommitments for
// the last sharing instance that made it to state Done. If the state machine has never
// been in the state Done, then the zero shares are returned.
func (opener Opener) Decommitments() []secp256k1.Fn {
	return opener.decommitments
}

// New returns a new instance of the Opener state machine for the given set of
// indices and the given Pedersen commitment system parameter. The state
// machine begins in the Uninitialised state.
func New(b uint32, indices []secp256k1.Fn, h secp256k1.Point) Opener {
	shareBuffers := make([]shamir.Shares, b)
	decomBuffers := make([]shamir.Shares, b)
	for i := 0; i < int(b); i++ {
		shareBuffers[i] = make(shamir.Shares, 0, len(indices))
		decomBuffers[i] = make(shamir.Shares, 0, len(indices))
	}

	commitments := make([]shamir.Commitment, b)

	secrets := make([]secp256k1.Fn, b)
	decommitments := make([]secp256k1.Fn, b)

	return Opener{
		batchSize:     b,
		commitments:   commitments,
		shareBuffers:  shareBuffers,
		decomBuffers:  decomBuffers,
		secrets:       secrets,
		decommitments: decommitments,
		checker:       shamir.NewVSSChecker(h),
		reconstructor: shamir.NewReconstructor(indices),
	}
}

// TransitionShares handles the state transition logic upon receiving a set of shares,
// and returns a ShareEvent that describes the outcome of the state transition.
// See the documentation for the different ShareEvent possiblities for their
// significance.
func (opener *Opener) TransitionShares(shares shamir.VerifiableShares) ShareEvent {
	// Do nothing when in the Uninitialised state. This can be checked by
	// seeing if k is zero, as Resetting the state machine can only be done if
	// k is greater than 0.
	if opener.K() <= 0 {
		return Ignored
	}

	// If the number of verifiable shares provided is not equal to the batch size
	// of the Opener machine, ignore them
	if len(shares) != int(opener.BatchSize()) {
		return Ignored
	}

	// For every share in the set of shares
	firstShare := shares[0].Share()
	firstIndex := firstShare.Index()
	for i, vshare := range shares {
		// Verify that each provided share has the same index
		share := vshare.Share()
		if !share.IndexEq(&firstIndex) {
			return InvalidShares
		}

		// Even if a single share is invalid, we mark the entire set of shares
		// to be invalid
		if !opener.checker.IsValid(&opener.commitments[i], &vshare) {
			return InvalidShares
		}
	}

	// Check if a share with this index is already in the buffer. Note that
	// since we have already checked that the share is valid, it is necessarily
	// the case that if the index is a duplicate, so too will be the entire
	// share.
	//
	// TODO: These temporary variables are gross, and there will probably be an
	// easier way if we were using shares that assumed the indices of the
	// shares were sequential starting from 1. Look into enforcing this.
	//
	// We already have checked that every share in the provided set of shares
	// has the same index.
	// So checking this constraint for just the first share buffer suffices
	var ind secp256k1.Fn
	innerShare := shares[0].Share()
	for _, s := range opener.shareBuffers[0] {
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
	//
	// Since we append shares to every buffer at the same time, at every point
	// in time the lenth of each share buffer will be the same.
	// Again, checking this constraint for just the first share buffer suffices
	if len(opener.shareBuffers[0]) == cap(opener.shareBuffers[0]) {
		return IndexOutOfRange
	}

	// At this stage we know that the shares are allowed to be added to the
	// respective buffers
	for i := 0; i < int(opener.BatchSize()); i++ {
		opener.shareBuffers[i] = append(opener.shareBuffers[i], shares[i].Share())
		opener.decomBuffers[i] = append(opener.decomBuffers[i], decommitmentShare(shares[i]))
	}

	// If we have just added the kth share, we can reconstruct.
	if len(opener.shareBuffers[0]) == opener.K() {
		var err error
		for i := 0; i < int(opener.BatchSize()); i++ {
			opener.secrets[i], err = opener.reconstructor.CheckedOpen(opener.shareBuffers[i], opener.K())

			// The previous checks should ensure that the error does not occur.
			//
			// TODO: It seems wrong that we did the checks here, but then many of
			// the same checks get run in CheckedOpen. Think about whether this is
			// OK.
			if err != nil {
				panic(err)
			}

			opener.decommitments[i], err = opener.reconstructor.CheckedOpen(opener.decomBuffers[i], opener.K())

			if err != nil {
				panic(err)
			}
		}

		return Done
	}

	// At this stage we have added the shares to the respective buffers
	// but we were not yet able to reconstruct the secrets
	return SharesAdded
}

// TransitionReset handles the state transition logic on receiving a Reset
// message, and returns a ResetEvent that describes the outcome of the state
// transition. See the documentation for the different ResetEvent possiblities
// for their significance.
func (opener *Opener) TransitionReset(commitments []shamir.Commitment) ResetEvent {
	// It is not valid for k to be less than 1
	if len(commitments) != int(opener.BatchSize()) {
		panic(fmt.Sprintf("length of commitments should be: %v, got: %v", opener.BatchSize(), len(commitments)))
	}

	// Make sure each commitment is for the same threshold
	// and that that threshold is greater than 0
	c0 := commitments[0]
	for _, c := range commitments {
		if c.Len() != c0.Len() {
			panic(fmt.Sprintf("k must be equal for all commitments"))
		}
	}
	if c0.Len() < 1 {
		panic(fmt.Sprintf("k must be greater than 0, got: %v", c0.Len()))
	}

	var ret ResetEvent
	if len(opener.shareBuffers[0]) < opener.K() {
		ret = Aborted
	} else {
		ret = Reset
	}

	for i := 0; i < int(opener.BatchSize()); i++ {
		opener.shareBuffers[i] = opener.shareBuffers[i][:0]
		opener.decomBuffers[i] = opener.decomBuffers[i][:0]
		opener.commitments[i].Set(commitments[i])
	}

	return ret
}

// Private functions
func decommitmentShare(vshare shamir.VerifiableShare) shamir.Share {
	share := vshare.Share()

	return shamir.NewShare(share.Index(), vshare.Decommitment())
}
