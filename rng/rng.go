package rng

import (
	"fmt"
	"io"

	"github.com/renproject/secp256k1-go"
	"github.com/renproject/shamir"
	"github.com/renproject/shamir/curve"
	util "github.com/renproject/shamir/util"
	"github.com/renproject/surge"

	"github.com/renproject/mpc/open"
)

// RNGer describes the structure of the Random Number Generation machine
type RNGer struct {
	// state signifies the current state of the RNG state machine
	state State

	// index signifies the given RNG state machine's index
	index open.Fn

	// TODO: add this field while marshaling/unmarshaling
	// indices signifies the list of all such RNG state machines
	// participating in the RNG protocol
	indices []open.Fn

	// batchSize signifies the number of unbiased random numbers that
	// will be generated on successful execution of the RNG protocol
	batchSize uint32

	// threshold signifies the reconstruction threshold (k), or the
	// minimum number of valid openings required before a random number
	// can be reconstructed by polynomial interpolation
	threshold uint32

	// opener is the Opener state machine operating within the RNG state machine
	// As the RNG machine receives openings from other players, the opener
	// state machine also transitions, to eventually reconstruct the batchSize
	// number of secrets
	opener open.Opener

	// ownSetsOfShares signifies the given RNG state machine's own shares
	ownSetsOfShares []shamir.VerifiableShares

	// ownSetsOfCommitments signifies the given RNG state machine's sets of
	// commitments for its respective sets of shares
	ownSetsOfCommitments [][]shamir.Commitment
}

// SizeHint implements the surge.SizeHinter interface
func (rnger RNGer) SizeHint() int {
	return rnger.state.SizeHint() +
		rnger.index.SizeHint() +
		surge.SizeHint(rnger.indices) +
		surge.SizeHint(rnger.batchSize) +
		surge.SizeHint(rnger.threshold) +
		rnger.opener.SizeHint() +
		surge.SizeHint(rnger.ownSetsOfShares) +
		surge.SizeHint(rnger.ownSetsOfCommitments)
}

// Marshal implements the surge.Marshaler interface
func (rnger RNGer) Marshal(w io.Writer, m int) (int, error) {
	m, err := rnger.state.Marshal(w, m)
	if err != nil {
		return m, fmt.Errorf("marshaling state: %v", err)
	}
	m, err = rnger.index.Marshal(w, m)
	if err != nil {
		return m, fmt.Errorf("marshaling index: %v", err)
	}
	m, err = surge.Marshal(w, rnger.indices, m)
	if err != nil {
		return m, fmt.Errorf("marshaling indices: %v", err)
	}
	m, err = surge.Marshal(w, uint32(rnger.batchSize), m)
	if err != nil {
		return m, fmt.Errorf("marshaling batchSize: %v", err)
	}
	m, err = surge.Marshal(w, uint32(rnger.threshold), m)
	if err != nil {
		return m, fmt.Errorf("marshaling threshold: %v", err)
	}
	m, err = rnger.opener.Marshal(w, m)
	if err != nil {
		return m, fmt.Errorf("marshaling opener: %v", err)
	}
	m, err = surge.Marshal(w, rnger.ownSetsOfShares, m)
	if err != nil {
		return m, fmt.Errorf("marshaling ownSetsOfShares: %v", err)
	}
	m, err = surge.Marshal(w, rnger.ownSetsOfCommitments, m)
	if err != nil {
		return m, fmt.Errorf("marshaling ownSetsOfCommitments: %v", err)
	}
	return m, nil
}

// Unmarshal implements the surge.Unmarshaler interface
func (rnger *RNGer) Unmarshal(r io.Reader, m int) (int, error) {
	m, err := rnger.state.Unmarshal(r, m)
	if err != nil {
		return m, fmt.Errorf("unmarshaling state: %v", err)
	}
	m, err = rnger.index.Unmarshal(r, m)
	if err != nil {
		return m, fmt.Errorf("unmarshaling index: %v", err)
	}
	m, err = rnger.unmarshalIndices(r, m)
	if err != nil {
		return m, fmt.Errorf("unmarshaling indices: %v", err)
	}
	m, err = surge.Unmarshal(r, &rnger.batchSize, m)
	if err != nil {
		return m, fmt.Errorf("unmarshaling batchSize: %v", err)
	}
	m, err = surge.Unmarshal(r, &rnger.threshold, m)
	if err != nil {
		return m, fmt.Errorf("unmarshaling threshold: %v", err)
	}
	m, err = rnger.opener.Unmarshal(r, m)
	if err != nil {
		return m, fmt.Errorf("unmarshaling opener: %v", err)
	}
	m, err = rnger.unmarshalSetsOfShares(r, m)
	if err != nil {
		return m, fmt.Errorf("unmarshaling ownSetsOfShares: %v", err)
	}
	m, err = rnger.unmarshalSetsOfCommitments(r, m)
	if err != nil {
		return m, fmt.Errorf("unmarshaling ownSetsOfCommitments: %v", err)
	}
	return m, nil
}

// State returns the current state of the RNGer state machine
func (rnger RNGer) State() State {
	return rnger.state
}

// N returns the number of machine replicas participating in the RNG protocol
func (rnger RNGer) N() int {
	return len(rnger.indices)
}

// BatchSize returns the batch size of the RNGer state machine.
// This also denotes the number of random numbers that can possibly
// be generated after a successful execution of all state transitions
func (rnger RNGer) BatchSize() uint32 {
	return rnger.batchSize
}

// Threshold returns the reconstruction threshold for every set of shares.
// This is the same as `k`, or the minimum number of openings required
// to be able to reconstruct the random numbers
func (rnger RNGer) Threshold() uint32 {
	return rnger.threshold
}

// New creates a new RNG state machine for a given batch size
// ownIndex is the current machine's index
// indices is the set of player indices
// n is the number of players participating in the RNG protocol
// b is the number of random numbers generated in one invocation of RNG protocol
// k is the reconstruction threshold for every random number
// h is the Pedersen Commitment Parameter, a point on elliptic curve
func New(
	ownIndex open.Fn,
	indices []open.Fn,
	b, k uint32,
	h curve.Point,
) (TransitionEvent, RNGer) {
	state := Init

	// Declare variable to hold RNG machine's computed shares and commitments
	// and allocate necessary memory
	ownSetsOfShares := make([]shamir.VerifiableShares, b)
	ownSetsOfCommitments := make([][]shamir.Commitment, b)
	for i := 0; i < int(b); i++ {
		ownSetsOfShares[i] = make(shamir.VerifiableShares, 0, len(indices))
		ownSetsOfCommitments[i] = make([]shamir.Commitment, 0, len(indices))
	}

	// Create an instance of the Opener state machine
	// within the RNG state machine
	opener := open.New(b, indices, h)

	return Initialised, RNGer{
		state:                state,
		index:                ownIndex,
		indices:              indices,
		batchSize:            b,
		threshold:            k,
		opener:               opener,
		ownSetsOfShares:      ownSetsOfShares,
		ownSetsOfCommitments: ownSetsOfCommitments,
	}
}

// TransitionShares performs the state transition for the RNG state machine
// from `Init` to `WaitingOpen`, upon receiving `b` sets of verifiable shares
// and their respective commitments.
// The machine should locally compute its own shares from the received sets of shares
//
// setsOfShares are the b sets of verifiable shares from the player's BRNG outputs
// 	- We make no assumptions of correctness for the sets of shares
//	- MUST be of length equal to the batch size to be valid
//	- For invalid sets of shares, a nil slice []shamir.VerifiableShares{} MUST be supplied
//	- If the above checks are met, we assume that every set of verifiable shares is valid
//		- We assume it has a length equal to the RNG's reconstruction threshold
// setsOfCommitments are the b sets of commitments from the player's BRNG outputs
//	- We assume that the commitments are correct and valid (even if the shares may not be)
//	- MUST be of length equal to the batch size
//	- In case the sets of shares are invalid, we simply proceed with locally computing
//		the Open commitments, since we assume the supplied sets of commitments are correct
func (rnger *RNGer) TransitionShares(
	setsOfShares []shamir.VerifiableShares,
	setsOfCommitments [][]shamir.Commitment,
) TransitionEvent {
	// Simply ignore if the RNG state machine is not in the `Init` state
	if rnger.State() != Init {
		return SharesIgnored
	}

	// Since this refutes our assumption that the sets of commitments
	// are valid and correct
	if len(setsOfCommitments) != int(rnger.BatchSize()) {
		panic("Unexpected invalid sets of commitments to RNG")
	}

	// Boolean to keep a track of whether shares computation should be ignored or not
	// This is set to true if the sets of shares are invalid in any way
	ignoreShares := false

	// Ignore the shares if their number of sets does not match
	// the number of sets of commitments
	if len(setsOfShares) != len(setsOfCommitments) {
		ignoreShares = true
	}

	// Ignore the shares if their number of sets does not match
	// the batch size of the RNG state machine
	if len(setsOfShares) != int(rnger.BatchSize()) {
		ignoreShares = true
	}

	// Declare variable to hold field element for N
	locallyComputedCommitments := make([]shamir.Commitment, rnger.BatchSize())
	locallyComputedShares := make(shamir.VerifiableShares, rnger.BatchSize())

	// For every set of verifiable shares
	for i, setOfCommitments := range setsOfCommitments {
		// Since this refutes our assumption that if the sets of shares are of appropriate
		// length, then every set of shares is valid and correct
		if !ignoreShares && len(setsOfShares[i]) != int(rnger.Threshold()) {
			panic("Unexpected invalid set of shares")
		}

		// For j = 1 to N
		// compute r_{i,j}
		// append to ownSetsOfShares
		// append to ownSetsOfCommitments
		for j := 1; j <= int(rnger.N()); j++ {
			J := secp256k1.NewSecp256k1N(uint64(j))

			// Initialise the accumulators with the first values
			var accCommitment shamir.Commitment
			accCommitment.Set(setOfCommitments[0])
			var multiplier = secp256k1.OneSecp256k1N()

			var accShare shamir.VerifiableShare
			if !ignoreShares {
				accShare = setsOfShares[i][0]
			}

			// For all other shares and commitments
			for l := 1; l < len(setOfCommitments); l++ {
				// Scale the multiplier
				multiplier.Mul(&multiplier, &J)

				// Initialise
				// Scale by the multiplier
				// Add to the accumulator
				var commitment shamir.Commitment
				commitment.Set(setOfCommitments[l])
				commitment.Scale(&commitment, &multiplier)
				accCommitment.Add(&accCommitment, &commitment)

				// If we have received valid sets of shares
				// also do local computations for the shares
				if !ignoreShares {
					var share = setsOfShares[i][l]
					share.Scale(&share, &multiplier)
					accShare.Add(&accShare, &share)
				}
			}

			// append the accumulated values
			rnger.ownSetsOfCommitments[i] = append(rnger.ownSetsOfCommitments[i], accCommitment)
			if !ignoreShares {
				rnger.ownSetsOfShares[i] = append(rnger.ownSetsOfShares[i], accShare)
			} else {
				rnger.ownSetsOfShares[i] = shamir.VerifiableShares{}
			}

			// If j is the current machine's index, then populate the local shares
			// which will be later supplied to the Opener machine
			if rnger.index.Uint64() == uint64(j) {
				locallyComputedCommitments[i].Set(accCommitment)
				if !ignoreShares {
					locallyComputedShares[i] = accShare
				}
			}
		}
	}

	// Reset the Opener machine with the computed commitments
	resetEvent := rnger.opener.TransitionReset(locallyComputedCommitments)
	if resetEvent != open.Reset {
		panic(fmt.Sprintf("Could not set commitments in Opener: %v", locallyComputedCommitments))
	}

	// Transition the machine's state
	rnger.state = WaitingOpen

	// Supply the locally computed shares to the opener
	// This will only be a special case when the reconstruction threshold k
	// is equal to one
	if !ignoreShares {
		event := rnger.opener.TransitionShares(locallyComputedShares)
		if event == open.Done {
			rnger.state = Done
			return RNGsReconstructed
		}
	}

	if ignoreShares {
		return CommitmentsConstructed
	}

	return SharesConstructed
}

// HasConstructedShares returns `true` if the RNG machine has received its `b` sets
// of verifiable shares, and upon that constructed its shares. It returns false otherwise
func (rnger RNGer) HasConstructedShares() bool {
	return rnger.state != Init
}

// ConstructedSetsOfShares returns the RNG state machine's all constructed sets of shares
func (rnger RNGer) ConstructedSetsOfShares() ([]shamir.VerifiableShares, [][]shamir.Commitment) {
	return rnger.ownSetsOfShares, rnger.ownSetsOfCommitments
}

// ConstructedSetOfShares returns the RNG state machine's bID'th constructed set of shares
func (rnger RNGer) ConstructedSetOfShares(bID uint32) (shamir.VerifiableShares, []shamir.Commitment) {
	if bID >= rnger.BatchSize() {
		return nil, nil
	}

	return rnger.ownSetsOfShares[bID], rnger.ownSetsOfCommitments[bID]
}

// DirectedOpenings returns the openings from the RNG state machine to other
// RNG state machines
func (rnger RNGer) DirectedOpenings(to open.Fn) (shamir.VerifiableShares, []shamir.Commitment) {
	// If the RNG state machine is still in the Init state
	// ignore this call and return nil
	if rnger.state == Init {
		return nil, nil
	}

	openings := make(shamir.VerifiableShares, 0, rnger.BatchSize())
	commitments := make([]shamir.Commitment, 0, rnger.BatchSize())

	toIndex := int(to.Uint64())
	for i := 0; i < int(rnger.BatchSize()); i++ {
		// NOTE: This assumes sequential indices for players
		// Hence openings for player `toIndex` would have been appended at array index `toIndex - 1`
		// CONSIDER: Is this really the best way of achieving this?
		openings = append(openings, rnger.ownSetsOfShares[i][toIndex-1])
		commitments = append(commitments, rnger.ownSetsOfCommitments[i][toIndex-1])
	}

	return openings, commitments
}

// TransitionOpen performs the state transition for the RNG state machine upon
// receiving directed openings of shares from other players.
//
// The state transition on calling TransitionOpen is described below:
// 1. RNG machine in state `Init` transitions to `WaitingOpen`
// 2. RNG machine in state `WaitingOpen` continues to be in state `WaitingOpen`
//    if the machine has less than `k` opened shares, including the one supplied here.
// 3. RNG machine in state `WaitingOpen` transitions to `Done` if the machine
//    now has `k` opened shares, including the one supplied here.
//
// Since the RNG machine is capable of generating `b` random numbers, we expect
// other players to supply `b` directed openings of their shares too.
//
// fromIndex is the index of the RNG machine from which we are receiving directed openings
//	- MUST be a part of the set of indices in RNG machine
//	- Will be ignored if valid openings are already supplied by this index
// openings are the directed openings
//	- MUST be of length b (batch size)
//	- Will be ignored if they're not consistent with their respective commitments
// commitments are their respective commitments
//	- MUST be of length b (batch size)
//	- MUST be the same as the RNG's opener's commitments (verified within RNG's opener)
func (rnger *RNGer) TransitionOpen(
	fromIndex open.Fn,
	openings shamir.VerifiableShares,
	commitments []shamir.Commitment,
) TransitionEvent {
	// Simply ignore if the RNG state machine is not in the `WaitingOpen` state
	if rnger.State() != WaitingOpen {
		return OpeningsIgnored
	}

	// Ignore if the number of openings supplied is not equal to the number commitments
	if len(openings) != len(commitments) {
		return OpeningsIgnored
	}

	// Ignore if the number of openings/commitments supplied is not equal
	// to the RNG machine's batch size
	if len(openings) != int(rnger.BatchSize()) {
		return OpeningsIgnored
	}

	// If the fromIndex cannot be found in the set of valid machine indices
	// ignore the openings
	validIndex := false
	for _, index := range rnger.indices {
		if index.Eq(&fromIndex) {
			validIndex = true
		}
	}
	if validIndex == false {
		return OpeningsIgnored
	}

	// Pass these openings to the Opener state machine now that we have already
	// received valid commitments from BRNG outputs
	event := rnger.opener.TransitionShares(openings)

	// If the opener has received enough shares to be able to reconstruct the secrets
	if event == open.Done {
		rnger.state = Done
		return RNGsReconstructed
	}

	// If the opener has added the shares correctly (they are valid)
	if event == open.SharesAdded {
		return OpeningsAdded
	}

	// CONSIDER: This may be several different scenarios, should we handle separately?
	return OpeningsIgnored
}

// ReconstructedRandomNumbers returns the `b` random numbers that have been
// reconstructed by the RNG machine. This also means that the RNG machine is in
// the `Done` state. If it isn't this returns `nil`
func (rnger RNGer) ReconstructedRandomNumbers() []open.Fn {
	if rnger.State() == Done {
		return rnger.opener.Secrets()
	}

	return nil
}

// Reset transitions the RNG state machine back to the Init state
// Note that the Opener state machine is not reset at this point in time
// It is reset when the RNG receives its BRNG outputs again
func (rnger *RNGer) Reset() TransitionEvent {
	for i := 0; i < int(rnger.BatchSize()); i++ {
		rnger.ownSetsOfShares[i] = rnger.ownSetsOfShares[i][:0]
		rnger.ownSetsOfCommitments[i] = rnger.ownSetsOfCommitments[i][:0]
	}
	rnger.state = Init

	return Reset
}

// Private functions
func (rnger *RNGer) unmarshalIndices(r io.Reader, m int) (int, error) {
	var l uint32
	m, err := util.UnmarshalSliceLen32(&l, shamir.FnSizeBytes, r, m)
	if err != nil {
		return m, err
	}

	rnger.indices = (rnger.indices)[:0]
	for i := uint32(0); i < l; i++ {
		rnger.indices = append(rnger.indices, open.Fn{})
		m, err = rnger.indices[i].Unmarshal(r, m)
		if err != nil {
			return m, err
		}
	}

	return m, nil
}

func (rnger *RNGer) unmarshalSetsOfShares(r io.Reader, m int) (int, error) {
	var l uint32
	m, err := util.UnmarshalSliceLen32(&l, shamir.FnSizeBytes, r, m)
	if err != nil {
		return m, err
	}

	rnger.ownSetsOfShares = (rnger.ownSetsOfShares)[:0]
	for i := uint32(0); i < l; i++ {
		rnger.ownSetsOfShares = append(rnger.ownSetsOfShares, shamir.VerifiableShares{})
		m, err = rnger.ownSetsOfShares[i].Unmarshal(r, m)
		if err != nil {
			return m, err
		}
	}

	return m, nil
}

func (rnger *RNGer) unmarshalSetsOfCommitments(r io.Reader, m int) (int, error) {
	var l uint32
	m, err := util.UnmarshalSliceLen32(&l, shamir.FnSizeBytes, r, m)
	if err != nil {
		return m, err
	}

	rnger.ownSetsOfCommitments = (rnger.ownSetsOfCommitments)[:0]
	for i := uint32(0); i < l; i++ {
		rnger.ownSetsOfCommitments = append(rnger.ownSetsOfCommitments, []shamir.Commitment{})
		m, err = rnger.unmarshalCommitments(r, m, i)
		if err != nil {
			return m, err
		}
	}

	return m, nil
}

func (rnger *RNGer) unmarshalCommitments(r io.Reader, m int, i uint32) (int, error) {
	var l uint32
	m, err := util.UnmarshalSliceLen32(&l, shamir.FnSizeBytes, r, m)
	if err != nil {
		return m, err
	}

	rnger.ownSetsOfCommitments[i] = rnger.ownSetsOfCommitments[i][:0]
	for j := uint32(0); j < l; j++ {
		rnger.ownSetsOfCommitments[i] = append(rnger.ownSetsOfCommitments[i], shamir.Commitment{})
		m, err = rnger.ownSetsOfCommitments[i][j].Unmarshal(r, m)
		if err != nil {
			return m, err
		}
	}

	return m, nil
}
