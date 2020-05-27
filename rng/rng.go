package rng

import (
	"fmt"
	"io"

	"github.com/renproject/secp256k1-go"
	"github.com/renproject/shamir"
	"github.com/renproject/shamir/curve"
	"github.com/renproject/surge"
)

// Fn represents a convenience type for Secp256k1N
type Fn = secp256k1.Secp256k1N

// RNGer describes the structure of the Random Number Generation machine
type RNGer struct {
	// state signifies the current state of the RNG state machine
	state State

	// index signifies the given RNG state machine's index
	index Fn

	// TODO: add this field while marshaling/unmarshaling
	// indices signifies the list of all such RNG state machines
	// participating in the RNG protocol
	indices []Fn

	// batchSize signifies the number of unbiased random numbers that
	// will be generated on successful execution of the RNG protocol
	batchSize uint32

	// threshold signifies the reconstruction threshold (k), or the
	// minimum number of valid openings required before a random number
	// can be reconstructed by polynomial interpolation
	threshold uint32

	// isReady signifies whether the RNG state machine has received and hence
	// computed its own shares, or not
	// CONSIDER: We may not need this, if we can check if using
	// ownSetsOfShares can already let us know if shares have been constructed or not
	isReady bool

	// TODO: add this field while marshaling/unmarshaling
	// ownSetsOfShares signifies the given RNG state machine's own shares
	ownSetsOfShares []shamir.VerifiableShares

	// TODO: add this field while marshaling/unmarshaling
	// ownSetsOfCommitments signifies the given RNG state machine's sets of
	// commitments for its respective sets of shares
	ownSetsOfCommitments [][]shamir.Commitment

	// TODO: add this field while marshaling/unmarshaling
	// openingsMap holds a map of verifiableShares by player index
	// It is updated whenever the given RNG state machine receives valid
	// openings from other players in the network
	// CONSIDER: rename to `openingsByIndex`?
	openingsMap map[Fn]shamir.VerifiableShares

	// TODO: add this field while marshaling/unmarshaling
	// openingsFrom represents a list of RNG machine indices that have
	// revealed/communicated their openings to this RNG machine
	openingsFrom []Fn

	// TODO: add this field while marshaling/unmarshaling
	// nOpenings signifies the number of valid openings this RNG machine has
	// CONSIDER: We actually don't need this, as simply `len(openingsFrom)`
	// can be used instead
	nOpenings uint32

	// checker is the VerifiableShares checker, capable of verifying the
	// consistency of a verifiable share with respect to its commitment
	checker shamir.VSSChecker

	// reconstruct is the Shares reconstructor, capable of reconstructing a
	// secret by polynomial interpolation given enough evaluations/shares
	reconstructor shamir.Reconstructor

	// randomNumbers holds the unbiased random numbers that the current
	// RNG state machine has reconstructed
	randomNumbers []Fn
}

// SizeHint implements the surge.SizeHinter interface
func (rnger RNGer) SizeHint() int {
	return rnger.state.SizeHint() +
		surge.SizeHint(rnger.index) +
		surge.SizeHint(rnger.batchSize) +
		surge.SizeHint(rnger.threshold) +
		surge.SizeHint(rnger.isReady)
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
	m, err = surge.Marshal(w, uint32(rnger.batchSize), m)
	if err != nil {
		return m, fmt.Errorf("marshaling batchSize: %v", err)
	}
	m, err = surge.Marshal(w, uint32(rnger.threshold), m)
	if err != nil {
		return m, fmt.Errorf("marshaling threshold: %v", err)
	}
	m, err = surge.Marshal(w, rnger.isReady, m)
	if err != nil {
		return m, fmt.Errorf("marshaling isReady: %v", err)
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
	m, err = surge.Unmarshal(r, &rnger.batchSize, m)
	if err != nil {
		return m, fmt.Errorf("unmarshaling batchSize: %v", err)
	}
	m, err = surge.Unmarshal(r, &rnger.threshold, m)
	if err != nil {
		return m, fmt.Errorf("unmarshaling threshold: %v", err)
	}
	m, err = surge.Unmarshal(r, &rnger.isReady, m)
	if err != nil {
		return m, fmt.Errorf("unmarshaling isReady: %v", err)
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
func New(
	ownIndex Fn,
	indices []Fn,
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

	// Declare variable to hold received openings and allocate necessary memory
	openingsMap := make(map[Fn]shamir.VerifiableShares)
	openingsFrom := make([]Fn, 0, k)
	for j := 0; j < len(indices); j++ {
		// Each verifiable share is for each of the `b` unbiased random numbers
		openingsMap[indices[j]] = make(shamir.VerifiableShares, b)
	}

	// Declare variable to hold random numbers and allocate memory
	randomNumbers := make([]Fn, b)

	return Initialised, RNGer{
		state:                state,
		index:                ownIndex,
		indices:              indices,
		batchSize:            b,
		threshold:            k,
		isReady:              false,
		ownSetsOfShares:      ownSetsOfShares,
		ownSetsOfCommitments: ownSetsOfCommitments,
		openingsMap:          openingsMap,
		openingsFrom:         openingsFrom,
		nOpenings:            0,
		checker:              shamir.NewVSSChecker(h),
		reconstructor:        shamir.NewReconstructor(indices),
		randomNumbers:        randomNumbers,
	}
}

// TransitionShares performs the state transition for the RNG state machine
// from `Init` to `WaitingOpen`, upon receiving `b` sets of verifiable shares
// and their respective commitments.
// The machine should locally compute its own shares from the received sets of shares
func (rnger *RNGer) TransitionShares(
	setsOfShares []shamir.VerifiableShares,
	setsOfCommitments [][]shamir.Commitment,
) TransitionEvent {
	// Ignore the shares if their number of sets does not match
	// the number of sets of commitments
	if len(setsOfShares) != len(setsOfCommitments) {
		return SharesIgnored
	}

	// Ignore the shares if their number of sets does not match
	// the batch size of the RNG state machine
	if len(setsOfShares) != int(rnger.BatchSize()) {
		return SharesIgnored
	}

	// Declare variable to hold field element for N
	n := secp256k1.NewSecp256k1N(uint64(rnger.N()))

	// For every set of verifiable shares
	for i, setOfShares := range setsOfShares {
		// Continue only if there are `k` number of shares in the set
		// Otherwise assign empty shares/commitments
		if len(setOfShares) == int(rnger.Threshold()) {
			// For j = 1 to N
			// compute r_{i,j}
			// append to ownSetsOfShares
			// append to ownSetsOfCommitments
			for j := 1; j <= int(rnger.N()); j++ {
				// Initialise the accumulators with the first values
				var accShare = setOfShares[0]
				var accCommitment shamir.Commitment
				accCommitment.Set(setsOfCommitments[i][0])
				var multiplier = secp256k1.OneSecp256k1N()

				// For all other shares and commitments
				for l := 1; l < len(setOfShares); l++ {
					// Initialise share
					var share = setOfShares[l]
					var commitment shamir.Commitment
					commitment.Set(setsOfCommitments[i][l])

					// Scale it by the multiplier
					share.Scale(&share, &multiplier)
					commitment.Scale(&commitment, &multiplier)

					// Add it to the accumulators
					accShare.Add(&accShare, &share)
					accCommitment.Add(&accCommitment, &commitment)

					// Scale the multiplier
					multiplier.Mul(&multiplier, &n)
				}

				// append the accumulated share/commitment
				rnger.ownSetsOfShares[i] = append(rnger.ownSetsOfShares[i], accShare)
				rnger.ownSetsOfCommitments[i] = append(rnger.ownSetsOfCommitments[i], accCommitment)

				// If j is the current machine's index, then populate the `openingsMap`
				if rnger.index.Uint64() == uint64(j) {
					rnger.openingsMap[rnger.index][i] = accShare
				}
			}
		} else {
			// Simply append empty slices
			rnger.ownSetsOfShares = append(rnger.ownSetsOfShares, shamir.VerifiableShares{})
			rnger.ownSetsOfCommitments = append(rnger.ownSetsOfCommitments, []shamir.Commitment{})
		}
	}

	// Transition the machine's state
	rnger.state = WaitingOpen

	// Mark that the machine has constructed its own shares
	rnger.isReady = true

	// Increment `nOpenings` now that we have one set of valid openings
	// Add own index to the list of indices from which we have received openings
	rnger.nOpenings = rnger.nOpenings + 1
	rnger.openingsFrom = append(rnger.openingsFrom, rnger.index)

	// If this was the kth valid opening
	if rnger.nOpenings == rnger.Threshold() {
		success, err := rnger.reconstruct()

		// Panic if we encountered an error in reconstruction
		if err != nil {
			panic(err)
		}

		// If successful, return appropriate event
		// and transition the machine's state to `Done`
		if success {
			rnger.state = Done
			return RNGsReconstructed
		}
	}

	return SharesConstructed
}

// HasConstructedShares returns `true` if the RNG machine has received its `b` sets
// of verifiable shares, and upon that constructed its shares. It returns false otherwise
func (rnger RNGer) HasConstructedShares() bool {
	return rnger.isReady
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
func (rnger *RNGer) TransitionOpen(
	fromIndex Fn,
	openings shamir.VerifiableShares,
	commitments []shamir.Commitment,
) TransitionEvent {
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

	// Verify that each opening is consistent with its respective commitment
	for i, opening := range openings {
		if !rnger.checker.IsValid(&commitments[i], &opening) {
			return OpeningsInconsistent
		}
	}

	// At this point we know that the openings are valid, so can be added
	rnger.openingsMap[fromIndex] = openings
	rnger.nOpenings = rnger.nOpenings + 1
	rnger.openingsFrom = append(rnger.openingsFrom, fromIndex)

	// If this was the kth valid opening
	if rnger.nOpenings == rnger.Threshold() {
		success, err := rnger.reconstruct()

		// Panic if we encountered an error in reconstruction
		if err != nil {
			panic(err)
		}

		// If successful, return appropriate event
		// and transition the machine's state to `Done`
		if success {
			rnger.state = Done
			return RNGsReconstructed
		}
	}

	return OpeningsAdded
}

// ReconstructedRandomNumbers returns the `b` random numbers that have been
// reconstructed by the RNG machine. This also means that the RNG machine is in
// the `Done` state. If it isn't this returns `nil`
func (rnger RNGer) ReconstructedRandomNumbers() []Fn {
	if rnger.State() == Done {
		return rnger.randomNumbers
	}

	return nil
}

// ReconstructedRandomNumber returns the `bId`th random number that has been
// reconstructed by the RNG machine. This also means that the RNG machine is in
// the `Done` state. If it isn't this returns empty instance of Fn
func (rnger RNGer) ReconstructedRandomNumber(bID uint32) Fn {
	if bID >= rnger.BatchSize() {
		return Fn{}
	}

	if rnger.State() == Done {
		return rnger.randomNumbers[bID]
	}

	return Fn{}
}

// reconstruct tries to reconstruct the `b` random numbers for RNG state machine.
// This returns true if it was successfully able to reconstruct the random numbers, false otherwise.
// On success, the RNG state machine's `randomNumbers` field should contain the `b`
// unbiased random numbers
// On failure, this returns the error encountered that can be handled by the calling function
func (rnger *RNGer) reconstruct() (bool, error) {
	// Over all of RNG machine's batch size
	for b := 0; b < int(rnger.BatchSize()); b++ {
		verifiableShares := make(shamir.VerifiableShares, rnger.Threshold())

		// Over all players that we have received valid openings from
		for i, fromIndex := range rnger.openingsFrom {
			verifiableShares[i] = rnger.openingsMap[fromIndex][b]
		}

		// Try to reconstruct an unbiased random number
		var err error
		rnger.randomNumbers[b], err = rnger.reconstructor.CheckedOpen(verifiableShares.Shares(), int(rnger.Threshold()))

		// If we encounter an error, return it
		if err != nil {
			return false, err
		}
	}

	return true, nil
}
