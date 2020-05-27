package rng

import (
	"fmt"
	"io"

	"github.com/renproject/secp256k1-go"
	"github.com/renproject/shamir"
	"github.com/renproject/surge"
)

// RNGer describes the structure of the Random Number Generation machine
type RNGer struct {
	state State
	index Fn

	// TODO: add this field while marshaling/unmarshaling
	indices []Fn

	batchSize uint32
	threshold uint32
	isReady   bool

	// TODO: add these fields while marshaling/unmarshaling
	ownSetsOfShares      []shamir.VerifiableShares
	ownSetsOfCommitments [][]shamir.Commitment

	// TODO: add these fields while marshaling/unmarshaling
	openingsMap map[Fn]shamir.VerifiableShares
	nOpenings   uint32
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
	m, err = surge.Marshal(w, secp256k1.Secp256k1N(rnger.index), m)
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
	m, err = surge.Unmarshal(r, (*secp256k1.Secp256k1N)(&rnger.index), m)
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
) (TransitionEvent, RNGer) {
	state := Init

	// Declare variable to hold RNG machine's computed shares and commitments
	// and allocate necessary memory
	ownSetsOfShares := make([]shamir.VerifiableShares, b)
	ownSetsOfCommitments := make([][]shamir.Commitment, b)
	for i := 0; i < int(b); i++ {
		ownSetsOfShares[i] = make(shamir.VerifiableShares, len(indices))
		ownSetsOfCommitments[i] = make([]shamir.Commitment, len(indices))
	}

	// Declare variable to hold received openings and allocate necessary memory
	openingsMap := make(map[Fn]shamir.VerifiableShares)
	for j := 0; j < len(indices); j++ {
		// Each verifiable share is for each of the `b` unbiased random numbers
		openingsMap[indices[j]] = make(shamir.VerifiableShares, b)
	}

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
		nOpenings:            0,
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
	rnger.nOpenings = rnger.nOpenings + 1

	return SharesConstructed
}

// HasConstructedShares returns `true` if the RNG machine has received its `b` sets
// of verifiable shares, and upon that constructed its shares. It returns false otherwise
func (rnger RNGer) HasConstructedShares() bool {
	return rnger.isReady
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
	index Fn,
	openings shamir.VerifiableShares,
	commitments []shamir.Commitment,
) TransitionEvent {
	return OpeningsIgnored
}

// ReconstructedRandomNumbers returns the `b` random numbers that have been
// reconstructed by the RNG machine. This also means that the RNG machine is in
// the `Done` state. If it isn't this returns `nil`
func (rnger RNGer) ReconstructedRandomNumbers() []Fn {
	return nil
}

// ReconstructedRandomNumber returns the `bId`th random number that has been
// reconstructed by the RNG machine. This also means that the RNG machine is in
// the `Done` state. If it isn't this returns empty instance of Fn
func (rnger RNGer) ReconstructedRandomNumber(bID uint32) Fn {
	return Fn{}
}
