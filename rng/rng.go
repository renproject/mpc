package rng

import (
	"fmt"

	"github.com/renproject/secp256k1"
	"github.com/renproject/shamir"
	"github.com/renproject/surge"

	"github.com/renproject/mpc/open"
	"github.com/renproject/mpc/rng/compute"
)

// RNGer describes the structure of the Random Number Generation machine. The
// machine can be used for an arbitrary number of invocations of RNG, however
// each instance is specific to the set of machine indices it was constructed
// with, as well as the batch size, reconstruction threshold and Pedersen
// Commitment Scheme Parameter.
//
// RNGer can exist in one of the following states:
// - Init
// - WaitingOpen
// - Done
//
// A new instance of RNGer can be created by calling:
// - New(index, indices, b, k, h)
//
// State transitions can be triggered by three different functions:
// - TransitionShares(setsOfShares, setsOfCommitments)
// - TransitionOpen(openings)
// - Reset
//
// Every state transition function returns a transition event, depending on how
// the inputs were processed. The various state transitions are as follows:
// - state(Init)
//	 - TransitionShares
//			|
//			|__ Invalid Shares --> event(CommitmentsConstructed) --> state(WaitingOpen)
//			|__ Valid Shares   --> event(SharesConstructed)      --> state(WaitingOpen)
//	 - TransitionOpen
//			|
//			|__ Invalid/Valid Openings --> event(OpeningsIgnored) --> state(Init)
//	 - Reset
//			|
//			|__ Any --> event(Reset) --> state(Init)
//
// - state(WaitingOpen)
//	 - TransitionShares
//			|
//			|__ Invalid/Valid Shares --> event(SharesIgnored) --> state(WaitingOpen)
//	 - TransitionOpen
//			|
//			|__ Invalid Openings     --> event(OpeningsIgnored)      --> state(WaitingOpen)
//			|__ Valid Openings       --> event(OpeningsAdded)        --> state(WaitingOpen)
//			|__ Valid Openings (kth) --> event(RNGsReconstructed)    --> state(Done)
//	 - Reset
//			|
//			|__ Any --> event(Reset) --> state(Init)
type RNGer struct {
	// state signifies the current state of the RNG state machine.
	state State

	// index signifies the given RNG state machine's index.
	index secp256k1.Fn

	// indices signifies the list of all such RNG state machines participating
	// in the RNG protocol.
	indices []secp256k1.Fn

	// batchSize signifies the number of unbiased random numbers that will be
	// generated on successful execution of the RNG protocol.
	batchSize uint32

	// threshold signifies the reconstruction threshold (k), or the minimum
	// number of valid openings required before a random number can be
	// reconstructed by polynomial interpolation.
	threshold uint32

	// opener is the Opener state machine operating within the RNG state
	// machine As the RNG machine receives openings from other players, the
	// opener state machine also transitions, to eventually reconstruct the
	// batchSize number of secrets.
	opener open.Opener

	// commitments signify the set of commitments for the batch of unbiased
	// random numbers to be reconstructed in RNG.
	commitments []shamir.Commitment

	// openingsMap holds a map of directed openings towards a player.
	openingsMap map[secp256k1.Fn]shamir.VerifiableShares

	secrets, decommitments []secp256k1.Fn
}

// SizeHint implements the surge.SizeHinter interface.
func (rnger RNGer) SizeHint() int {
	return rnger.state.SizeHint() +
		rnger.index.SizeHint() +
		surge.SizeHint(rnger.indices) +
		surge.SizeHint(rnger.batchSize) +
		surge.SizeHint(rnger.threshold) +
		rnger.opener.SizeHint() +
		surge.SizeHint(rnger.commitments) +
		surge.SizeHint(rnger.openingsMap) +
		surge.SizeHint(rnger.secrets) +
		surge.SizeHint(rnger.decommitments)
}

// Marshal implements the surge.Marshaler interface.
func (rnger RNGer) Marshal(buf []byte, rem int) ([]byte, int, error) {
	buf, rem, err := rnger.state.Marshal(buf, rem)
	if err != nil {
		return buf, rem, fmt.Errorf("marshaling state: %v", err)
	}
	buf, rem, err = rnger.index.Marshal(buf, rem)
	if err != nil {
		return buf, rem, fmt.Errorf("marshaling index: %v", err)
	}
	buf, rem, err = surge.Marshal(rnger.indices, buf, rem)
	if err != nil {
		return buf, rem, fmt.Errorf("marshaling indices: %v", err)
	}
	buf, rem, err = surge.MarshalU32(uint32(rnger.batchSize), buf, rem)
	if err != nil {
		return buf, rem, fmt.Errorf("marshaling batchSize: %v", err)
	}
	buf, rem, err = surge.MarshalU32(uint32(rnger.threshold), buf, rem)
	if err != nil {
		return buf, rem, fmt.Errorf("marshaling threshold: %v", err)
	}
	buf, rem, err = rnger.opener.Marshal(buf, rem)
	if err != nil {
		return buf, rem, fmt.Errorf("marshaling opener: %v", err)
	}
	buf, rem, err = surge.Marshal(rnger.commitments, buf, rem)
	if err != nil {
		return buf, rem, fmt.Errorf("marshaling commitments: %v", err)
	}
	buf, rem, err = surge.Marshal(rnger.openingsMap, buf, rem)
	if err != nil {
		return buf, rem, fmt.Errorf("marshaling openingsMap: %v", err)
	}
	buf, rem, err = surge.Marshal(rnger.secrets, buf, rem)
	if err != nil {
		return buf, rem, fmt.Errorf("marshaling secrets: %v", err)
	}
	buf, rem, err = surge.Marshal(rnger.decommitments, buf, rem)
	if err != nil {
		return buf, rem, fmt.Errorf("marshaling decommitments: %v", err)
	}
	return buf, rem, nil
}

// Unmarshal implements the surge.Unmarshaler interface.
func (rnger *RNGer) Unmarshal(buf []byte, rem int) ([]byte, int, error) {
	buf, rem, err := rnger.state.Unmarshal(buf, rem)
	if err != nil {
		return buf, rem, fmt.Errorf("unmarshaling state: %v", err)
	}
	buf, rem, err = rnger.index.Unmarshal(buf, rem)
	if err != nil {
		return buf, rem, fmt.Errorf("unmarshaling index: %v", err)
	}
	buf, rem, err = surge.Unmarshal(&rnger.indices, buf, rem)
	if err != nil {
		return buf, rem, fmt.Errorf("unmarshaling indices: %v", err)
	}
	buf, rem, err = surge.UnmarshalU32(&rnger.batchSize, buf, rem)
	if err != nil {
		return buf, rem, fmt.Errorf("unmarshaling batchSize: %v", err)
	}
	buf, rem, err = surge.UnmarshalU32(&rnger.threshold, buf, rem)
	if err != nil {
		return buf, rem, fmt.Errorf("unmarshaling threshold: %v", err)
	}
	buf, rem, err = rnger.opener.Unmarshal(buf, rem)
	if err != nil {
		return buf, rem, fmt.Errorf("unmarshaling opener: %v", err)
	}
	buf, rem, err = surge.Unmarshal(&rnger.commitments, buf, rem)
	if err != nil {
		return buf, rem, fmt.Errorf("unmarshaling commitments: %v", err)
	}
	buf, rem, err = surge.Unmarshal(&rnger.openingsMap, buf, rem)
	if err != nil {
		return buf, rem, fmt.Errorf("unmarshaling openingsMap: %v", err)
	}
	buf, rem, err = surge.Unmarshal(&rnger.secrets, buf, rem)
	if err != nil {
		return buf, rem, fmt.Errorf("unmarshaling secrets: %v", err)
	}
	buf, rem, err = surge.Unmarshal(&rnger.decommitments, buf, rem)
	if err != nil {
		return buf, rem, fmt.Errorf("unmarshaling decommitments: %v", err)
	}
	return buf, rem, nil
}

// State returns the current state of the RNGer state machine.
func (rnger RNGer) State() State {
	return rnger.state
}

// N returns the number of machine replicas participating in the RNG protocol.
func (rnger RNGer) N() int {
	return len(rnger.indices)
}

// BatchSize returns the batch size of the RNGer state machine.  This also
// denotes the number of random numbers that can possibly be generated after a
// successful execution of all state transitions.
func (rnger RNGer) BatchSize() uint32 {
	return rnger.batchSize
}

// Threshold returns the reconstruction threshold for every set of shares.
// This is the same as `k`, or the minimum number of openings required to be
// able to reconstruct the random numbers.
func (rnger RNGer) Threshold() uint32 {
	return rnger.threshold
}

// Commitments returns the shamir commitments to the batch of unbiased random
// numbers.
func (rnger RNGer) Commitments() []shamir.Commitment {
	commitmentsCopy := make([]shamir.Commitment, len(rnger.commitments))
	for i := range rnger.commitments {
		commitmentsCopy[i].Set(rnger.commitments[i])
	}
	return commitmentsCopy
}

// Generate implements the quick.Generator interface.
/*
func (rnger RNGer) Generate(_ *rand.Rand, _ int) reflect.Value {
	indices := shamirutil.RandomIndices(rand.Intn(20) + 1)
	ownIndex := indices[rand.Intn(len(indices))]
	b := uint32(rand.Intn(10))
	k := uint32(rand.Intn(20))
	h := secp256k1.RandomPoint()
	_, v := New(ownIndex, indices, b, k, h)
	return reflect.ValueOf(v)
}
*/

// New creates a new RNG state machine for a given batch size.
// - Inputs
// 	 - ownIndex is the current machine's index
// 	 - indices is the set of player indices
// 	 - b is the number of random numbers generated in one invocation of the protocol
// 	 - k is the reconstruction threshold for every random number
// 	 - h is the Pedersen Commitment Parameter, a point on elliptic curve
//
// - Returns
//	 - TransitionEvent is the `Initialised` event emitted on creation
//	 - RNGer the newly created RNGer instance
func New(
	ownIndex secp256k1.Fn,
	indices []secp256k1.Fn,
	b, k uint32,
	h secp256k1.Point,
	setsOfShares []shamir.VerifiableShares,
	setsOfCommitments [][]shamir.Commitment,
	isZero bool,
) (TransitionEvent, RNGer) {
	state := Init

	// Declare variable to hold RNG machine's computed shares and commitments
	// and allocate necessary memory.
	commitments := make([]shamir.Commitment, b)
	for i := range commitments {
		commitments[i] = shamir.Commitment{}
	}
	openingsMap := make(map[secp256k1.Fn]shamir.VerifiableShares)
	for _, index := range indices {
		openingsMap[index] = make(shamir.VerifiableShares, 0, b)
	}

	// Create an instance of the Opener state machine within the RNG state
	// machine.
	// FIXME: Compute the commitments here.
	commitmentBatch := []shamir.Commitment{shamir.Commitment{secp256k1.Point{}}}
	opener := open.New(commitmentBatch, indices, h)

	rnger := RNGer{
		state:         state,
		index:         ownIndex,
		indices:       indices,
		batchSize:     b,
		threshold:     k,
		opener:        opener,
		commitments:   commitments,
		openingsMap:   openingsMap,
		secrets:       []secp256k1.Fn{},
		decommitments: []secp256k1.Fn{},
	}

	event := rnger.transitionShares(setsOfShares, setsOfCommitments, isZero, h)

	return event, rnger
}

// TransitionShares performs the state transition for the RNG state machine
// from `Init` to `WaitingOpen`, upon receiving `b` sets of verifiable shares
// and their respective commitments. The machine should locally compute its
// own shares from the received sets of shares.
//
// - Inputs
//   - setsOfShares are the b sets of verifiable shares from the player's BRNG
//   	outputs
//  	 - MUST be of length equal to the batch size to be valid
//  	 - For invalid sets of shares, a nil slice []shamir.VerifiableShares{}
//  	 	MUST be supplied
//  	 - If the above checks are met, we assume that every set of verifiable
//  	 	shares is valid
//  		 - We assume it has a length equal to the RNG's reconstruction
//  		 	threshold
//		 - For sets of shares of length not equal to the batch size, we ignore
//		 	those shares while simply computing the commitments
//   - setsOfCommitments are the b sets of commitments from the player's BRNG
//   	outputs
//  	 - We assume that the commitments are correct and valid (even if the
//  	 	shares may not be)
//  	 - MUST be of length equal to the batch size
//  	 - In case the sets of shares are invalid, we simply proceed with
//  	 	locally computing the Open commitments, since we assume the
//  	 	supplied sets of commitments are correct
//	 - isZero is a boolean indicating whether this is a Random Zero Generator or not
//
// - Returns
//   - TransitionEvent
//		 - SharesIgnored when the RNGer is not in `Init` state
//		 - CommitmentsConstructed when the sets of shares were invalid
//		 - SharesConstructed when the sets of shares were valid
//		 - RNGsReconstructed when the RNGer was able to reconstruct the random
//		 	shares (k = 1)
func (rnger *RNGer) transitionShares(
	setsOfShares []shamir.VerifiableShares,
	setsOfCommitments [][]shamir.Commitment,
	isZero bool,
	h secp256k1.Point,
) TransitionEvent {
	// Simply ignore if the RNG state machine is not in the `Init` state.
	if rnger.state != Init {
		return SharesIgnored
	}

	// The required batch size for the BRNG outputs is k for RNG and k-1 for RZG
	var requiredBrngBatchSize int
	if isZero {
		requiredBrngBatchSize = int(rnger.threshold - 1)
	} else {
		requiredBrngBatchSize = int(rnger.threshold)
	}

	//
	// Commitments validity
	//

	if len(setsOfCommitments) != int(rnger.batchSize) {
		panic("invalid sets of commitments")
	}

	for _, coms := range setsOfCommitments {
		if len(coms) != requiredBrngBatchSize {
			panic("invalid sets of commitments")
		}
	}

	// Boolean to keep a track of whether shares computation should be ignored
	// or not. This is set to true if the sets of shares are invalid in any
	// way.
	ignoreShares := false

	// Ignore the shares if their number of sets does not match the number of
	// sets of commitments.
	if len(setsOfShares) != len(setsOfCommitments) {
		ignoreShares = true
	}

	//
	// Shares validity
	//

	if !ignoreShares {
		// Each set of shares in the batch should have the correct length.
		for _, shares := range setsOfShares {
			if len(shares) != requiredBrngBatchSize {
				panic("invalid set of shares")
			}
		}
	}

	// Declare variable to hold commitments to initialize the opener.
	locallyComputedCommitments := make([]shamir.Commitment, rnger.batchSize)

	// Construct the commitments for the batch of unbiased random numbers.
	for i, setOfCommitments := range setsOfCommitments {
		// Compute the output commitment.
		rnger.commitments[i] = shamir.NewCommitmentWithCapacity(int(rnger.threshold))
		if isZero {
			rnger.commitments[i].Append(secp256k1.NewPointInfinity())
		}

		for _, c := range setOfCommitments {
			rnger.commitments[i].Append(c[0])
		}

		// Compute the share commitment and add it to the local set of
		// commitments.
		accCommitment := compute.ShareCommitment(rnger.index, setOfCommitments)
		if isZero {
			accCommitment.Scale(accCommitment, &rnger.index)
		}

		locallyComputedCommitments[i].Set(accCommitment)
	}

	// If the sets of shares are valid, we must construct the directed openings
	// to other players in the network.
	if !ignoreShares {
		for _, j := range rnger.indices {
			for _, setOfShares := range setsOfShares {
				accShare := compute.ShareOfShare(j, setOfShares)
				if isZero {
					accShare.Scale(&accShare, &j)
				}
				rnger.openingsMap[j] = append(rnger.openingsMap[j], accShare)
			}
		}
	}

	// Reset the Opener machine with the computed commitments.
	// FIXME: This should happen in the constructor.
	rnger.opener = open.New(locallyComputedCommitments, rnger.indices, h)

	// Transition the machine's state.
	rnger.state = WaitingOpen

	// Supply the locally computed shares to the opener.
	if !ignoreShares {
		event, secrets, decommitments := rnger.opener.HandleShareBatch(rnger.openingsMap[rnger.index])

		// This only happens when k = 1.
		if event == open.Done {
			rnger.state = Done
			rnger.secrets = secrets
			rnger.decommitments = decommitments
			return RNGsReconstructed
		}
	}

	if ignoreShares {
		return CommitmentsConstructed
	}

	return SharesConstructed
}

// HasConstructedShares returns `true` if the RNG machine has received its `b`
// sets of verifiable shares, and upon that constructed its shares. It returns
// false otherwise.
func (rnger RNGer) HasConstructedShares() bool {
	return rnger.state != Init
}

// DirectedOpenings returns the openings from the RNG state machine to other
// RNG state machines.
func (rnger RNGer) DirectedOpenings(to secp256k1.Fn) shamir.VerifiableShares {
	if rnger.state == Init {
		return nil
	}

	shares, ok := rnger.openingsMap[to]
	if !ok {
		return nil
	}

	return shares
}

// TransitionOpen performs the state transition for the RNG state machine upon
// receiving directed openings of shares from other players.
//
// The state transition on calling TransitionOpen is described below:
// 1. RNG machine in state `Init` transitions to `WaitingOpen`
// 2. RNG machine in state `WaitingOpen` continues to be in state `WaitingOpen`
// 		if the machine has less than `k` opened shares, including the one
// 		supplied here.
// 3. RNG machine in state `WaitingOpen` transitions to `Done` if the machine
// 		now has `k` opened shares, including the one supplied here.
//
// Since the RNG machine is capable of generating `b` random numbers, we expect
// other players to supply `b` directed openings of their shares too.
//
// When the RNG machine transitions to the Done state, it has a share each
// `r_j` for the `b` random numbers.
//
// - Inputs
//   - openings are the directed openings
//	   - MUST be of length b (batch size)
//	   - Will be ignored if they're not consistent with their respective commitments
//
// - Returns
//   - TransitionEvent
// 		- OpeningsIgnored when the openings were invalid in form or consistency
// 		- OpeningsAdded when the openings were valid are were added to the opener
// 		- RNGsReconstructed when the set of openings was the kth valid set and
// 			hence the RNGer could reconstruct its shares for the unbiased
// 			random numbers
func (rnger *RNGer) TransitionOpen(openings shamir.VerifiableShares) TransitionEvent {
	// Simply ignore if the RNG state machine is not in the `WaitingOpen`
	// state.
	if rnger.state != WaitingOpen {
		return OpeningsIgnored
	}

	// Pass these openings to the Opener state machine now that we have already
	// received valid commitments from BRNG outputs.
	event, secrets, decommitments := rnger.opener.HandleShareBatch(openings)

	switch event {
	case open.Done:
		rnger.state = Done
		rnger.secrets = secrets
		rnger.decommitments = decommitments
		return RNGsReconstructed
	case open.SharesAdded:
		return OpeningsAdded
	default:
		return OpeningsIgnored
	}
}

// ReconstructedShares returns the `b` verifiable shares for the `b` random
// numbers that have been reconstructed by the RNG machine (one verifiable
// share for each random number). This also means that the RNG machine is in
// the `Done` state. If it isn't in the Done state this function returns `nil`.
func (rnger RNGer) ReconstructedShares() shamir.VerifiableShares {
	if rnger.state != Done {
		return nil
	}

	vshares := make(shamir.VerifiableShares, rnger.batchSize)
	for i, secret := range rnger.secrets {
		share := shamir.NewShare(rnger.index, secret)
		vshares[i] = shamir.NewVerifiableShare(share, rnger.decommitments[i])
	}

	return vshares
}

// Reset transitions the RNG state machine back to the Init state. Note that
// the Opener state machine is not reset at this point in time. It is reset
// when the RNG receives its BRNG outputs again.
func (rnger *RNGer) Reset() TransitionEvent {
	for i := 0; i < int(rnger.batchSize); i++ {
		rnger.commitments = rnger.commitments[:0]
	}

	for _, index := range rnger.indices {
		rnger.openingsMap[index] = rnger.openingsMap[index][:0]
	}

	rnger.state = Init

	return Reset
}
