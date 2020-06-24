package rng

import (
	"fmt"
	"io"

	"github.com/renproject/shamir"
	"github.com/renproject/shamir/curve"
	"github.com/renproject/shamir/util"
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
	index open.Fn

	// indices signifies the list of all such RNG state machines participating
	// in the RNG protocol.
	indices []open.Fn

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
	openingsMap map[open.Fn]shamir.VerifiableShares
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
		surge.SizeHint(rnger.openingsMap)
}

// Marshal implements the surge.Marshaler interface.
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
	m, err = surge.Marshal(w, rnger.commitments, m)
	if err != nil {
		return m, fmt.Errorf("marshaling commitments: %v", err)
	}
	m, err = surge.Marshal(w, rnger.openingsMap, m)
	if err != nil {
		return m, fmt.Errorf("marshaling openingsMap: %v", err)
	}
	return m, nil
}

// Unmarshal implements the surge.Unmarshaler interface.
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
	m, err = rnger.unmarshalCommitments(r, m)
	if err != nil {
		return m, fmt.Errorf("unmarshaling commitments: %v", err)
	}
	m, err = rnger.unmarshalOpeningsMap(r, m)
	if err != nil {
		return m, fmt.Errorf("unmarshaling openingsMap: %v", err)
	}
	return m, nil
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
	ownIndex open.Fn,
	indices []open.Fn,
	b, k uint32,
	h curve.Point,
) (TransitionEvent, RNGer) {
	state := Init

	// Declare variable to hold RNG machine's computed shares and commitments
	// and allocate necessary memory.
	commitments := make([]shamir.Commitment, b)
	openingsMap := make(map[open.Fn]shamir.VerifiableShares)
	for _, index := range indices {
		openingsMap[index] = make(shamir.VerifiableShares, 0, b)
	}

	// Create an instance of the Opener state machine within the RNG state
	// machine.
	opener := open.New(b, indices, h)

	return Initialised, RNGer{
		state:       state,
		index:       ownIndex,
		indices:     indices,
		batchSize:   b,
		threshold:   k,
		opener:      opener,
		commitments: commitments,
		openingsMap: openingsMap,
	}
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
//
// - Returns
//   - TransitionEvent
//		 - SharesIgnored when the RNGer is not in `Init` state
//		 - CommitmentsConstructed when the sets of shares were invalid
//		 - SharesConstructed when the sets of shares were valid
//		 - RNGsReconstructed when the RNGer was able to reconstruct the random
//		 	shares (k = 1)
func (rnger *RNGer) TransitionShares(
	setsOfShares []shamir.VerifiableShares,
	setsOfCommitments [][]shamir.Commitment,
) TransitionEvent {
	// Simply ignore if the RNG state machine is not in the `Init` state.
	if rnger.state != Init {
		return SharesIgnored
	}

	//
	// Commitments validity
	//

	if len(setsOfCommitments) != int(rnger.batchSize) {
		panic("invalid sets of commitments")
	}

	for _, coms := range setsOfCommitments {
		if len(coms) != int(rnger.threshold) {
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

	// Each set of shares in the batch should have the correct length.
	for _, shares := range setsOfShares {
		if !ignoreShares && len(shares) != int(rnger.threshold) {
			panic("invalid set of shares")
		}
	}

	// Declare variable to hold field element for N.
	locallyComputedCommitments := make([]shamir.Commitment, rnger.batchSize)

	// Construct the commitments for the batch of unbiased random numbers.
	for i, setOfCommitments := range setsOfCommitments {
		rnger.commitments[i] = compute.OutputCommitment(setOfCommitments)

		// Compute the share commitment and add it to the local set of
		// commitments.
		accCommitment := compute.ShareCommitment(rnger.index, setOfCommitments)
		locallyComputedCommitments[i].Set(accCommitment)
	}

	// If the sets of shares are valid, we must construct the directed openings
	// to other players in the network.
	if !ignoreShares {
		// For every player in the network,
		for _, j := range rnger.indices {
			// for every set of commitments in the batch (sets of commitments),
			for _, setOfShares := range setsOfShares {
				// if the sets of shares are valid, compute the share of the
				// share and append to the directed openings map.
				accShare := compute.ShareOfShare(j, setOfShares)
				rnger.openingsMap[j] = append(rnger.openingsMap[j], accShare)
			}
		}
	}

	// Reset the Opener machine with the computed commitments.
	resetEvent := rnger.opener.TransitionReset(locallyComputedCommitments)
	if resetEvent != open.Reset {
		panic(fmt.Sprintf("Could not set commitments in Opener: %v", locallyComputedCommitments))
	}

	// Transition the machine's state.
	rnger.state = WaitingOpen

	// Supply the locally computed shares to the opener.
	if !ignoreShares {
		event := rnger.opener.TransitionShares(rnger.openingsMap[rnger.index])

		// This only happens when k = 1.
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

// HasConstructedShares returns `true` if the RNG machine has received its `b`
// sets of verifiable shares, and upon that constructed its shares. It returns
// false otherwise.
func (rnger RNGer) HasConstructedShares() bool {
	return rnger.state != Init
}

// DirectedOpenings returns the openings from the RNG state machine to other
// RNG state machines.
func (rnger RNGer) DirectedOpenings(to open.Fn) shamir.VerifiableShares {
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
//   - fromIndex is the index of the RNG machine from which we are receiving directed openings
//	   - MUST be a part of the set of indices in RNG machine
//	   - Will be ignored if valid openings are already supplied by this index
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
func (rnger *RNGer) TransitionOpen(
	fromIndex open.Fn,
	openings shamir.VerifiableShares,
) TransitionEvent {
	// Simply ignore if the RNG state machine is not in the `WaitingOpen`
	// state.
	if rnger.state != WaitingOpen {
		return OpeningsIgnored
	}

	// Ignore if the number of openings supplied is not equal to the RNG
	// machine's batch size.
	if len(openings) != int(rnger.batchSize) {
		return OpeningsIgnored
	}

	// If the fromIndex cannot be found in the set of valid machine indices
	// ignore the openings.
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
	// received valid commitments from BRNG outputs.
	event := rnger.opener.TransitionShares(openings)

	// If the opener has received enough shares to be able to reconstruct the
	// secrets.
	if event == open.Done {
		rnger.state = Done
		return RNGsReconstructed
	}

	// If the opener has added the shares correctly (they are valid).
	if event == open.SharesAdded {
		return OpeningsAdded
	}

	return OpeningsIgnored
}

// ReconstructedShares returns the `b` verifiable shares for the `b` random
// numbers that have been reconstructed by the RNG machine (one verifiable
// share for each random number). This also means that the RNG machine is in
// the `Done` state. If it isn't in the Done state this function returns `nil`.
func (rnger RNGer) ReconstructedShares() shamir.VerifiableShares {
	if rnger.state != Done {
		return nil
	}

	secrets := rnger.opener.Secrets()
	decommitments := rnger.opener.Decommitments()
	vshares := make(shamir.VerifiableShares, len(secrets))

	for i, secret := range secrets {
		share := shamir.NewShare(rnger.index, secret)
		vshares[i] = shamir.NewVerifiableShare(share, decommitments[i])
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

//
// Private functions
//

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

func (rnger *RNGer) unmarshalCommitments(r io.Reader, m int) (int, error) {
	var l uint32
	m, err := util.UnmarshalSliceLen32(&l, shamir.FnSizeBytes, r, m)
	if err != nil {
		return m, err
	}

	rnger.commitments = (rnger.commitments)[:0]
	for i := uint32(0); i < l; i++ {
		rnger.commitments = append(rnger.commitments, shamir.Commitment{})
		m, err = rnger.commitments[i].Unmarshal(r, m)
		if err != nil {
			return m, err
		}
	}

	return m, nil
}

func (rnger *RNGer) unmarshalOpeningsMap(r io.Reader, m int) (int, error) {
	var l uint32
	m, err := util.UnmarshalSliceLen32(&l, shamir.FnSizeBytes, r, m)
	if err != nil {
		return m, err
	}

	rnger.openingsMap = make(map[open.Fn]shamir.VerifiableShares, l)
	for i := uint32(0); i < l; i++ {
		var key open.Fn
		m, err = key.Unmarshal(r, m)
		if err != nil {
			return m, err
		}

		rnger.openingsMap[key] = make(shamir.VerifiableShares, rnger.batchSize)
		var vshares shamir.VerifiableShares
		m, err = vshares.Unmarshal(r, m)
		if err != nil {
			return m, err
		}
		rnger.openingsMap[key] = vshares
	}

	return m, nil
}
