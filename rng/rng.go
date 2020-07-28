package rng

import (
	"fmt"

	"github.com/renproject/secp256k1"
	"github.com/renproject/shamir"
	"github.com/renproject/surge"

	"github.com/renproject/mpc/open"
	"github.com/renproject/mpc/rng/compute"
)

type RNGer struct {
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
}

func New(
	ownIndex secp256k1.Fn,
	indices []secp256k1.Fn,
	b, k uint32,
	h secp256k1.Point,
	setsOfShares []shamir.VerifiableShares,
	setsOfCommitments [][]shamir.Commitment,
	isZero bool,
) (TransitionEvent, RNGer, map[secp256k1.Fn]shamir.VerifiableShares, []shamir.Commitment) {
	// The required batch size for the BRNG outputs is k for RNG and k-1 for RZG
	var requiredBrngBatchSize int
	if isZero {
		requiredBrngBatchSize = int(k - 1)
	} else {
		requiredBrngBatchSize = int(k)
	}

	//
	// Commitments validity
	//

	if len(setsOfCommitments) != int(b) {
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
	locallyComputedCommitments := make([]shamir.Commitment, b)

	commitments := make([]shamir.Commitment, b)
	for i, setOfCommitments := range setsOfCommitments {
		// Compute the output commitment.
		commitments[i] = shamir.NewCommitmentWithCapacity(int(k))
		if isZero {
			commitments[i].Append(secp256k1.NewPointInfinity())
		}

		for _, c := range setOfCommitments {
			commitments[i].Append(c[0])
		}

		// Compute the share commitment and add it to the local set of
		// commitments.
		accCommitment := compute.ShareCommitment(ownIndex, setOfCommitments)
		if isZero {
			accCommitment.Scale(accCommitment, &ownIndex)
		}

		locallyComputedCommitments[i].Set(accCommitment)
	}

	// If the sets of shares are valid, construct the directed openings to
	// other players in the network.
	openingsMap := make(map[secp256k1.Fn]shamir.VerifiableShares, b)
	if !ignoreShares {
		for _, j := range indices {
			for _, setOfShares := range setsOfShares {
				accShare := compute.ShareOfShare(j, setOfShares)
				if isZero {
					accShare.Scale(&accShare, &j)
				}
				openingsMap[j] = append(openingsMap[j], accShare)
			}
		}
	}

	// Reset the Opener machine with the computed commitments.
	opener := open.New(locallyComputedCommitments, indices, h)

	var event TransitionEvent
	if ignoreShares {
		event = CommitmentsConstructed
	} else {
		// Handle own share.
		openEvent, secrets, decommitments := opener.HandleShareBatch(openingsMap[ownIndex])

		// This only happens when k = 1.
		if openEvent == open.Done {
			shares := make(shamir.VerifiableShares, b)
			for i, secret := range secrets {
				share := shamir.NewShare(ownIndex, secret)
				shares[i] = shamir.NewVerifiableShare(share, decommitments[i])
			}
			event = RNGsReconstructed
		} else {
			event = SharesConstructed
		}
	}

	rnger := RNGer{
		index:     ownIndex,
		indices:   indices,
		batchSize: b,
		threshold: k,
		opener:    opener,
	}

	return event, rnger, openingsMap, commitments
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
func (rnger *RNGer) TransitionOpen(openings shamir.VerifiableShares) (TransitionEvent, shamir.VerifiableShares) {
	// Pass these openings to the Opener state machine now that we have already
	// received valid commitments from BRNG outputs.
	event, secrets, decommitments := rnger.opener.HandleShareBatch(openings)

	switch event {
	case open.Done:
		shares := make(shamir.VerifiableShares, rnger.batchSize)
		for i, secret := range secrets {
			share := shamir.NewShare(rnger.index, secret)
			shares[i] = shamir.NewVerifiableShare(share, decommitments[i])
		}
		return RNGsReconstructed, shares
	case open.SharesAdded:
		return OpeningsAdded, nil
	default:
		return OpeningsIgnored, nil
	}
}

// SizeHint implements the surge.SizeHinter interface.
func (rnger RNGer) SizeHint() int {
	return rnger.index.SizeHint() +
		surge.SizeHint(rnger.indices) +
		surge.SizeHint(rnger.batchSize) +
		surge.SizeHint(rnger.threshold) +
		rnger.opener.SizeHint()
}

// Marshal implements the surge.Marshaler interface.
func (rnger RNGer) Marshal(buf []byte, rem int) ([]byte, int, error) {
	buf, rem, err := rnger.index.Marshal(buf, rem)
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
	return buf, rem, nil
}

// Unmarshal implements the surge.Unmarshaler interface.
func (rnger *RNGer) Unmarshal(buf []byte, rem int) ([]byte, int, error) {
	buf, rem, err := rnger.index.Unmarshal(buf, rem)
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
	return buf, rem, nil
}

// Generate implements the quick.Generator interface.
/*
func (rnger RNGer) Generate(rand *rand.Rand, size int) reflect.Value {
	size /= 10

	indices := shamirutil.RandomIndices(rand.Intn(20) + 1)
	ownIndex := indices[rand.Intn(len(indices))]
	b := (rand.Uint32() % uint32(size)) + 1
	k := uint32(size)/b + 1
	h := secp256k1.RandomPoint()
	setsOfCommitments := make([][]shamir.Commitment, b)
	for i := range setsOfCommitments {
		setsOfCommitments[i] = make([]shamir.Commitment, k)
		for j := range setsOfCommitments[i] {
			setsOfCommitments[i][j] = shamir.NewCommitmentWithCapacity(int(k))
			for l := uint32(0); l < k; l++ {
				setsOfCommitments[i][j] = append(setsOfCommitments[i][j], secp256k1.RandomPoint())
			}
		}
	}
	setsOfShares := make([]shamir.VerifiableShares, b)
	for i := range setsOfShares {
		setsOfShares[i] = make(shamir.VerifiableShares, k)
		for j := range setsOfShares[i] {
			setsOfShares[i][j].Share.Index = secp256k1.RandomFn()
			setsOfShares[i][j].Share.Value = secp256k1.RandomFn()
			setsOfShares[i][j].Decommitment = secp256k1.RandomFn()
		}
	}
	isZero := rand.Int31()&1 == 1
	_, v := New(ownIndex, indices, b, k, h, setsOfShares, setsOfCommitments, isZero)
	return reflect.ValueOf(v)
}
*/
