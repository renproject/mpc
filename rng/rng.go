package rng

import (
	"fmt"
	"math/rand"
	"reflect"

	"github.com/renproject/secp256k1"
	"github.com/renproject/shamir"

	"github.com/renproject/mpc/open"
	"github.com/renproject/mpc/rng/compute"
)

type RNGer struct {
	// index signifies the given RNG state machine's index.
	index secp256k1.Fn

	// opener is the Opener state machine operating within the RNG state
	// machine As the RNG machine receives openings from other players, the
	// opener state machine also transitions, to eventually reconstruct the
	// batchSize number of secrets.
	opener open.Opener
}

func New(
	ownIndex secp256k1.Fn,
	indices []secp256k1.Fn,
	h secp256k1.Point,
	brngShareBatch []shamir.VerifiableShares,
	brngCommitmentBatch [][]shamir.Commitment,
	isZero bool,
) (RNGer, map[secp256k1.Fn]shamir.VerifiableShares, []shamir.Commitment) {
	b := uint32(len(brngCommitmentBatch))
	if b <= 0 {
		panic(fmt.Sprintf("b must be greater than 0, got: %v", b))
	}
	k := uint32(len(brngCommitmentBatch[0]))
	if isZero {
		k++
	}
	if k <= 1 {
		panic(fmt.Sprintf("k must be greater than 1, got: %v", k))
	}

	var requiredBrngBatchSize int
	if isZero {
		// The constant term of the polynomial is zero so we don't need a share
		// for it.
		requiredBrngBatchSize = int(k - 1)
	} else {
		requiredBrngBatchSize = int(k)
	}

	//
	// Commitments validity
	//

	for _, coms := range brngCommitmentBatch {
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
	if len(brngShareBatch) != len(brngCommitmentBatch) {
		ignoreShares = true
	}

	//
	// Shares validity
	//

	if !ignoreShares {
		// Each set of shares in the batch should have the correct length.
		for _, shares := range brngShareBatch {
			if len(shares) != requiredBrngBatchSize {
				panic("invalid set of shares")
			}
		}
	}

	ownCommitments := make([]shamir.Commitment, b)
	outputCommitments := make([]shamir.Commitment, b)
	for i, setOfCommitments := range brngCommitmentBatch {
		// Compute the output commitment.
		outputCommitments[i] = shamir.NewCommitmentWithCapacity(int(k))
		if isZero {
			outputCommitments[i].Append(secp256k1.NewPointInfinity())
		}

		for _, c := range setOfCommitments {
			outputCommitments[i].Append(c[0])
		}

		// Compute the share commitment and add it to the local set of
		// outputCommitments.
		accCommitment := compute.ShareCommitment(ownIndex, setOfCommitments)
		if isZero {
			accCommitment.Scale(accCommitment, &ownIndex)
		}

		ownCommitments[i].Set(accCommitment)
	}

	// If the sets of shares are valid, construct the directed openings to
	// other players in the network.
	var directedOpenings map[secp256k1.Fn]shamir.VerifiableShares = nil
	if !ignoreShares {
		directedOpenings = make(map[secp256k1.Fn]shamir.VerifiableShares, b)
		for _, j := range indices {
			for _, setOfShares := range brngShareBatch {
				accShare := compute.ShareOfShare(j, setOfShares)
				if isZero {
					accShare.Scale(&accShare, &j)
				}
				directedOpenings[j] = append(directedOpenings[j], accShare)
			}
		}
	}

	opener := open.New(ownCommitments, indices, h)
	if !ignoreShares {
		// Handle own share.
		secrets, decommitments, err := opener.HandleShareBatch(directedOpenings[ownIndex])
		if err != nil {
			panic(fmt.Sprintf("unexpected error: %v", err))
		}
		if secrets != nil || decommitments != nil {
			panic("opener should not have reconstructed after one share")
		}
	}

	rnger := RNGer{
		index:  ownIndex,
		opener: opener,
	}

	return rnger, directedOpenings, outputCommitments
}

func (rnger *RNGer) HandleShareBatch(shareBatch shamir.VerifiableShares) (shamir.VerifiableShares, error) {
	secrets, decommitments, err := rnger.opener.HandleShareBatch(shareBatch)
	if err != nil {
		return nil, err
	}
	if secrets == nil {
		return nil, nil
	}
	shares := make(shamir.VerifiableShares, len(secrets))
	for i, secret := range secrets {
		share := shamir.NewShare(rnger.index, secret)
		shares[i] = shamir.NewVerifiableShare(share, decommitments[i])
	}
	return shares, nil
}

// SizeHint implements the surge.SizeHinter interface.
func (rnger RNGer) SizeHint() int {
	return rnger.index.SizeHint() +
		rnger.opener.SizeHint()
}

// Marshal implements the surge.Marshaler interface.
func (rnger RNGer) Marshal(buf []byte, rem int) ([]byte, int, error) {
	buf, rem, err := rnger.index.Marshal(buf, rem)
	if err != nil {
		return buf, rem, fmt.Errorf("marshaling index: %v", err)
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
	buf, rem, err = rnger.opener.Unmarshal(buf, rem)
	if err != nil {
		return buf, rem, fmt.Errorf("unmarshaling opener: %v", err)
	}
	return buf, rem, nil
}

// Generate implements the quick.Generator interface.
func (rnger RNGer) Generate(rand *rand.Rand, size int) reflect.Value {
	index := secp256k1.RandomFn()
	opener := open.Opener{}.Generate(rand, size).Interface().(open.Opener)
	return reflect.ValueOf(RNGer{index, opener})
}
