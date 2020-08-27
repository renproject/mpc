package rng

import (
	"fmt"

	"github.com/renproject/secp256k1"
	"github.com/renproject/shamir"

	"github.com/renproject/mpc/open"
	"github.com/renproject/mpc/params"
	"github.com/renproject/mpc/rng/compute"
)

// An RNGer implements the RNG or RZG protocol.
type RNGer struct {
	index  secp256k1.Fn
	opener open.Opener
}

// New creates a new intance of a state machine that carries out either the RNG
// or RZG protocol. Which one of these two cases is instantiated is determined
// by the isZero argument. The share and commitment batch arguments are outputs
// from the BRNG protocol; they are expected to be valid, and if the given
// shares are nil then they will be ignored. Along with the state machine, the
// initial messages to be sent to the other parties are returned, which is a
// map indexed by the index of the player that the message is destined for. If
// this function is called with a nil share batch, this returned map will also
// be nil, as the initial messages cannot be computed without input shares.
//
// Panics: This function will panic in the following cases.
//	- The batch size is less than 1.
//	- The batch size of the BRNG outputs is less than 1 in the case of RZG, or
//	less than 2 in the case of RNG.
//	- Not all batch sizes of the BRNG outputs (both commitments and shares) are
//	the same.
//	- Not all commitments have the correct threshold (k).
//	- The shares and commitments have a different batch size.
func New(
	ownIndex secp256k1.Fn,
	indices []secp256k1.Fn,
	h secp256k1.Point,
	brngShareBatch []shamir.VerifiableShares,
	brngCommitmentBatch [][]shamir.Commitment,
	isZero bool,
) (RNGer, map[secp256k1.Fn]shamir.VerifiableShares, []shamir.Commitment) {
	if !params.ValidPedersenParameter(h) {
		panic("insecure choice of pedersen parameter")
	}
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

	for _, commitments := range brngCommitmentBatch {
		if len(commitments) != requiredBrngBatchSize {
			panic("invalid commitment dimensions")
		}
		for _, commitment := range commitments {
			if commitment.Len() != int(k) {
				panic(fmt.Sprintf(
					"inconsistent commitment threshold: expected %v, got %v",
					k, commitment.Len(),
				))
			}
		}
	}

	// If the supplied shares are nil, they are to be ignored (this means that
	// the output from BRNG was not valid for this player). Any non-nil slice
	// of shares is assumed to be valid.
	ignoreShares := brngShareBatch == nil

	if !ignoreShares {
		if len(brngShareBatch) != int(b) {
			panic(fmt.Sprintf(
				"incorrect share batch size: expected %v (commitments), got %v\n",
				b, len(brngShareBatch),
			))
		}

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
	opener := open.New(ownCommitments, indices, h)

	// If the sets of shares are valid, construct the directed openings to
	// other players in the network.
	var directedOpenings map[secp256k1.Fn]shamir.VerifiableShares = nil
	if !ignoreShares {
		directedOpenings = make(map[secp256k1.Fn]shamir.VerifiableShares, len(indices))
		for _, j := range indices {
			for _, setOfShares := range brngShareBatch {
				accShare := compute.ShareOfShare(j, setOfShares)
				if isZero {
					accShare.Scale(&accShare, &j)
				}
				directedOpenings[j] = append(directedOpenings[j], accShare)
			}
		}

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

// HandleShareBatch handles a batch of shares received from another player. If
// the share batch was invalid in any way, an error will be returned. If the
// given share batch was the kth valid batch to be received, reconstruction is
// possible and the return value will be the reconstructed secrets. Otherwise,
// the return value will be nil.
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
