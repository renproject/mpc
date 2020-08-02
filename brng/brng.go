package brng

import (
	"fmt"

	"github.com/renproject/secp256k1"
	"github.com/renproject/shamir"
)

type BRNGer struct {
	batchSize uint32
	index     secp256k1.Fn
	h         secp256k1.Point
}

// New creates a new BRNG state machine for the given indices and pedersen
// parameter h.
func New(batchSize, k uint32, indices []secp256k1.Fn, index secp256k1.Fn, h secp256k1.Point) (
	BRNGer, []Sharing,
) {
	if batchSize < 1 {
		panic(fmt.Sprintf("batch size must be at least 1: got %v", batchSize))
	}
	if k < 1 {
		panic(fmt.Sprintf("k must be at least 1: got %v", k))
	}
	n := len(indices)
	sharings := make([]Sharing, int(batchSize))
	for i := range sharings {
		sharings[i].Shares = make(shamir.VerifiableShares, n)
		sharings[i].Commitment = shamir.NewCommitmentWithCapacity(int(k))
		shamir.VShareSecret(&sharings[i].Shares, &sharings[i].Commitment,
			indices, h, secp256k1.RandomFn(), int(k))
	}
	brnger := BRNGer{batchSize, index, h}
	return brnger, sharings
}

func (brnger *BRNGer) IsValid(
	sharesBatch []shamir.VerifiableShares,
	commitmentsBatch [][]shamir.Commitment,
	requiredContributions int,
) error {
	if requiredContributions < 1 {
		panic(fmt.Sprintf("required contributions must be at least 1: got %v", requiredContributions))
	}
	if uint32(len(commitmentsBatch)) != brnger.batchSize {
		return ErrIncorrectBatchSize
	}
	numContributions := len(commitmentsBatch[0])
	if numContributions < requiredContributions {
		return ErrNotEnoughContributions
	}
	for _, commitments := range commitmentsBatch {
		if len(commitments) != numContributions {
			return ErrInvalidInputDimensions
		}
	}
	k := commitmentsBatch[0][0].Len()
	for _, commitments := range commitmentsBatch {
		for _, commitment := range commitments {
			if commitment.Len() != k {
				return ErrInvalidInputDimensions
			}
		}
	}

	if uint32(len(sharesBatch)) != brnger.batchSize {
		return ErrIncorrectBatchSize
	}
	for i, shares := range sharesBatch {
		if len(shares) != numContributions {
			return ErrInvalidInputDimensions
		}
		for j, share := range shares {
			if !share.Share.IndexEq(&brnger.index) {
				return ErrIncorrectIndex
			}
			if !shamir.IsValid(brnger.h, &commitmentsBatch[i][j], &share) {
				return ErrInvalidShares
			}
		}
	}

	return nil
}

// HandleConsensusOutput performs the state transition for the BRNger state
// machine upon receiving a slice.
func HandleConsensusOutput(
	sharesBatch []shamir.VerifiableShares, commitmentsBatch [][]shamir.Commitment,
) (
	shamir.VerifiableShares, []shamir.Commitment,
) {
	commitmentSumBatch := make([]shamir.Commitment, len(commitmentsBatch))
	for i, commitments := range commitmentsBatch {
		commitmentSumBatch[i].Set(commitments[0])
		for _, com := range commitments[1:] {
			commitmentSumBatch[i].Add(commitmentSumBatch[i], com)
		}
	}

	// If the given shares were nil then they should be ignored, otherwise
	// progress to summing them.
	if sharesBatch == nil {
		return nil, commitmentSumBatch
	}

	shareSumBatch := make(shamir.VerifiableShares, len(sharesBatch))
	for i, shares := range sharesBatch {
		shareSumBatch[i] = shares[0]
		for _, share := range shares[1:] {
			shareSumBatch[i].Add(&shareSumBatch[i], &share)
		}
	}

	return shareSumBatch, commitmentSumBatch
}
