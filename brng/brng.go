package brng

import (
	"fmt"

	"github.com/renproject/secp256k1"
	"github.com/renproject/shamir"
)

//BRNGer implements the BRNG algorithm.
type BRNGer struct {
	batchSize uint32
	index     secp256k1.Fn
	h         secp256k1.Point
}

// New creates a new BRNG state machine for the given indices and pedersen
// parameter h. The given index represents the index of the created player. The
// batch size represents the number of instances of the algorithm to be run in
// parallel.
//
// Panics: This function will panic if either the batch size or the
// reconstruction threshold (k) are less than 1.
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

// IsValid checks the validity of the given potential consensus outputs. The
// required contributions argument is the minimum number of contributions
// required from other players for the consensus output to be considered valid.
// Usually, this will be set to the reconstruction threshold (k) of the shares.
// A return value of true means that this consensus output can be used to
// construct the output shares and commitments for BRNG. If the return value is
// false, then either the shares or the commitments or both are not valid, and
// a corresponding error is returned based on how they are invalid.
//
// Panics: This function will panic if the given required contributions is less
// than 1.
func (brnger *BRNGer) IsValid(
	sharesBatch []shamir.VerifiableShares,
	commitmentsBatch [][]shamir.Commitment,
	requiredContributions int,
) error {
	if requiredContributions < 1 {
		panic(fmt.Sprintf("required contributions must be at least 1: got %v", requiredContributions))
	}
	// Commitments validity.
	if uint32(len(commitmentsBatch)) != brnger.batchSize {
		return ErrIncorrectCommitmentsBatchSize
	}
	numContributions := len(commitmentsBatch[0])
	if numContributions < requiredContributions {
		return ErrNotEnoughContributions
	}
	for _, commitments := range commitmentsBatch {
		if len(commitments) != numContributions {
			return ErrInvalidCommitmentDimensions
		}
	}
	k := commitmentsBatch[0][0].Len()
	for _, commitments := range commitmentsBatch {
		for _, commitment := range commitments {
			if commitment.Len() != k {
				return ErrInvalidCommitmentDimensions
			}
		}
	}

	// Shares validity.
	if uint32(len(sharesBatch)) != brnger.batchSize {
		return ErrIncorrectSharesBatchSize
	}
	for i, shares := range sharesBatch {
		if len(shares) != numContributions {
			return ErrInvalidShareDimensions
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
