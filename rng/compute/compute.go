package compute

import (
	"github.com/renproject/mpc/open"
	"github.com/renproject/secp256k1-go"
	"github.com/renproject/shamir"
)

// Commitment accepts the set of commitments for batch of BRNG outputs
// and returns a valid commitment for the final random number
func Commitment(
	setOfCommitments []shamir.Commitment,
	k uint32,
) shamir.Commitment {
	commitment := shamir.NewCommitmentWithCapacity(int(k))

	for _, c := range setOfCommitments {
		p := c.GetPoint(0)
		commitment.AppendPoint(p)
	}

	return commitment
}

// AccumulatorCommitment accepts the set of commitments and computes a weighted
// linear combination of those commitments.
// This accumulated value also represents the commitment for this machine's
// player for its share of the final unbiased random number
func AccumulatorCommitment(
	toIndex open.Fn,
	setOfCommitments []shamir.Commitment,
) shamir.Commitment {
	// Initialise the accumulators with the first values
	var multiplier open.Fn
	var accCommitment shamir.Commitment

	multiplier = secp256k1.OneSecp256k1N()
	accCommitment.Set(setOfCommitments[0])

	// For all other shares and commitments
	for l := 1; l < len(setOfCommitments); l++ {
		// Scale the multiplier
		multiplier.Mul(&multiplier, &toIndex)
		multiplier.Normalize()

		// Initialise
		// Scale by the multiplier
		// Add to the accumulator
		var commitment shamir.Commitment
		commitment.Set(setOfCommitments[l])
		commitment.Scale(&commitment, &multiplier)
		accCommitment.Add(&accCommitment, &commitment)
	}

	return accCommitment
}

// AccumulatorShare accepts the set of verifiable shares and computes a weighted
// linear combination of those shares.
// This accumulated value also represents the directed openings from this machine's
// player to the player at index `toIndex`
func AccumulatorShare(
	toIndex open.Fn,
	setOfShares shamir.VerifiableShares,
) shamir.VerifiableShare {
	// Initialise the accumulators with the first values
	var multiplier open.Fn
	var accShare shamir.VerifiableShare

	multiplier = secp256k1.OneSecp256k1N()
	accShare = setOfShares[0]

	// For all other shares and commitments
	for l := 1; l < len(setOfShares); l++ {
		// Scale the multiplier
		multiplier.Mul(&multiplier, &toIndex)
		multiplier.Normalize()

		// Initialise
		// Scale by the multiplier
		// Add to the accumulator
		var share = setOfShares[l]
		share.Scale(&share, &multiplier)
		accShare.Add(&accShare, &share)
	}

	return accShare
}
