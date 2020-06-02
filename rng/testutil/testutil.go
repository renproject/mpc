package testutil

import (
	"github.com/renproject/secp256k1-go"
	"github.com/renproject/shamir"
	"github.com/renproject/shamir/curve"

	"github.com/renproject/mpc/brng"
	btu "github.com/renproject/mpc/brng/testutil"
	"github.com/renproject/mpc/open"
)

// GetBrngOutputs uses a temporary BRNG engine to generate random
// sets of shares and commitments
func GetBrngOutputs(
	indices []open.Fn,
	index open.Fn,
	b, k int,
	h curve.Point,
) ([]shamir.VerifiableShares, [][]shamir.Commitment) {
	// We will need a BRNG engine
	brnger := brng.New(indices, h)

	// since we generate b unbiased random numbers together
	// and we need k BRNG calls for every random number generation
	setsOfShares := make([]shamir.VerifiableShares, b)
	setsOfCommitments := make([][]shamir.Commitment, b)
	for i := 0; i < b; i++ {
		// reset the BRNG engine
		brnger.Reset()
		_ = brnger.TransitionStart(k, k)

		// generate a valid table. Each table represents `k` BRNG runs
		// which also means, a batch size of `k` for the BRNG call
		table := btu.RandomValidTable(
			indices,      // indices of players
			h,            // pedersen commitment parameter
			k,            // reconstruction threshold
			k,            // batch size of each BRNG call
			len(indices), // height of the table
		)

		// get slice of this table for the player of our interest
		slice := table.TakeSlice(index, indices)

		// process slice to get shares and commitments
		shares, commitments, _ := brnger.TransitionSlice(slice)
		setsOfShares[i] = shares
		setsOfCommitments[i] = commitments
	}

	return setsOfShares, setsOfCommitments
}

// GetDirectedOpenings computes and returns openings and their
// respective commitments from a player for another player
// using the from player's sets of shares and commitments
func GetDirectedOpenings(
	setsOfShares []shamir.VerifiableShares,
	setsOfCommitments [][]shamir.Commitment,
	to open.Fn,
) (shamir.VerifiableShares, []shamir.Commitment) {
	N := len(setsOfShares[0])
	n := secp256k1.NewSecp256k1N(uint64(N))
	computedShares := make(shamir.VerifiableShares, len(setsOfShares))
	computedCommitments := make([]shamir.Commitment, len(setsOfShares))

	for i, setOfShares := range setsOfShares {
		for j := 1; j <= N; j++ {
			// Initialise the accumulators with the first values
			var accShare = setOfShares[0]
			var accCommitment shamir.Commitment
			accCommitment.Set(setsOfCommitments[i][0])
			var multiplier = secp256k1.OneSecp256k1N()

			// For all other shares and commitments
			for l := 1; l < len(setOfShares); l++ {
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

			// If j is the `to` machine's index, then populate the shares
			// which will be later returned
			if to.Uint64() == uint64(j) {
				computedShares[i] = accShare
				computedCommitments[i] = accCommitment
			}
		}
	}

	return computedShares, computedCommitments
}
