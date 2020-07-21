package rkpg

import (
	"fmt"

	"github.com/renproject/secp256k1"
	"github.com/renproject/shamir"
)

// InitialMessages creates the share batch for the open performed in the RKPG
// protocol.
func InitialMessages(params *Params, rngShares, rzgShares shamir.VerifiableShares) (shamir.Shares, error) {
	if len(rngShares) != int(params.b) || len(rzgShares) != int(params.b) {
		return nil, fmt.Errorf(
			"invalid share batch size: expected both %v (rng) and %v (rzg) to be %v",
			len(rngShares), len(rzgShares), params.b,
		)
	}

	shares := make(shamir.Shares, len(rngShares))
	for i := range shares {
		rnShare := rngShares[i].Share()
		rzShare := rzgShares[i].Share()
		ind := rzShare.Index()
		if !rnShare.IndexEq(&ind) {
			return nil, fmt.Errorf("mismatched indices: expected %v to equal %v", rnShare.Index(), ind)
		}
		if _, ok := params.ArrIndex[ind]; !ok {
			return nil, fmt.Errorf("indices out of range: index %v not in index set", ind)
		}

		dRnShare := shamir.NewShare(ind, rngShares[i].Decommitment())
		RzShare := rzgShares[i].Share()

		shares[i].Add(&dRnShare, &RzShare)
	}

	return shares, nil
}

// TransitionShares applies a state transition to the given state upon
// receiveing the given shares from another party during the open in the RKPG
// protocol. The given commitments correspond to the RNG shares that were input
// for RKPG. Once enough shares have been received to reconstruct, they are
// used to compute and return the output public key batch. If not enough shares
// have been received, the return value will be nil.
func TransitionShares(
	state *State,
	params *Params,
	coms []shamir.Commitment,
	shares shamir.Shares,
) ([]secp256k1.Point, TransitionEvent) {
	if len(shares) != int(params.b) {
		return nil, WrongBatchSize
	}
	index := shares[0].Index()
	ind, ok := params.ArrIndex[index]
	if !ok {
		return nil, InvalidIndex
	}
	if state.shareReceived[ind] {
		return nil, DuplicateIndex
	}
	// Check that all indices in the share batch are the same.
	for i := 1; i < len(shares); i++ {
		if !shares[i].IndexEq(&index) {
			return nil, InconsistentShares
		}
	}

	// Checks have passed so we update the state.
	for i, buf := range state.buffers {
		buf[ind] = shares[i].Value()
	}
	state.shareReceived[ind] = true
	state.count++

	if int(state.count) < int(params.n-params.k+1) {
		// Not enough shares have been received for construction.
		return nil, ShareAdded
	}
	secrets := make([]secp256k1.Fn, params.b)
	for i, buf := range state.buffers {
		poly, ok := params.decoder.Decode(buf)
		if !ok {
			// The RS decoder was not able to reconstruct the polynomial
			// because there are too many incorrect shares.
			return nil, TooManyErrors
		}
		secrets[i] = *poly.Coefficient(0)
	}

	pubKeys := make([]secp256k1.Point, params.b)
	for i, secret := range secrets {
		// Compute xG = (xG + sH) + (-s)H
		secret.Negate(&secret)
		pubKeys[i].Scale(&params.h, &secret)
		pubKeys[i].Add(&pubKeys[i], &coms[i][0])
	}
	return pubKeys, Reconstructed
}
