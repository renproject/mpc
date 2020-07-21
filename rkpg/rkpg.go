package rkpg

import (
	"fmt"

	"github.com/renproject/secp256k1"
	"github.com/renproject/shamir"
)

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
	for i := 1; i < len(shares); i++ {
		if !shares[i].IndexEq(&index) {
			return nil, InconsistentShares
		}
	}

	for i, buf := range state.buffers {
		buf[ind] = shares[i].Value()
	}
	state.shareReceived[ind] = true
	state.count++

	if int(state.count) < int(params.n-params.k+1) {
		return nil, ShareAdded
	}
	secrets := make([]secp256k1.Fn, params.b)
	for i, buf := range state.buffers {
		poly, ok := params.decoder.Decode(buf)
		if !ok {
			return nil, TooManyErrors
		}
		secrets[i] = *poly.Coefficient(0)
	}

	pubKeys := make([]secp256k1.Point, params.b)
	for i, secret := range secrets {
		secret.Negate(&secret)
		pubKeys[i].Scale(&params.h, &secret)
		pubKeys[i].Add(&pubKeys[i], &coms[i][0])
	}

	return pubKeys, Reconstructed
}
