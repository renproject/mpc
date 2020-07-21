package rkpgutil

import (
	"github.com/renproject/secp256k1"
	"github.com/renproject/shamir"
)

// RNGOutputBatch returns a random valid output of an instance of the RNG
// protocol. In the returned shares, shares[i] are the outputs for player i and
// has length equal to the batch size. The returned Fn values are the secret
// values for each sharing in the batch.
func RNGOutputBatch(
	indices []secp256k1.Fn,
	k, b int,
	h secp256k1.Point,
) ([]shamir.VerifiableShares, []shamir.Commitment, []secp256k1.Fn) {
	return RXGOutputBatch(indices, k, b, h, false)
}

// RZGOutputBatch returns a random valid output of an instance of the RZG
// protocol. In the returned shares, shares[i] are the outputs for player i and
// has length equal to the batch size.
func RZGOutputBatch(
	indices []secp256k1.Fn,
	k, b int,
	h secp256k1.Point,
) ([]shamir.VerifiableShares, []shamir.Commitment) {
	shares, coms, _ := RXGOutputBatch(indices, k, b, h, true)
	return shares, coms
}

// RXGOutputBatch returns either RNG or RZG output based on the flag zero.
func RXGOutputBatch(
	indices []secp256k1.Fn,
	k, b int,
	h secp256k1.Point,
	zero bool,
) ([]shamir.VerifiableShares, []shamir.Commitment, []secp256k1.Fn) {
	shares := make([]shamir.VerifiableShares, b)
	coms := make([]shamir.Commitment, b)
	secrets := make([]secp256k1.Fn, b)
	for i := range shares {
		if zero {
			shares[i], coms[i] = RXGOutput(indices, k, h, secp256k1.NewFnFromU16(0))
		} else {
			secrets[i] = secp256k1.RandomFn()
			shares[i], coms[i] = RXGOutput(indices, k, h, secrets[i])
		}
	}
	sharesTrans := make([]shamir.VerifiableShares, len(indices))
	for i := range sharesTrans {
		sharesTrans[i] = make(shamir.VerifiableShares, b)
	}
	for i := range shares {
		for j, share := range shares[i] {
			sharesTrans[j][i] = share
		}
	}
	return sharesTrans, coms, secrets
}

// RXGOutput returns the shares and a commitment for a valid verifiable sharing
// of the value x with threshold k and Pedersen parameter h.
func RXGOutput(
	indices []secp256k1.Fn,
	k int,
	h secp256k1.Point,
	x secp256k1.Fn,
) (shamir.VerifiableShares, shamir.Commitment) {
	shares := make(shamir.VerifiableShares, len(indices))
	com := shamir.NewCommitmentWithCapacity(k)
	sharer := shamir.NewVSSharer(indices, h)
	sharer.Share(&shares, &com, x, k)
	return shares, com
}
