package rkpgutil

import (
	"github.com/renproject/secp256k1"
	"github.com/renproject/shamir"
)

func RNGOutputBatch(
	indices []secp256k1.Fn,
	k, b int,
	h secp256k1.Point,
) ([]shamir.VerifiableShares, []shamir.Commitment, []secp256k1.Fn) {
	return RXGOutputBatch(indices, k, b, h, false)
}

func RZGOutputBatch(
	indices []secp256k1.Fn,
	k, b int,
	h secp256k1.Point,
) ([]shamir.VerifiableShares, []shamir.Commitment) {
	shares, coms, _ := RXGOutputBatch(indices, k, b, h, true)
	return shares, coms
}

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
