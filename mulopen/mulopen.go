package mulopen

import (
	"log"
	"time"

	"github.com/renproject/mpc/mulopen/mulzkp"
	"github.com/renproject/secp256k1"
	"github.com/renproject/shamir"
)

type MulOpener struct {
	shareBufs []shamir.Shares

	batchSize, k                                           uint32
	aCommitmentBatch, bCommitmentBatch, rzgCommitmentBatch []shamir.Commitment

	indices []secp256k1.Fn
	h       secp256k1.Point
}

func New(
	aShareBatch, bShareBatch, rzgShareBatch shamir.VerifiableShares,
	aCommitmentBatch, bCommitmentBatch, rzgCommitmentBatch []shamir.Commitment,
	indices []secp256k1.Fn, h secp256k1.Point,
) (MulOpener, []Message) {
	batchSize := len(aShareBatch)
	if batchSize < 1 {
		// TODO
	}
	if len(bShareBatch) != batchSize ||
		len(rzgShareBatch) != batchSize ||
		len(aCommitmentBatch) != batchSize ||
		len(bCommitmentBatch) != batchSize ||
		len(rzgCommitmentBatch) != batchSize {
		// TODO
	}
	k := aCommitmentBatch[0].Len()
	if k < 2 {
		// TODO
	}
	for _, com := range aCommitmentBatch {
		if com.Len() != k {
			// TODO
		}
	}
	for _, com := range bCommitmentBatch {
		if com.Len() != k {
			// TODO
		}
	}
	for _, com := range bCommitmentBatch {
		if com.Len() != 2*k-1 {
			// TODO
		}
	}
	n := len(indices)
	if 2*k-1 > n {
		// TODO
	}
	index := aShareBatch[0].Share.Index

	shareBufs := make([]shamir.Shares, batchSize)
	for i := range shareBufs {
		shareBufs[i] = make(shamir.Shares, 0, k)
	}

	mulopener := MulOpener{
		shareBufs:          shareBufs,
		batchSize:          uint32(batchSize),
		k:                  uint32(2*k - 1),
		aCommitmentBatch:   aCommitmentBatch,
		bCommitmentBatch:   bCommitmentBatch,
		rzgCommitmentBatch: rzgCommitmentBatch,
		indices:            indices,
		h:                  h,
	}

	var product secp256k1.Fn
	messageBatch := make([]Message, batchSize)
	for i := 0; i < batchSize; i++ {
		product.Mul(&aShareBatch[i].Share.Value, &bShareBatch[i].Share.Value)
		tau := secp256k1.RandomFn()
		aShareCommitment := polyEvalPoint(aCommitmentBatch[i], index)
		bShareCommitment := polyEvalPoint(bCommitmentBatch[i], index)
		productShareCommitment := pedersenCommit(&product, &tau, &h)
		proof := mulzkp.CreateProof(&h, &aShareCommitment, &bShareCommitment, &productShareCommitment,
			aShareBatch[i].Share.Value, bShareBatch[i].Share.Value,
			aShareBatch[i].Decommitment, bShareBatch[i].Decommitment, tau,
		)
		share := shamir.VerifiableShare{
			Share: shamir.Share{
				Index: index,
				Value: product,
			},
			Decommitment: tau,
		}
		share.Add(&share, &rzgShareBatch[i])
		messageBatch[i] = Message{
			VShare:     share,
			Commitment: productShareCommitment,
			Proof:      proof,
		}
	}

	return mulopener, messageBatch
}

func (mulopener *MulOpener) HandleShareBatch(messageBatch []Message) ([]secp256k1.Fn, error) {
	start := time.Now()
	defer func() {
		elapsed := time.Since(start)
		log.Printf("processed message in %s", elapsed)
	}()

	if uint32(len(messageBatch)) != mulopener.batchSize {
		// TODO
	}
	index := messageBatch[0].VShare.Share.Index
	{
		exists := false
		for i := range mulopener.indices {
			if index.Eq(&mulopener.indices[i]) {
				exists = true
			}
		}
		if !exists {
			// TODO
		}
	}
	for i := range messageBatch {
		if !messageBatch[i].VShare.Share.IndexEq(&index) {
			// TODO
		}
	}
	for i := uint32(0); i < mulopener.batchSize; i++ {
		aShareCommitment := polyEvalPoint(mulopener.aCommitmentBatch[i], index)
		bShareCommitment := polyEvalPoint(mulopener.bCommitmentBatch[i], index)
		if !mulzkp.Verify(
			&mulopener.h, &aShareCommitment, &bShareCommitment, &messageBatch[i].Commitment,
			&messageBatch[i].Proof,
		) {
			// TODO
		}
		var shareCommitment secp256k1.Point
		rzgShareCommitment := polyEvalPoint(mulopener.rzgCommitmentBatch[i], index)
		shareCommitment.Add(&messageBatch[i].Commitment, &rzgShareCommitment)

		com := pedersenCommit(
			&messageBatch[i].VShare.Share.Value, &messageBatch[i].VShare.Decommitment,
			&mulopener.h,
		)
		if !shareCommitment.Eq(&com) {
			// TODO
		}
	}

	// Shares are valid so we add them to the buffers.
	for i := range mulopener.shareBufs {
		mulopener.shareBufs[i] = append(mulopener.shareBufs[i], messageBatch[i].VShare.Share)
	}

	// If we have enough shares, reconstruct.
	if uint32(len(mulopener.shareBufs[0])) == mulopener.k {
		secrets := make([]secp256k1.Fn, mulopener.batchSize)
		for i, buf := range mulopener.shareBufs {
			secrets[i] = shamir.Open(buf)
		}
		return secrets, nil
	}

	return nil, nil
}

// TODO: This should probably be a function inside the shamir package.
func polyEvalPoint(commitment shamir.Commitment, index secp256k1.Fn) secp256k1.Point {
	var acc secp256k1.Point
	acc = commitment[len(commitment)-1]
	for l := len(commitment) - 2; l >= 0; l-- {
		acc.Scale(&acc, &index)
		acc.Add(&acc, &commitment[l])
	}
	return acc
}

// TODO: This should probably be a function inside the shamir package.
func pedersenCommit(value, decommitment *secp256k1.Fn, h *secp256k1.Point) secp256k1.Point {
	var commitment, hPow secp256k1.Point
	commitment.BaseExp(value)
	hPow.Scale(h, decommitment)
	commitment.Add(&commitment, &hPow)
	return commitment
}