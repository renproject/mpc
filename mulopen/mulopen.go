package mulopen

import (
	"fmt"

	"github.com/renproject/mpc/mulopen/mulzkp"
	"github.com/renproject/mpc/params"
	"github.com/renproject/secp256k1"
	"github.com/renproject/shamir"
)

// A MulOpener is a state machine that implements the multiply and open
// protocol.
type MulOpener struct {
	shareBufs []shamir.Shares

	batchSize, k                                           uint32
	aCommitmentBatch, bCommitmentBatch, rzgCommitmentBatch []shamir.Commitment

	indices []secp256k1.Fn
	h       secp256k1.Point
}

// New returns a new MulOpener state machine along with the initial message
// that is to be broadcast to the other parties. The state machine will handle
// this message before being returned.
func New(
	aShareBatch, bShareBatch, rzgShareBatch shamir.VerifiableShares,
	aCommitmentBatch, bCommitmentBatch, rzgCommitmentBatch []shamir.Commitment,
	indices []secp256k1.Fn, h secp256k1.Point,
) (MulOpener, []Message) {
	if !params.ValidPedersenParameter(h) {
		panic("insecure choice of pedersen parameter")
	}
	batchSize := len(aShareBatch)
	if batchSize < 1 {
		panic(fmt.Sprintf("batch size should be at least 1: got %v", batchSize))
	}
	if len(bShareBatch) != batchSize ||
		len(rzgShareBatch) != batchSize ||
		len(aCommitmentBatch) != batchSize ||
		len(bCommitmentBatch) != batchSize ||
		len(rzgCommitmentBatch) != batchSize {
		panic("inconsistent batch size")
	}
	k := aCommitmentBatch[0].Len()
	if k < 2 {
		panic(fmt.Sprintf("k should be at least 2: got %v", k))
	}
	for i := 0; i < batchSize; i++ {
		if aCommitmentBatch[i].Len() != k || bCommitmentBatch[i].Len() != k {
			panic("inconsistent threshold (k)")
		}
	}
	for _, com := range rzgCommitmentBatch {
		if com.Len() != 2*k-1 {
			panic(fmt.Sprintf("incorrect rzg k: expected 2*%v-1 = %v, got %v", k, 2*k-1, com.Len()))
		}
	}

	index := aShareBatch[0].Share.Index
	for _, aShare := range aShareBatch {
		if !aShare.Share.Index.Eq(&index) {
			panic(fmt.Sprintf("incorrect a_index: expected %v, got %v", index, aShare.Share.Index))
		}
	}
	for _, bShare := range bShareBatch {
		if !bShare.Share.Index.Eq(&index) {
			panic(fmt.Sprintf("incorrect b_index: expected %v, got %v", index, bShare.Share.Index))
		}
	}
	for _, rzgShare := range rzgShareBatch {
		if !rzgShare.Share.Index.Eq(&index) {
			panic(fmt.Sprintf("incorrect z_index: expected %v, got %v", index, rzgShare.Share.Index))
		}
	}

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
		aShareCommitment := pedersenCommit(&aShareBatch[i].Share.Value, &aShareBatch[i].Decommitment, &h)
		bShareCommitment := pedersenCommit(&bShareBatch[i].Share.Value, &bShareBatch[i].Decommitment, &h)
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

	// Handle own message immediately.
	output, err := mulopener.HandleShareBatch(messageBatch)
	if output != nil || err != nil {
		panic("unexpected result handling own message")
	}

	return mulopener, messageBatch
}

// HandleShareBatch applies a state transition upon receiveing the given shares
// from another party during the open in the multiply and open protocol. Once
// enough valid shares have been received to reconstruct, the output, i.e. the
// product of the two input secrets, is computed and returned. If not enough
// shares have been received, the return value will be nil. If the message
// batch id invalid in any way, an error will be returned along with a nil
// value.
func (mulopener *MulOpener) HandleShareBatch(messageBatch []Message) ([]secp256k1.Fn, error) {
	if uint32(len(messageBatch)) != mulopener.batchSize {
		return nil, ErrIncorrectBatchSize
	}
	index := messageBatch[0].VShare.Share.Index
	{
		exists := false
		for i := range mulopener.indices {
			if index.Eq(&mulopener.indices[i]) {
				exists = true
				break
			}
		}
		if !exists {
			return nil, ErrInvalidIndex
		}
	}
	for i := range messageBatch {
		if !messageBatch[i].VShare.Share.IndexEq(&index) {
			return nil, ErrInconsistentShares
		}
	}
	for _, s := range mulopener.shareBufs[0] {
		if s.IndexEq(&index) {
			return nil, ErrDuplicateIndex
		}
	}

	for i := uint32(0); i < mulopener.batchSize; i++ {
		aShareCommitment := polyEvalPoint(mulopener.aCommitmentBatch[i], index)
		bShareCommitment := polyEvalPoint(mulopener.bCommitmentBatch[i], index)
		if !mulzkp.Verify(
			&mulopener.h, &aShareCommitment, &bShareCommitment, &messageBatch[i].Commitment,
			&messageBatch[i].Proof,
		) {
			return nil, ErrInvalidZKP
		}
		var shareCommitment secp256k1.Point
		rzgShareCommitment := polyEvalPoint(mulopener.rzgCommitmentBatch[i], index)
		shareCommitment.Add(&messageBatch[i].Commitment, &rzgShareCommitment)

		com := pedersenCommit(
			&messageBatch[i].VShare.Share.Value, &messageBatch[i].VShare.Decommitment,
			&mulopener.h,
		)
		if !shareCommitment.Eq(&com) {
			return nil, ErrInvalidShares
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
