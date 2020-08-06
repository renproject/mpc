package inv

import (
	"github.com/renproject/mpc/mulopen"
	"github.com/renproject/secp256k1"
	"github.com/renproject/shamir"
)

type Inverter struct {
	mulopener        mulopen.MulOpener
	rShareBatch      shamir.VerifiableShares
	rCommitmentBatch []shamir.Commitment
}

func New(
	aShareBatch, rShareBatch, rzgShareBatch shamir.VerifiableShares,
	aCommitmentBatch, rCommitmentBatch, rzgCommitmentBatch []shamir.Commitment,
	indices []secp256k1.Fn, h secp256k1.Point,
) (Inverter, []mulopen.Message) {
	rShareBatchCopy := make(shamir.VerifiableShares, len(rShareBatch))
	rCommitmentBatchCopy := make([]shamir.Commitment, len(rCommitmentBatch))
	copy(rShareBatchCopy, rShareBatch)
	copy(rCommitmentBatchCopy, rCommitmentBatch)
	mulopener, messages := mulopen.New(
		aShareBatch, rShareBatch, rzgShareBatch,
		aCommitmentBatch, rCommitmentBatch, rzgCommitmentBatch,
		indices, h,
	)
	inverter := Inverter{
		mulopener:        mulopener,
		rShareBatch:      rShareBatchCopy,
		rCommitmentBatch: rCommitmentBatchCopy,
	}
	return inverter, messages
}

func (inverter *Inverter) HandleMulOpenMessageBatch(messageBatch []mulopen.Message) (
	shamir.VerifiableShares, []shamir.Commitment, error,
) {
	output, err := inverter.mulopener.HandleShareBatch(messageBatch)
	if err != nil {
		return nil, nil, err
	}
	if output != nil {
		var inv secp256k1.Fn
		invShares := make(shamir.VerifiableShares, len(inverter.rShareBatch))
		invCommitments := make([]shamir.Commitment, len(inverter.rCommitmentBatch))
		for i := range output {
			invCommitments[i] = shamir.NewCommitmentWithCapacity(inverter.rCommitmentBatch[0].Len())
			inv.Inverse(&output[i])
			invShares[i].Scale(&inverter.rShareBatch[i], &inv)
			invCommitments[i].Scale(inverter.rCommitmentBatch[i], &inv)
		}
		return invShares, invCommitments, nil
	}
	return nil, nil, nil
}
