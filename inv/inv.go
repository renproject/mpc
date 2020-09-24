package inv

import (
	"github.com/renproject/mpc/mulopen"
	"github.com/renproject/secp256k1"
	"github.com/renproject/shamir"
)

// An Inverter is a state machine that implements the inversion protocol.
type Inverter struct {
	mulopener        mulopen.MulOpener
	rShareBatch      shamir.VerifiableShares
	rCommitmentBatch []shamir.Commitment
}

// New returns a new Inverter state machine along with the initial message that
// is to be broadcast to the other parties. The state machine will handle this
// message before being returned.
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

// HandleMulOpenMessageBatch applies a state transition upon receiveing the
// given shares from another party during the  multiply and open step in the
// inversion protocol. Once enough valid messages have been received to
// complete the inversion protocol, the output, i.e.  shares and commitments
// that correspond to the multiplicative inverse of the input secret, is
// computed and returned. If not enough messages have been received, the return
// value will be nil. If the message batch is invalid in any way, an error will
// be returned along with a nil value.
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
