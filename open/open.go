package open

import (
	"fmt"

	"github.com/renproject/secp256k1"
	"github.com/renproject/shamir"
)

// Opener is a state machine that is responsible for opening the secret value
// for a verifiable sharing. An instance of this state machine has a specific
// commitment used for share verification, a specific value of the Pedersen
// parameter (known as "h"), and a specific set of indices for the participating
// players.
//
// The description of the state machine is simple: the state is a buffer of
// shares that have been validated. When a share is received, it is checked
// against the commitment and other parameters, and if it is valid it is added
// to the buffer. Once enough shares have been added to the buffer, the secret
// is opened (the required number of shares is known as "k").
//
// The state machine supports batching. If several secrets need to be opened at
// once, instead of having multiple state machines, just one can be used and the
// incoming shares are processed in batches. This batching functionality
// requires the secrets to have all been shared using the same parameters, i.e.
//	- the number of players and their corresponding indices,
//	- the reconstruction threshold (k),
//	- and the Pedersen parameter (h).
type Opener struct {
	// State
	shareBufs []shamir.VerifiableShares

	// Instance parameters
	commitmentBatch []shamir.Commitment

	// Global parameters
	indices []secp256k1.Fn
	h       secp256k1.Point
}

// K returns the number of shares required to open secrets. It assumes that all
// batches require the same number of shares (this assumption is enforced by all
// other methods).
func (opener Opener) K() int {
	return opener.commitmentBatch[0].Len()
}

// BatchSize of the opener.
func (opener Opener) BatchSize() int {
	return len(opener.commitmentBatch)
}

// I returns the current number of valid shares that the opener has received. It
// assumes that all batches contain the same number of shares (this assumption
// is enforced by all other methods).
func (opener Opener) I() int {
	return len(opener.shareBufs[0])
}

// New returns a new instance of the Opener state machine for the given
// Pedersen commitments for the verifiable sharing(s), indices, and Pedersen
// commitment system parameter. The length of the commitment slice determines
// the batch size.
//
// Panics: This function will panic if any of the following conditions are met.
//	- The batch size is less than 1.
//	- The reconstruction threshold (k) is less than 1.
//	- Not all commitments in the batch of commitments have the same
//		reconstruction threshold (k).
func New(commitmentBatch []shamir.Commitment, indices []secp256k1.Fn, h secp256k1.Point) Opener {
	// The batch size must be at least 1.
	b := uint32(len(commitmentBatch))
	if b < 1 {
		panic(fmt.Sprintf("b must be greater than 0, got: %v", b))
	}
	// Make sure each commitment is for the same threshold and that that
	// threshold is greater than 0.
	k := commitmentBatch[0].Len()
	if k < 1 {
		panic(fmt.Sprintf("k must be greater than 0, got: %v", k))
	}
	for _, c := range commitmentBatch[1:] {
		if c.Len() != k {
			panic(fmt.Sprintf("k must be equal for all commitments in the batch"))
		}
	}

	comBatchCopy := make([]shamir.Commitment, b)
	for i := range comBatchCopy {
		comBatchCopy[i].Set(commitmentBatch[i])
	}
	shareBufs := make([]shamir.VerifiableShares, b)
	for i := range shareBufs {
		shareBufs[i] = shamir.VerifiableShares{}
	}
	indicesCopy := make([]secp256k1.Fn, len(indices))
	copy(indicesCopy, indices)

	return Opener{
		shareBufs:       shareBufs,
		commitmentBatch: comBatchCopy,
		indices:         indicesCopy,
		h:               h,
	}
}

// HandleShareBatch handles the state transition logic upon receiving a batch
// of shares. If enough shares have been received to reconstruct the secret,
// then this is returned, otherwise the corresponding return value is nil.
// Similarly, the decommitment (or hiding) value for the verifiable sharing
// will also be returned. If the share batch was invalid in any way, an error
// is returned.
func (opener *Opener) HandleShareBatch(shareBatch shamir.VerifiableShares) (
	[]secp256k1.Fn,
	[]secp256k1.Fn,
	error,
) {
	// The number of shares should equal the batch size.
	if len(shareBatch) != int(opener.BatchSize()) {
		return nil, nil, ErrIncorrectBatchSize
	}

	// All shares should have the same index.
	for i := 1; i < len(shareBatch); i++ {
		if !shareBatch[i].Share.IndexEq(&shareBatch[0].Share.Index) {
			return nil, nil, ErrInvalidShares
		}
	}
	index := shareBatch[0].Share.Index

	// The share index must be in the index set.
	{
		exists := false
		for i := range opener.indices {
			if index.Eq(&opener.indices[i]) {
				exists = true
			}
		}
		if !exists {
			return nil, nil, ErrIndexOutOfRange
		}
	}

	// There should be no duplicate indices.
	for _, s := range opener.shareBufs[0] {
		if s.Share.IndexEq(&index) {
			return nil, nil, ErrDuplicateIndex
		}
	}

	// No shares should be invalid. If even a single share is invalid, we mark
	// the entire set of shares to be invalid.
	for i, share := range shareBatch {
		if !shamir.IsValid(opener.h, &opener.commitmentBatch[i], &share) {
			return nil, nil, ErrInvalidShares
		}
	}

	// At this stage we know that the shares are allowed to be added to the
	// respective buffers.
	for i := 0; i < int(opener.BatchSize()); i++ {
		opener.shareBufs[i] = append(opener.shareBufs[i], shareBatch[i])
	}

	// If we have just added the kth share, we can reconstruct.
	numShares := len(opener.shareBufs[0])
	if numShares == opener.K() {
		secrets := make([]secp256k1.Fn, opener.BatchSize())
		decommitments := make([]secp256k1.Fn, opener.BatchSize())
		shareBuf := make(shamir.Shares, numShares)
		for i := 0; i < int(opener.BatchSize()); i++ {
			for j := range opener.shareBufs[i] {
				shareBuf[j].Index = opener.shareBufs[i][j].Share.Index
				shareBuf[j].Value = opener.shareBufs[i][j].Share.Value
			}
			secrets[i] = shamir.Open(shareBuf)
			for j := range opener.shareBufs[i] {
				shareBuf[j].Index = opener.shareBufs[i][j].Share.Index
				shareBuf[j].Value = opener.shareBufs[i][j].Decommitment
			}
			decommitments[i] = shamir.Open(shareBuf)
		}

		return secrets, decommitments, nil
	}

	// At this stage we have added the shares to the respective buffers
	// but we were not yet able to reconstruct the secrets.
	return nil, nil, nil
}
