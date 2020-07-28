package open

import (
	"fmt"
	"math/rand"
	"reflect"

	"github.com/renproject/secp256k1"
	"github.com/renproject/shamir"
	"github.com/renproject/shamir/shamirutil"
	"github.com/renproject/surge"
)

// Opener is a state machine that handles the collecting of verifiable secret
// shares and the reconstruction (if possible) of these shares to yield the
// underlying secret. The state machine is designed to be resettable: the same
// instance of a Opener can be used to open many different sharings, as opposed
// to being one time use. However, each instance of the state machine is
// specific to a given set of indices of the parties (i.e. the set of possible
// indices that shares can have) and system parameter for the Pedersen
// commitments used in the verifiable secret sharing scheme.
//
// The state machine states and transitions are as follows. At a high level,
// the states need to capture:
//
//	- The current sharing instance
//	- Whether or not there are enough valid shares to perform a reconstruction
//
// The information needed for the sharing instance is captured by the
// commitment `c` for the verifiable secret sharing instance, and the
// associated reconstruction threshold `k`. The information that determines
// whether it is possible to reconstruct is simply the number of valid shares
// received `i`, and also `k`. The number of shares received is maintained
// indirectly by storing all valid shares received, the latter of course need
// to be saved in order to be able to perform a reconstruction. These three
// variables, `c`, `k` and `i`, represent the entirety of the state needed for
// the state transition logic. It is however convenient to group subsets of the
// possible states into higher level states that reflect the higher level
// operation of the state machine. The two main higher level states are Waiting
// and Done. Additionally, there is an additional state Uninitialised that the
// state machine is in upon construction and once moving to one of the other
// two states will never be in this state again. To summarise, the high level
// states (parameterised by the relevant parts of the lower level state) are
//
//	1. Uninitialised
//	2. Waiting(`c`, `k`, `i`)
//	3. Done(`c`)
//
// Now we consider the state transitions. There are only two triggers for state
// transitions:
//
//	- Receiving a new share
//	- Resetting for a new sharing instance
//
// The Opener state machine functions in batches, and has a batch size
// associated with it. The number of shares it receives every time MUST be
// equal to the batch size. When it has received threshold number of sets
// of shares, it reconstructs all the secrets, a total of batch size in number.
//
// All of the state transitions are listed in the following and are grouped by
// the current state. The condition Valid('c') for a share means that the share
// is valid with repect to the commitment `c` and also that the index for the
// share does not equal any of the indices in the current set of valid shares
// and that it is in the list of indices that the state machine was constructed
// with.
//
//	- Uninitialised
//		- New instance(`c`, `k`) 	-> Waiting(`c`, `k`, `0`)
//		- Otherwise 			-> Do nothing
//	- Waiting(`c`, `k`, `k-1`)
//		- New instance(`c`, `k`) 	-> Waiting(`c`, `k`, `0`)
//		- Share, Valid(`c`) 		-> Done(`c`)
//		- Otherwise 			-> Do nothing
//	- Waiting(`c`, `k`, `i`), `i` < `k-1`
//		- New instance(`c`, `k`) 	-> Waiting(`c`, `k`, `0`)
//		- Share, Valid(`c`) 		-> Waiting(`c`, `k`, `i+1`)
//		- Otherwise 			-> Do nothing
//	- Done(`c`)
//		- New instance(`c`, `k`) 	-> Waiting(`c`, `k`, `0`)
//		- Otherwise 			-> Do nothing
//
// Alternatively, the state transitions can be grouped by message.
//
//	- New instance(`c`, `k`)
//		- Any -> Waiting(`c`, `k`, `0`)
//	- Share, Valid(`c`)
//		- Waiting(`c`, `k`, `k-1`) 		-> Done(`c`)
//		- Waiting(`c`, `k`, `i`), `i` < `k-1` 	-> Waiting(`c`, `k`, `i+1`)
type Opener struct {
	// State
	shareBufs []shamir.VerifiableShares

	// Instance parameters
	batchSize       uint32
	commitmentBatch []shamir.Commitment

	// Global parameters
	indices []secp256k1.Fn
	h       secp256k1.Point
}

// K returns the reconstruction threshold for the current sharing instance.
func (opener Opener) K() int {
	return opener.commitmentBatch[0].Len()
}

// I returns the current number of valid shares that the opener has received.
func (opener Opener) I() int {
	return len(opener.shareBufs[0])
}

// New returns a new instance of the Opener state machine for the given set of
// indices and the given Pedersen commitment system parameter. The state
// machine begins in the Uninitialised state.
func New(b uint32, indices []secp256k1.Fn, h secp256k1.Point) Opener {
	shareBufs := make([]shamir.VerifiableShares, b)
	for i := range shareBufs {
		shareBufs[i] = shamir.VerifiableShares{}
	}
	commitmentBatch := make([]shamir.Commitment, b)
	for i := range commitmentBatch {
		commitmentBatch[i] = shamir.Commitment{}
	}

	return Opener{
		shareBufs:       shareBufs,
		batchSize:       b,
		commitmentBatch: commitmentBatch,
		indices:         indices,
		h:               h,
	}
}

// HandleShareBatch handles the state transition logic upon receiving a set of
// shares, and returns a ShareEvent that describes the outcome of the state
// transition.  See the documentation for the different ShareEvent possiblities
// for their significance.
func (opener *Opener) HandleShareBatch(shareBatch shamir.VerifiableShares) (
	ShareEvent,
	[]secp256k1.Fn,
	[]secp256k1.Fn,
) {
	// Do nothing when in the Uninitialised state. This can be checked by
	// seeing if k is zero, as Resetting the state machine can only be done if
	// k is greater than 0.
	if opener.K() <= 0 {
		return Ignored, nil, nil
	}

	// The number of shares should equal the batch size.
	if len(shareBatch) != int(opener.batchSize) {
		return Ignored, nil, nil
	}

	// All shares should have the same index.
	for i := 1; i < len(shareBatch); i++ {
		if !shareBatch[i].Share.IndexEq(&shareBatch[0].Share.Index) {
			return InvalidShares, nil, nil
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
			return IndexOutOfRange, nil, nil
		}
	}

	// There should be no duplicate indices.
	for _, s := range opener.shareBufs[0] {
		if s.Share.IndexEq(&index) {
			return IndexDuplicate, nil, nil
		}
	}

	// No shares should be invalid. If even a single share is invalid, we mark
	// the entire set of shares to be invalid.
	for i, share := range shareBatch {
		if !shamir.IsValid(opener.h, &opener.commitmentBatch[i], &share) {
			return InvalidShares, nil, nil
		}
	}

	// At this stage we know that the shares are allowed to be added to the
	// respective buffers.
	for i := 0; i < int(opener.batchSize); i++ {
		opener.shareBufs[i] = append(opener.shareBufs[i], shareBatch[i])
	}

	// If we have just added the kth share, we can reconstruct.
	numShares := len(opener.shareBufs[0])
	if numShares == opener.K() {
		secrets := make([]secp256k1.Fn, opener.batchSize)
		decommitments := make([]secp256k1.Fn, opener.batchSize)
		shareBuf := make(shamir.Shares, numShares)
		for i := 0; i < int(opener.batchSize); i++ {
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

		return Done, secrets, decommitments
	}

	// At this stage we have added the shares to the respective buffers
	// but we were not yet able to reconstruct the secrets.
	return SharesAdded, nil, nil
}

// NewInstance initialises the opener for a new instance of the open algorithm,
// corresponding to the given Pedersen commitments. See the documentation for
// the different ResetEvent possiblities for their significance.
func (opener *Opener) NewInstance(commitmentBatch []shamir.Commitment) ResetEvent {
	if len(commitmentBatch) != int(opener.batchSize) {
		panic(fmt.Sprintf(
			"length of commitmentBatch should be: %v, got: %v",
			opener.batchSize, len(commitmentBatch),
		))
	}

	// Make sure each commitment is for the same threshold and that that
	// threshold is greater than 0
	c0Len := commitmentBatch[0].Len()
	if c0Len < 1 {
		panic(fmt.Sprintf("k must be greater than 0, got: %v", c0Len))
	}
	for _, c := range commitmentBatch[1:] {
		if c.Len() != c0Len {
			panic(fmt.Sprintf("k must be equal for all commitments in the batch"))
		}
	}

	var ret ResetEvent
	if len(opener.shareBufs[0]) < opener.K() {
		ret = Aborted
	} else {
		ret = Reset
	}

	for i := 0; i < int(opener.batchSize); i++ {
		opener.shareBufs[i] = opener.shareBufs[i][:0]
		opener.commitmentBatch[i].Set(commitmentBatch[i])
	}

	return ret
}

// Generate implements the quick.Generator interface.
func (opener Opener) Generate(_ *rand.Rand, _ int) reflect.Value {
	b := rand.Intn(20)
	indices := shamirutil.RandomIndices(rand.Intn(20))
	h := secp256k1.RandomPoint()
	return reflect.ValueOf(New(uint32(b), indices, h))
}

// SizeHint implements the surge.SizeHinter interface.
func (opener Opener) SizeHint() int {
	return surge.SizeHint(opener.batchSize) +
		surge.SizeHint(opener.commitmentBatch) +
		surge.SizeHint(opener.shareBufs) +
		opener.h.SizeHint() +
		surge.SizeHint(opener.indices)
}

// Marshal implements the surge.Marshaler interface.
func (opener Opener) Marshal(buf []byte, rem int) ([]byte, int, error) {
	buf, rem, err := surge.Marshal(opener.shareBufs, buf, rem)
	if err != nil {
		return buf, rem, fmt.Errorf("marshaling share buffers: %v", err)
	}
	buf, rem, err = surge.MarshalU32(opener.batchSize, buf, rem)
	if err != nil {
		return buf, rem, fmt.Errorf("marshaling batchSize: %v", err)
	}
	buf, rem, err = surge.Marshal(opener.commitmentBatch, buf, rem)
	if err != nil {
		return buf, rem, fmt.Errorf("marshaling commitmentBatch: %v", err)
	}
	buf, rem, err = opener.h.Marshal(buf, rem)
	if err != nil {
		return buf, rem, fmt.Errorf("marshaling h: %v", err)
	}
	buf, rem, err = surge.Marshal(opener.indices, buf, rem)
	if err != nil {
		return buf, rem, fmt.Errorf("marshaling indices: %v", err)
	}
	return buf, rem, nil
}

// Unmarshal implements the surge.Unmarshaler interface.
func (opener *Opener) Unmarshal(buf []byte, rem int) ([]byte, int, error) {
	buf, rem, err := surge.Unmarshal(&opener.shareBufs, buf, rem)
	if err != nil {
		return buf, rem, fmt.Errorf("unmarshaling share buffers: %v", err)
	}
	buf, rem, err = surge.UnmarshalU32(&opener.batchSize, buf, rem)
	if err != nil {
		return buf, rem, fmt.Errorf("unmarshaling batchSize: %v", err)
	}
	buf, rem, err = surge.Unmarshal(&opener.commitmentBatch, buf, rem)
	if err != nil {
		return buf, rem, fmt.Errorf("unmarshaling commitment: %v", err)
	}
	buf, rem, err = opener.h.Unmarshal(buf, rem)
	if err != nil {
		return buf, rem, fmt.Errorf("unmarshaling h: %v", err)
	}
	buf, rem, err = surge.Unmarshal(&opener.indices, buf, rem)
	if err != nil {
		return buf, rem, fmt.Errorf("unmarshaling indices: %v", err)
	}
	return buf, rem, nil
}
