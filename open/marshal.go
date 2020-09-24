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

// Generate implements the quick.Generator interface.
func (opener Opener) Generate(_ *rand.Rand, size int) reflect.Value {
	// A curve point is more or less 3 field elements that contain 4 uint64s.
	size /= 12

	k := rand.Intn(size) + 1
	b := size/k + 1
	commitmentBatch := make([]shamir.Commitment, b)
	for i := range commitmentBatch {
		commitmentBatch[i] = shamir.NewCommitmentWithCapacity(k)
		for j := 0; j < k; j++ {
			commitmentBatch[i] = append(commitmentBatch[i], secp256k1.RandomPoint())
		}
	}
	indices := shamirutil.RandomIndices(rand.Intn(20))
	h := secp256k1.RandomPoint()
	return reflect.ValueOf(New(commitmentBatch, indices, h))
}

// SizeHint implements the surge.SizeHinter interface.
func (opener Opener) SizeHint() int {
	return surge.SizeHint(opener.commitmentBatch) +
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
