package mulopen

import (
	"math/rand"
	"reflect"

	"github.com/renproject/mpc/mulopen/mulzkp"
	"github.com/renproject/secp256k1"
	"github.com/renproject/shamir"
	"github.com/renproject/shamir/shamirutil"
	"github.com/renproject/surge"
)

// SizeHint implements the surge.SizeHinter interface.
func (mulopener MulOpener) SizeHint() int {
	return surge.SizeHint(mulopener.shareBufs) +
		surge.SizeHint(mulopener.batchSize) +
		surge.SizeHint(mulopener.k) +
		surge.SizeHint(mulopener.aCommitmentBatch) +
		surge.SizeHint(mulopener.bCommitmentBatch) +
		surge.SizeHint(mulopener.rzgCommitmentBatch) +
		surge.SizeHint(mulopener.indices) +
		mulopener.h.SizeHint()
}

// Marshal implements the surge.Marshaler interface.
func (mulopener MulOpener) Marshal(buf []byte, rem int) ([]byte, int, error) {
	buf, rem, err := surge.Marshal(mulopener.shareBufs, buf, rem)
	if err != nil {
		return buf, rem, err
	}
	buf, rem, err = surge.MarshalU32(mulopener.batchSize, buf, rem)
	if err != nil {
		return buf, rem, err
	}
	buf, rem, err = surge.MarshalU32(mulopener.k, buf, rem)
	if err != nil {
		return buf, rem, err
	}
	buf, rem, err = surge.Marshal(mulopener.aCommitmentBatch, buf, rem)
	if err != nil {
		return buf, rem, err
	}
	buf, rem, err = surge.Marshal(mulopener.bCommitmentBatch, buf, rem)
	if err != nil {
		return buf, rem, err
	}
	buf, rem, err = surge.Marshal(mulopener.rzgCommitmentBatch, buf, rem)
	if err != nil {
		return buf, rem, err
	}
	buf, rem, err = surge.Marshal(mulopener.indices, buf, rem)
	if err != nil {
		return buf, rem, err
	}
	return mulopener.h.Marshal(buf, rem)
}

// Unmarshal implements the surge.Unmarshaler interface.
func (mulopener *MulOpener) Unmarshal(buf []byte, rem int) ([]byte, int, error) {
	buf, rem, err := surge.Unmarshal(&mulopener.shareBufs, buf, rem)
	if err != nil {
		return buf, rem, err
	}
	buf, rem, err = surge.UnmarshalU32(&mulopener.batchSize, buf, rem)
	if err != nil {
		return buf, rem, err
	}
	buf, rem, err = surge.UnmarshalU32(&mulopener.k, buf, rem)
	if err != nil {
		return buf, rem, err
	}
	buf, rem, err = surge.Unmarshal(&mulopener.aCommitmentBatch, buf, rem)
	if err != nil {
		return buf, rem, err
	}
	buf, rem, err = surge.Unmarshal(&mulopener.bCommitmentBatch, buf, rem)
	if err != nil {
		return buf, rem, err
	}
	buf, rem, err = surge.Unmarshal(&mulopener.rzgCommitmentBatch, buf, rem)
	if err != nil {
		return buf, rem, err
	}
	buf, rem, err = surge.Unmarshal(&mulopener.indices, buf, rem)
	if err != nil {
		return buf, rem, err
	}
	return mulopener.h.Unmarshal(buf, rem)
}

// Generate implements the quick.Generator interface.
func (mulopener MulOpener) Generate(_ *rand.Rand, size int) reflect.Value {
	size /= 5
	n := rand.Intn(size/2) + 1
	k := uint32(rand.Intn(size/2) + 2)
	batchSize := uint32(size) / k
	if batchSize == 0 {
		batchSize++
	}
	shareBufs := make([]shamir.Shares, batchSize)
	numReceived := rand.Intn(n)
	for i := range shareBufs {
		shareBufs[i] = shamir.Shares{}
		for j := 0; j < numReceived; j++ {
			shareBufs[i] = append(shareBufs[i],
				shamir.Share{
					Index: secp256k1.RandomFn(),
					Value: secp256k1.RandomFn(),
				},
			)
		}
	}
	aCommitmentBatch := make([]shamir.Commitment, batchSize)
	bCommitmentBatch := make([]shamir.Commitment, batchSize)
	rzgCommitmentBatch := make([]shamir.Commitment, batchSize)
	for i := uint32(0); i < batchSize; i++ {
		for j := uint32(0); j < k; j++ {
			aCommitmentBatch[i].Append(secp256k1.RandomPoint())
			bCommitmentBatch[i].Append(secp256k1.RandomPoint())
			rzgCommitmentBatch[i].Append(secp256k1.RandomPoint())
		}
	}
	indices := shamirutil.RandomIndices(n)
	h := secp256k1.RandomPoint()
	mo := MulOpener{
		shareBufs,
		batchSize,
		k,
		aCommitmentBatch,
		bCommitmentBatch,
		rzgCommitmentBatch,
		indices,
		h,
	}
	return reflect.ValueOf(mo)
}

// SizeHint implements the surge.SizeHinter interface.
func (msg Message) SizeHint() int {
	return msg.VShare.SizeHint() +
		msg.Commitment.SizeHint() +
		msg.Proof.SizeHint()
}

// Marshal implements the surge.Marshaler interface.
func (msg Message) Marshal(buf []byte, rem int) ([]byte, int, error) {
	buf, rem, err := msg.VShare.Marshal(buf, rem)
	if err != nil {
		return buf, rem, err
	}
	buf, rem, err = msg.Commitment.Marshal(buf, rem)
	if err != nil {
		return buf, rem, err
	}
	return msg.Proof.Marshal(buf, rem)
}

// Unmarshal implements the surge.Unmarshaler interface.
func (msg *Message) Unmarshal(buf []byte, rem int) ([]byte, int, error) {
	buf, rem, err := msg.VShare.Unmarshal(buf, rem)
	if err != nil {
		return buf, rem, err
	}
	buf, rem, err = msg.Commitment.Unmarshal(buf, rem)
	if err != nil {
		return buf, rem, err
	}
	return msg.Proof.Unmarshal(buf, rem)
}

// Generate implements the quick.Generator interface.
func (msg Message) Generate(rand *rand.Rand, size int) reflect.Value {
	share := shamir.VerifiableShare{
		Share: shamir.Share{
			Index: secp256k1.RandomFn(),
			Value: secp256k1.RandomFn(),
		},
		Decommitment: secp256k1.RandomFn(),
	}
	com := secp256k1.RandomPoint()
	proof := mulzkp.Proof{}.Generate(rand, size).Interface().(mulzkp.Proof)
	m := Message{
		VShare:     share,
		Commitment: com,
		Proof:      proof,
	}
	return reflect.ValueOf(m)
}
