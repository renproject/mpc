package inv

import (
	"math/rand"
	"reflect"

	"github.com/renproject/mpc/mulopen"
	"github.com/renproject/secp256k1"
	"github.com/renproject/shamir"
	"github.com/renproject/surge"
)

// SizeHint implements the surge.SizeHinter interface.
func (inverter Inverter) SizeHint() int {
	return inverter.mulopener.SizeHint() +
		surge.SizeHint(inverter.rShareBatch) +
		surge.SizeHint(inverter.rCommitmentBatch)
}

// Marshal implements the surge.Marshaler interface.
func (inverter Inverter) Marshal(buf []byte, rem int) ([]byte, int, error) {
	buf, rem, err := inverter.mulopener.Marshal(buf, rem)
	if err != nil {
		return buf, rem, err
	}
	buf, rem, err = surge.Marshal(inverter.rShareBatch, buf, rem)
	if err != nil {
		return buf, rem, err
	}
	return surge.Marshal(inverter.rCommitmentBatch, buf, rem)
}

// Unmarshal implements the surge.Unmarshaler interface.
func (inverter *Inverter) Unmarshal(buf []byte, rem int) ([]byte, int, error) {
	buf, rem, err := inverter.mulopener.Unmarshal(buf, rem)
	if err != nil {
		return buf, rem, err
	}
	buf, rem, err = surge.Unmarshal(&inverter.rShareBatch, buf, rem)
	if err != nil {
		return buf, rem, err
	}
	return surge.Unmarshal(&inverter.rCommitmentBatch, buf, rem)
}

// Generate implements the quick.Generator interface.
func (inverter Inverter) Generate(rand *rand.Rand, size int) reflect.Value {
	size /= 4
	b := rand.Intn(size/2) + 1
	mulopener := mulopen.MulOpener{}.Generate(rand, size).Interface().(mulopen.MulOpener)
	rShareBatch := make(shamir.VerifiableShares, b)
	for i := 0; i < b; i++ {
		rShareBatch[i] = shamir.VerifiableShare{
			Share: shamir.Share{
				Index: secp256k1.RandomFn(),
				Value: secp256k1.RandomFn(),
			},
			Decommitment: secp256k1.RandomFn(),
		}
	}
	rCommitmentBatch := make([]shamir.Commitment, b)
	for i := 0; i < b; i++ {
		rCommitmentBatch[i] = shamir.Commitment{}.Generate(rand, size/2).Interface().(shamir.Commitment)
	}
	inv := Inverter{
		mulopener,
		rShareBatch,
		rCommitmentBatch,
	}
	return reflect.ValueOf(inv)
}
