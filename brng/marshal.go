package brng

import (
	"fmt"
	"math/rand"
	"reflect"

	"github.com/renproject/secp256k1"
	"github.com/renproject/surge"
)

// Generate implements the quick.Generator interface.
func (brnger BRNGer) Generate(_ *rand.Rand, _ int) reflect.Value {
	batchSize := rand.Uint32()
	h := secp256k1.RandomPoint()
	return reflect.ValueOf(BRNGer{batchSize, h})
}

// SizeHint implements the surge.SizeHinter interface.
func (brnger BRNGer) SizeHint() int {
	return surge.SizeHint(brnger.batchSize) +
		brnger.h.SizeHint()
}

// Marshal implements the surge.Marshaler interface.
func (brnger BRNGer) Marshal(buf []byte, rem int) ([]byte, int, error) {
	buf, rem, err := surge.MarshalU32(uint32(brnger.batchSize), buf, rem)
	if err != nil {
		return buf, rem, fmt.Errorf("marshaling batchSize: %v", err)
	}
	buf, rem, err = brnger.h.Marshal(buf, rem)
	if err != nil {
		return buf, rem, fmt.Errorf("marshaling h: %v", err)
	}
	return buf, rem, nil
}

// Unmarshal implements the surge.Unmarshaler interface.
func (brnger *BRNGer) Unmarshal(buf []byte, rem int) ([]byte, int, error) {
	buf, rem, err := surge.UnmarshalU32(&brnger.batchSize, buf, rem)
	if err != nil {
		return buf, rem, fmt.Errorf("unmarshaling batchSize: %v", err)
	}
	buf, rem, err = brnger.h.Unmarshal(buf, rem)
	if err != nil {
		return buf, rem, fmt.Errorf("unmarshaling h: %v", err)
	}
	return buf, rem, nil
}
