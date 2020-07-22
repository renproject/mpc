package rkpg

import (
	"math/rand"
	"reflect"

	"github.com/renproject/secp256k1"
	"github.com/renproject/shamir/rs"
	"github.com/renproject/surge"
)

// Params represent parameters for an instance of the RKPG protocol. This will
// remain constant for the duration of the instance of RKPG.
type Params struct {
	n, k, b  int32
	h        secp256k1.Point
	arrIndex map[secp256k1.Fn]int32
	decoder  rs.Decoder
}

// CreateParams constructs a new parameters object.
func CreateParams(k, b int, h secp256k1.Point, indices []secp256k1.Fn) Params {
	n := len(indices)
	arrIndex := make(map[secp256k1.Fn]int32, n)
	for i, index := range indices {
		arrIndex[index] = int32(i)
	}
	decoder := rs.NewDecoder(indices, k)

	return Params{
		n: int32(n), k: int32(k), b: int32(b),
		h:        h,
		arrIndex: arrIndex,
		decoder:  decoder,
	}
}

// Generate implements the quick.Generator interface.
func (params Params) Generate(rand *rand.Rand, size int) reflect.Value {
	n := rand.Int31()
	k := rand.Int31()
	b := rand.Int31()
	h := secp256k1.RandomPoint()
	arrIndex := make(map[secp256k1.Fn]int32, size/2)
	for i := 0; i < size; i++ {
		arrIndex[secp256k1.RandomFn()] = rand.Int31()
	}
	decoder := rs.Decoder{}.Generate(rand, size/2).Interface().(rs.Decoder)
	ps := Params{
		n: n, k: k, b: b,
		h:        h,
		arrIndex: arrIndex,
		decoder:  decoder,
	}
	return reflect.ValueOf(ps)
}

// SizeHint implements the surge.SizeHinter interface.
func (params Params) SizeHint() int {
	return surge.SizeHint(params.n) +
		surge.SizeHint(params.k) +
		surge.SizeHint(params.b) +
		params.h.SizeHint() +
		surge.SizeHint(params.arrIndex) +
		params.decoder.SizeHint()
}

// Marshal implements the surge.Marshaler interface.
func (params Params) Marshal(buf []byte, rem int) ([]byte, int, error) {
	buf, rem, err := surge.MarshalI32(params.n, buf, rem)
	if err != nil {
		return buf, rem, err
	}
	buf, rem, err = surge.MarshalI32(params.k, buf, rem)
	if err != nil {
		return buf, rem, err
	}
	buf, rem, err = surge.MarshalI32(params.b, buf, rem)
	if err != nil {
		return buf, rem, err
	}
	buf, rem, err = params.h.Marshal(buf, rem)
	if err != nil {
		return buf, rem, err
	}
	buf, rem, err = surge.Marshal(params.arrIndex, buf, rem)
	if err != nil {
		return buf, rem, err
	}
	return params.decoder.Marshal(buf, rem)
}

// Unmarshal implements the surge.Unmarshaler interface.
func (params *Params) Unmarshal(buf []byte, rem int) ([]byte, int, error) {
	buf, rem, err := surge.UnmarshalI32(&params.n, buf, rem)
	if err != nil {
		return buf, rem, err
	}
	buf, rem, err = surge.UnmarshalI32(&params.k, buf, rem)
	if err != nil {
		return buf, rem, err
	}
	buf, rem, err = surge.UnmarshalI32(&params.b, buf, rem)
	if err != nil {
		return buf, rem, err
	}
	buf, rem, err = params.h.Unmarshal(buf, rem)
	if err != nil {
		return buf, rem, err
	}
	buf, rem, err = surge.Unmarshal(&params.arrIndex, buf, rem)
	if err != nil {
		return buf, rem, err
	}
	return params.decoder.Unmarshal(buf, rem)
}
