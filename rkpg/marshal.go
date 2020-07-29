package rkpg

import (
	"math/rand"
	"reflect"

	"github.com/renproject/secp256k1"
	"github.com/renproject/shamir/rs"
	"github.com/renproject/surge"
)

// Generate implements the quick.Generator interface.
func (rkpger RKPGer) Generate(rand *rand.Rand, size int) reflect.Value {
	size /= 4
	state := State{}.Generate(rand, size).Interface().(State)
	points := make([]secp256k1.Point, size/4)
	for i := range points {
		points[i] = secp256k1.RandomPoint()
	}
	decoder := rs.Decoder{}.Generate(rand, size).Interface().(rs.Decoder)
	indices := make([]secp256k1.Fn, size/4)
	for i := range indices {
		indices[i] = secp256k1.RandomFn()
	}
	r := RKPGer{
		state:   state,
		k:       rand.Int31(),
		points:  points,
		decoder: decoder,
		indices: indices,
		h:       secp256k1.RandomPoint(),
	}
	return reflect.ValueOf(r)
}

// SizeHint implements the surge.SizeHinter interface.
func (rkpger RKPGer) SizeHint() int {
	return rkpger.state.SizeHint() +
		surge.SizeHint(rkpger.k) +
		surge.SizeHint(rkpger.points) +
		rkpger.decoder.SizeHint() +
		surge.SizeHint(rkpger.indices) +
		rkpger.h.SizeHint()
}

// Marshal implements the surge.Marshaler interface.
func (rkpger RKPGer) Marshal(buf []byte, rem int) ([]byte, int, error) {
	buf, rem, err := rkpger.state.Marshal(buf, rem)
	if err != nil {
		return buf, rem, err
	}
	buf, rem, err = surge.MarshalI32(rkpger.k, buf, rem)
	if err != nil {
		return buf, rem, err
	}
	buf, rem, err = surge.Marshal(rkpger.points, buf, rem)
	if err != nil {
		return buf, rem, err
	}
	buf, rem, err = rkpger.decoder.Marshal(buf, rem)
	if err != nil {
		return buf, rem, err
	}
	buf, rem, err = surge.Marshal(rkpger.indices, buf, rem)
	if err != nil {
		return buf, rem, err
	}
	return rkpger.h.Marshal(buf, rem)
}

// Unmarshal implements the surge.Unmarshaler interface.
func (rkpger *RKPGer) Unmarshal(buf []byte, rem int) ([]byte, int, error) {
	buf, rem, err := rkpger.state.Unmarshal(buf, rem)
	if err != nil {
		return buf, rem, err
	}
	buf, rem, err = surge.UnmarshalI32(&rkpger.k, buf, rem)
	if err != nil {
		return buf, rem, err
	}
	buf, rem, err = surge.Unmarshal(&rkpger.points, buf, rem)
	if err != nil {
		return buf, rem, err
	}
	buf, rem, err = rkpger.decoder.Unmarshal(buf, rem)
	if err != nil {
		return buf, rem, err
	}
	buf, rem, err = surge.Unmarshal(&rkpger.indices, buf, rem)
	if err != nil {
		return buf, rem, err
	}
	return rkpger.h.Unmarshal(buf, rem)
}
