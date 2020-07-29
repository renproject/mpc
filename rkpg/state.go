package rkpg

import (
	"math/rand"
	"reflect"

	"github.com/renproject/mpc/rng/rngutil"
	"github.com/renproject/secp256k1"
	"github.com/renproject/surge"
)

// State represents the current state of an instance of the RKPG protocol.
type State struct {
	count         int32
	shareReceived []bool
	buffers       [][]secp256k1.Fn
}

// NewState constructs a new state object for n players with a batch size of b.
func NewState(n, b int) State {
	count := int32(0)
	shareReceived := make([]bool, n)
	buffers := make([][]secp256k1.Fn, b)
	for i := range buffers {
		buffers[i] = make([]secp256k1.Fn, n)
	}

	return State{
		count:         count,
		shareReceived: shareReceived,
		buffers:       buffers,
	}
}

// Generate implements the quick.Generator interface.
func (state State) Generate(_ *rand.Rand, size int) reflect.Value {
	b := rand.Intn(size + 1)
	n := size / rngutil.Max(b, 1)
	count := rand.Int31n(int32(n))
	shareReceived := make([]bool, n)
	for i := range shareReceived {
		shareReceived[i] = rand.Int()&1 == 1
	}
	buffers := make([][]secp256k1.Fn, b)
	for i := range buffers {
		buffers[i] = make([]secp256k1.Fn, n)
		for j := range buffers[i] {
			buffers[i][j] = secp256k1.RandomFn()
		}
	}
	s := State{
		count:         count,
		shareReceived: shareReceived,
		buffers:       buffers,
	}
	return reflect.ValueOf(s)
}

// SizeHint implements the surge.SizeHinter interface.
func (state State) SizeHint() int {
	return surge.SizeHint(int32(state.count)) +
		surge.SizeHint(state.shareReceived) +
		surge.SizeHint(state.buffers)
}

// Marshal implements the surge.Marshaler interface.
func (state State) Marshal(buf []byte, rem int) ([]byte, int, error) {
	buf, rem, err := surge.MarshalI32(int32(state.count), buf, rem)
	if err != nil {
		return buf, rem, err
	}
	buf, rem, err = surge.Marshal(state.shareReceived, buf, rem)
	if err != nil {
		return buf, rem, err
	}
	buf, rem, err = surge.Marshal(state.buffers, buf, rem)
	return buf, rem, err
}

// Unmarshal implements the surge.Unmarshaler interface.
func (state *State) Unmarshal(buf []byte, rem int) ([]byte, int, error) {
	buf, rem, err := surge.UnmarshalI32(&state.count, buf, rem)
	if err != nil {
		return buf, rem, err
	}
	buf, rem, err = surge.Unmarshal(&state.shareReceived, buf, rem)
	if err != nil {
		return buf, rem, err
	}
	return surge.Unmarshal(&state.buffers, buf, rem)
}
