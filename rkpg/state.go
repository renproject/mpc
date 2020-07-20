package rkpg

import (
	"math/rand"
	"reflect"

	"github.com/renproject/mpc/rng/rngutil"
	"github.com/renproject/secp256k1"
	"github.com/renproject/surge"
)

type State struct {
	count         int32
	shareReceived []bool
	buffers       [][]secp256k1.Fn
}

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

func (state *State) Clear() {
	state.count = 0
	for i := range state.shareReceived {
		state.shareReceived[i] = false
	}
	for _, buf := range state.buffers {
		for i := range buf {
			buf[i].Clear()
		}
	}
}

// Generate implements the quick.Generator interface.
func (s State) Generate(_ *rand.Rand, size int) reflect.Value {
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
	state := State{
		count:         count,
		shareReceived: shareReceived,
		buffers:       buffers,
	}
	return reflect.ValueOf(state)
}

// SizeHint implements the surge.SizeHinter interface.
func (s State) SizeHint() int {
	return surge.SizeHint(int32(s.count)) + surge.SizeHint(s.shareReceived) + surge.SizeHint(s.buffers)
}

// Marshal implements the surge.Marshaler interface.
func (s State) Marshal(buf []byte, rem int) ([]byte, int, error) {
	buf, rem, err := surge.MarshalI32(int32(s.count), buf, rem)
	if err != nil {
		return buf, rem, err
	}
	buf, rem, err = surge.Marshal(s.shareReceived, buf, rem)
	if err != nil {
		return buf, rem, err
	}
	buf, rem, err = surge.Marshal(s.buffers, buf, rem)
	return buf, rem, err
}

// Unmarshal implements the surge.Unmarshaler interface.
func (s *State) Unmarshal(buf []byte, rem int) ([]byte, int, error) {
	buf, rem, err := surge.UnmarshalI32(&s.count, buf, rem)
	if err != nil {
		return buf, rem, err
	}
	buf, rem, err = surge.Unmarshal(&s.shareReceived, buf, rem)
	if err != nil {
		return buf, rem, err
	}
	return surge.Unmarshal(&s.buffers, buf, rem)
}
