package open

import (
	"math/rand"
	"reflect"

	"github.com/renproject/secp256k1"
	"github.com/renproject/shamir"
	"github.com/renproject/surge"
)

type State struct {
	buf []shamir.VerifiableShares
}

func NewState(b uint32) State {
	buf := make([]shamir.VerifiableShares, b)
	for i := range buf {
		buf[i] = shamir.VerifiableShares{}
	}
	return State{buf}
}

func (state State) NumShares() int { return len(state.buf[0]) }

func (state State) Generate(_ *rand.Rand, size int) reflect.Value {
	b := rand.Intn(size) + 1
	n := size / b
	buf := make([]shamir.VerifiableShares, b)
	for i := range buf {
		buf[i] = make(shamir.VerifiableShares, n)
		for j := range buf[i] {
			buf[i][j] = shamir.NewVerifiableShare(
				shamir.NewShare(secp256k1.RandomFn(), secp256k1.RandomFn()),
				secp256k1.RandomFn(),
			)
		}
	}
	return reflect.ValueOf(State{buf})
}

func (state State) SizeHint() int { return surge.SizeHint(state.buf) }

func (state State) Marshal(buf []byte, rem int) ([]byte, int, error) {
	return surge.Marshal(state.buf, buf, rem)
}

func (state *State) Unmarshal(buf []byte, rem int) ([]byte, int, error) {
	return surge.Unmarshal(&state.buf, buf, rem)
}
