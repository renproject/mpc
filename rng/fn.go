package rng

import (
	"io"

	"github.com/renproject/secp256k1-go"
)

// Fn represents a convenience type for Secp256k1N
type Fn secp256k1.Secp256k1N

// SizeHint calls the SizeHint implementation of secp256k1.Secp256k1N
func (fn Fn) SizeHint() int {
	v := secp256k1.Secp256k1N(fn)
	return v.SizeHint()
}

// Marshal calls the Marshal implementation of secp256k1.Secp256k1N
func (fn Fn) Marshal(w io.Writer, m int) (int, error) {
	v := secp256k1.Secp256k1N(fn)
	return v.Marshal(w, m)
}

// Unmarshal calls the Unmarshal implementation of secp256k1.Secp256k1N
func (fn *Fn) Unmarshal(r io.Reader, m int) (int, error) {
	v := (*secp256k1.Secp256k1N)(fn)
	return v.Unmarshal(r, m)
}

// Uint64 returns the uint64 equivalent of the Fn field element
func (fn Fn) Uint64() uint64 {
	v := secp256k1.Secp256k1N(fn)
	return v.Uint64()
}
