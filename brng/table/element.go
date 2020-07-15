package table

import (
	"fmt"
	"math/rand"
	"reflect"

	"github.com/renproject/secp256k1"
	"github.com/renproject/shamir"
)

// An Element represents a share received from another player; along with the
// share, it contains the index of the player that created the sharing, and the
// assocaited Pedersen commitment.
type Element struct {
	from       secp256k1.Fn
	share      shamir.VerifiableShare
	commitment shamir.Commitment
}

// Generate implements the quick.Generator interface.
func (e Element) Generate(rand *rand.Rand, size int) reflect.Value {
	var share shamir.VerifiableShare
	var commitment shamir.Commitment

	from := secp256k1.RandomFn()
	share = share.Generate(rand, size).Interface().(shamir.VerifiableShare)
	commitment = commitment.Generate(rand, size).Interface().(shamir.Commitment)

	return reflect.ValueOf(NewElement(from, share, commitment))
}

// NewElement constructs a new Element from the given arguments.
func NewElement(
	from secp256k1.Fn,
	share shamir.VerifiableShare,
	commitment shamir.Commitment,
) Element {
	return Element{from, share, commitment}
}

// From returns the index of the player that created the element
func (e Element) From() secp256k1.Fn {
	return e.from
}

// Share returns the share of the element
func (e Element) Share() shamir.VerifiableShare {
	return e.share
}

// Commitment returns the pedersen commitment for the
// share held in the element
func (e Element) Commitment() shamir.Commitment {
	return e.commitment
}

// SizeHint implements the surge.SizeHinter interface.
func (e Element) SizeHint() int {
	return e.from.SizeHint() + e.share.SizeHint() + e.commitment.SizeHint()
}

// Marshal implements the surge.Marshaler interface.
func (e Element) Marshal(buf []byte, rem int) ([]byte, int, error) {
	buf, rem, err := e.from.Marshal(buf, rem)
	if err != nil {
		return buf, rem, fmt.Errorf("marshaling from: %v", err)
	}
	buf, rem, err = e.share.Marshal(buf, rem)
	if err != nil {
		return buf, rem, fmt.Errorf("marshaling share: %v", err)
	}
	buf, rem, err = e.commitment.Marshal(buf, rem)
	if err != nil {
		return buf, rem, fmt.Errorf("marshaling commitment: %v", err)
	}
	return buf, rem, nil
}

// Unmarshal implements the surge.Unmarshaler interface.
func (e *Element) Unmarshal(buf []byte, rem int) ([]byte, int, error) {
	buf, rem, err := e.from.Unmarshal(buf, rem)
	if err != nil {
		return buf, rem, fmt.Errorf("unmarshaling from: %v", err)
	}
	buf, rem, err = e.share.Unmarshal(buf, rem)
	if err != nil {
		return buf, rem, fmt.Errorf("unmarshaling share: %v", err)
	}
	buf, rem, err = e.commitment.Unmarshal(buf, rem)
	if err != nil {
		return buf, rem, fmt.Errorf("unmarshaling commitment: %v", err)
	}
	return buf, rem, nil
}

// Set the receiver to be equal to the given Element.
func (e *Element) Set(other Element) {
	e.from = other.from
	e.share = other.share
	e.commitment.Set(other.commitment)
}
