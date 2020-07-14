package table

import (
	"fmt"
	"io"

	"github.com/renproject/secp256k1"
	"github.com/renproject/shamir"
)

// An Element represents a share received from another player; along with the
// share, it contains the index of the player that created the sharing, and the
// assocaited Pedersen commitment.
type Element struct {
	from       secp256k1.Secp256k1N
	share      shamir.VerifiableShare
	commitment shamir.Commitment
}

// NewElement constructs a new Element from the given arguments.
func NewElement(
	from secp256k1.Secp256k1N,
	share shamir.VerifiableShare,
	commitment shamir.Commitment,
) Element {
	return Element{from, share, commitment}
}

// From returns the index of the player that created the element
func (e Element) From() secp256k1.Secp256k1N {
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
func (e Element) Marshal(w io.Writer, m int) (int, error) {
	m, err := e.from.Marshal(w, m)
	if err != nil {
		return m, fmt.Errorf("marshaling from: %v", err)
	}
	m, err = e.share.Marshal(w, m)
	if err != nil {
		return m, fmt.Errorf("marshaling share: %v", err)
	}
	m, err = e.commitment.Marshal(w, m)
	if err != nil {
		return m, fmt.Errorf("marshaling commitment: %v", err)
	}
	return m, nil
}

// Unmarshal implements the surge.Unmarshaler interface.
func (e *Element) Unmarshal(r io.Reader, m int) (int, error) {
	m, err := e.from.Unmarshal(r, m)
	if err != nil {
		return m, fmt.Errorf("unmarshaling from: %v", err)
	}
	m, err = e.share.Unmarshal(r, m)
	if err != nil {
		return m, fmt.Errorf("unmarshaling share: %v", err)
	}
	m, err = e.commitment.Unmarshal(r, m)
	if err != nil {
		return m, fmt.Errorf("unmarshaling commitment: %v", err)
	}
	return m, nil
}

// Set the receiver to be equal to the given Element.
func (e *Element) Set(other Element) {
	e.from = other.from
	e.share = other.share
	e.commitment.Set(other.commitment)
}
