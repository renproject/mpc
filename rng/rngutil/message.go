package rngutil

import (
	"fmt"

	"github.com/renproject/secp256k1"
	"github.com/renproject/shamir"
	"github.com/renproject/surge"

	"github.com/renproject/mpc/mpcutil"
)

// RngMessage type represents the message structure in the RNG protocol
type RngMessage struct {
	from, to  mpcutil.ID
	fromIndex secp256k1.Fn
	openings  shamir.VerifiableShares
	isZero    bool
}

// From returns the player ID of message sender
func (msg RngMessage) From() mpcutil.ID {
	return msg.from
}

// To returns the player ID of message recipient
func (msg RngMessage) To() mpcutil.ID {
	return msg.to
}

// IsZero returns true if the message is a RZG message, false otherwise
func (msg RngMessage) IsZero() bool {
	return msg.isZero
}

// Openings returns the directed openings from the message
func (msg RngMessage) Openings() shamir.VerifiableShares {
	return msg.openings
}

// SizeHint implements surge SizeHinter
func (msg RngMessage) SizeHint() int {
	return msg.from.SizeHint() +
		msg.to.SizeHint() +
		msg.fromIndex.SizeHint() +
		msg.openings.SizeHint() +
		surge.SizeHint(msg.isZero)
}

// Marshal implements surge Marshaler
func (msg RngMessage) Marshal(buf []byte, rem int) ([]byte, int, error) {
	buf, rem, err := msg.from.Marshal(buf, rem)
	if err != nil {
		return buf, rem, fmt.Errorf("marshaling from: %v", err)
	}
	buf, rem, err = msg.to.Marshal(buf, rem)
	if err != nil {
		return buf, rem, fmt.Errorf("marshaling to: %v", err)
	}
	buf, rem, err = msg.fromIndex.Marshal(buf, rem)
	if err != nil {
		return buf, rem, fmt.Errorf("marshaling fromIndex: %v", err)
	}
	buf, rem, err = msg.openings.Marshal(buf, rem)
	if err != nil {
		return buf, rem, fmt.Errorf("marshaling openings: %v", err)
	}
	buf, rem, err = surge.Marshal(msg.isZero, buf, rem)
	if err != nil {
		return buf, rem, fmt.Errorf("marshaling isZero: %v", err)
	}

	return buf, rem, nil
}

// Unmarshal implements surge Unmarshaler
func (msg *RngMessage) Unmarshal(buf []byte, rem int) ([]byte, int, error) {
	buf, rem, err := msg.from.Unmarshal(buf, rem)
	if err != nil {
		return buf, rem, fmt.Errorf("unmarshaling from: %v", err)
	}
	buf, rem, err = msg.to.Unmarshal(buf, rem)
	if err != nil {
		return buf, rem, fmt.Errorf("unmarshaling to: %v", err)
	}
	buf, rem, err = msg.fromIndex.Unmarshal(buf, rem)
	if err != nil {
		return buf, rem, fmt.Errorf("unmarshaling fromIndex: %v", err)
	}
	buf, rem, err = msg.openings.Unmarshal(buf, rem)
	if err != nil {
		return buf, rem, fmt.Errorf("unmarshaling openings: %v", err)
	}
	buf, rem, err = surge.Unmarshal(&msg.isZero, buf, rem)
	if err != nil {
		return buf, rem, fmt.Errorf("unmarshaling isZero: %v", err)
	}

	return buf, rem, nil
}
