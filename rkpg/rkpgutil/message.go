package rkpgutil

import (
	"fmt"
	"io"

	"github.com/renproject/mpc/mpcutil"
	"github.com/renproject/shamir"
)

// RkpgMessage type represents the message structure in the RKPG protocol
type RkpgMessage struct {
	from, to       mpcutil.ID
	hidingOpenings shamir.VerifiableShares
}

// From returns the player ID of the message sender
func (msg RkpgMessage) From() mpcutil.ID {
	return msg.from
}

// To returns the player ID of the message recipient
func (msg RkpgMessage) To() mpcutil.ID {
	return msg.to
}

// SizeHint implements surge SizeHinter
func (msg RkpgMessage) SizeHint() int {
	return msg.from.SizeHint() +
		msg.to.SizeHint() +
		msg.hidingOpenings.SizeHint()
}

// Marshal implements surge Marshaler
func (msg RkpgMessage) Marshal(w io.Writer, m int) (int, error) {
	m, err := msg.from.Marshal(w, m)
	if err != nil {
		return m, fmt.Errorf("marshaling from: %v", err)
	}
	m, err = msg.to.Marshal(w, m)
	if err != nil {
		return m, fmt.Errorf("marshaling to: %v", err)
	}
	m, err = msg.hidingOpenings.Marshal(w, m)
	if err != nil {
		return m, fmt.Errorf("marshaling hidingOpenings: %v", err)
	}

	return m, nil
}

// Unmarshal implements surge Unmarshaler
func (msg *RkpgMessage) Unmarshal(r io.Reader, m int) (int, error) {
	m, err := msg.from.Unmarshal(r, m)
	if err != nil {
		return m, fmt.Errorf("unmarshaling from: %v", err)
	}
	m, err = msg.to.Unmarshal(r, m)
	if err != nil {
		return m, fmt.Errorf("unmarshaling to: %v", err)
	}
	m, err = msg.hidingOpenings.Unmarshal(r, m)
	if err != nil {
		return m, fmt.Errorf("unmarshaling hidingOpenings: %v", err)
	}

	return m, nil
}
