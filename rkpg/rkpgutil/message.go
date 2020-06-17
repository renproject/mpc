package rkpgutil

import (
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
	// TODO:
	return m, nil
}

// Unmarshal implements surge Unmarshaler
func (msg *RkpgMessage) Unmarshal(r io.Reader, m int) (int, error) {
	// TODO:
	return m, nil
}
