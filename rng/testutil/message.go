package testutil

import (
	"fmt"
	"io"

	"github.com/renproject/secp256k1-go"
	"github.com/renproject/shamir"
	"github.com/renproject/shamir/util"
	"github.com/renproject/surge"

	mtu "github.com/renproject/mpc/testutil"

	"github.com/renproject/mpc/open"
)

// RngMessage type represents the message structure in the RNG protocol
type RngMessage struct {
	from, to    mtu.ID
	openings    shamir.VerifiableShares
	commitments []shamir.Commitment
}

// From returns the player ID of message sender
func (msg RngMessage) From() mtu.ID {
	return msg.from
}

// To returns the player ID of message recipient
func (msg RngMessage) To() mtu.ID {
	return msg.to
}

// SizeHint implements surge SizeHinter
func (msg RngMessage) SizeHint() int {
	return msg.from.SizeHint() +
		msg.to.SizeHint() +
		msg.openings.SizeHint() +
		surge.SizeHint(msg.commitments)
}

// Marshal implements surge Marshaler
func (msg RngMessage) Marshal(w io.Writer, m int) (int, error) {
	m, err := msg.from.Marshal(w, m)
	if err != nil {
		return m, fmt.Errorf("marshaling from: %v", err)
	}
	m, err = msg.to.Marshal(w, m)
	if err != nil {
		return m, fmt.Errorf("marshaling to: %v", err)
	}
	m, err = msg.openings.Marshal(w, m)
	if err != nil {
		return m, fmt.Errorf("marshaling openings: %v", err)
	}
	m, err = surge.Marshal(w, msg.commitments, m)
	if err != nil {
		return m, fmt.Errorf("marshaling commitments: %v", err)
	}

	return m, nil
}

// Unmarshal implements surge Unmarshaler
func (msg *RngMessage) Unmarshal(r io.Reader, m int) (int, error) {
	m, err := msg.from.Unmarshal(r, m)
	if err != nil {
		return m, fmt.Errorf("unmarshaling from: %v", err)
	}
	m, err = msg.to.Unmarshal(r, m)
	if err != nil {
		return m, fmt.Errorf("unmarshaling to: %v", err)
	}
	m, err = msg.openings.Unmarshal(r, m)
	if err != nil {
		return m, fmt.Errorf("unmarshaling openings: %v", err)
	}
	m, err = msg.unmarshalCommitments(r, m)
	if err != nil {
		return m, fmt.Errorf("unmarshaling commitments: %v", err)
	}

	return m, nil
}

// Private functions
func (msg *RngMessage) unmarshalCommitments(r io.Reader, m int) (int, error) {
	var l uint32
	m, err := util.UnmarshalSliceLen32(&l, shamir.FnSizeBytes, r, m)
	if err != nil {
		return m, err
	}

	msg.commitments = (msg.commitments)[:0]
	for i := uint32(0); i < l; i++ {
		msg.commitments = append(msg.commitments, shamir.Commitment{})
		m, err = msg.commitments[i].Unmarshal(r, m)
		if err != nil {
			return m, err
		}
	}

	return m, nil
}

func fnToID(in open.Fn) mtu.ID {
	v := in.Uint64()
	return mtu.ID(uint32(v))
}

func idToFn(in mtu.ID) open.Fn {
	v := uint32(in)
	return secp256k1.NewSecp256k1N(uint64(v))
}
