package rkpgutil

import (
	"fmt"

	"github.com/renproject/mpc/mpcutil"
	"github.com/renproject/mpc/rkpg"
	"github.com/renproject/secp256k1"
	"github.com/renproject/shamir"
	"github.com/renproject/surge"
)

// MachineType represents a type of player in the network.
type MachineType byte

const (
	// Honest represents a player that follows the RKPG protocol as specified.
	Honest = MachineType(iota)

	// Offline represents a player that is offline.
	Offline

	// Malicious represents a player that deviates from the RKPG protocol by
	// sending shares with incorrect values.
	Malicious

	// MaliciousZero represents a player that deviates from the RKPG protocol
	// by sending shares with values equal to zero.
	MaliciousZero
)

func (ty MachineType) String() string {
	switch ty {
	case Honest:
		return "Honest"
	case Offline:
		return "Offline"
	case Malicious:
		return "Malicious"
	case MaliciousZero:
		return "MaliciousZero"
	default:
		return "Unknown"
	}
}

// HonestMachine is a machine that follows the RKPG protocol as specified.
type HonestMachine struct {
	OwnID mpcutil.ID
	IDs   []mpcutil.ID

	Params rkpg.Params
	State  rkpg.State
	Coms   []shamir.Commitment
	Points []secp256k1.Point

	RNGShares, RZGShares shamir.VerifiableShares
}

// NewHonestMachine constructs and returns a new honest machine.
func NewHonestMachine(
	ownID mpcutil.ID,
	ids []mpcutil.ID,
	params rkpg.Params,
	state rkpg.State,
	coms []shamir.Commitment,
	rngShares, rzgShares shamir.VerifiableShares,
) HonestMachine {
	return HonestMachine{
		OwnID: ownID,
		IDs:   ids,

		Params: params,
		State:  state,
		Coms:   coms,
		Points: []secp256k1.Point{},

		RNGShares: rngShares, RZGShares: rzgShares,
	}
}

// ID implements the mpcutil.Machine interface.
func (m HonestMachine) ID() mpcutil.ID { return m.OwnID }

// InitialMessages implements the mpcutil.Machine interface.
func (m HonestMachine) InitialMessages() []mpcutil.Message {
	shares, err := rkpg.InitialMessages(&m.Params, m.RNGShares, m.RZGShares)
	if err != nil {
		panic(fmt.Sprintf("could not construct initial messages: %v", err))
	}
	messages := make([]mpcutil.Message, len(m.IDs))
	for i, to := range m.IDs {
		msgShares := make(shamir.Shares, len(shares))
		copy(msgShares, shares)
		messages[i] = &Message{
			ToID:       to,
			FromID:     m.OwnID,
			ShareBatch: msgShares,
		}
	}
	return messages
}

// Handle implements the mpcutil.Machine interface.
func (m *HonestMachine) Handle(msg mpcutil.Message) []mpcutil.Message {
	message := msg.(*Message)
	points, _ := rkpg.TransitionShares(&m.State, &m.Params, m.Coms, message.ShareBatch)
	if points != nil {
		m.Points = points
	}
	return nil
}

// A MaliciousMachine represents a player that acts maliciously by sending
// shares with incorrect values.
type MaliciousMachine struct {
	OwnID   mpcutil.ID
	IDs     []mpcutil.ID
	B       int32
	Indices []secp256k1.Fn

	// If set, the player will send shares that have values equal to zero.
	// Otherwise, these values will be random.
	Zero bool
}

// NewMaliciousMachine constructs and returns a new malicious machine.
func NewMaliciousMachine(
	ownID mpcutil.ID,
	ids []mpcutil.ID,
	b int32,
	indices []secp256k1.Fn,
	zero bool,
) MaliciousMachine {
	return MaliciousMachine{
		OwnID:   ownID,
		IDs:     ids,
		B:       b,
		Indices: indices,
		Zero:    zero,
	}
}

// ID implements the mpcutil.Machine interface.
func (m MaliciousMachine) ID() mpcutil.ID { return m.OwnID }

// InitialMessages implements the mpcutil.Machine interface.
func (m MaliciousMachine) InitialMessages() []mpcutil.Message {
	messages := make([]mpcutil.Message, len(m.IDs))
	var val secp256k1.Fn
	for i, to := range m.IDs {
		msgShares := make(shamir.Shares, m.B)
		for j := range msgShares {
			if m.Zero {
				val.SetU16(0)
			} else {
				val = secp256k1.RandomFn()
			}
			msgShares[j] = shamir.NewShare(m.Indices[i], val)
		}
		messages[i] = &Message{
			ToID:       to,
			FromID:     m.OwnID,
			ShareBatch: msgShares,
		}
	}
	return messages
}

// Handle implements the mpcutil.Machine interface.
func (m *MaliciousMachine) Handle(msg mpcutil.Message) []mpcutil.Message {
	return nil
}

// An OfflineMachine represents a player that is offline. It does not send any
// messages.
type OfflineMachine mpcutil.ID

// ID implements the mpcutil.Machine interface.
func (m OfflineMachine) ID() mpcutil.ID { return mpcutil.ID(m) }

// InitialMessages implements the mpcutil.Machine interface.
func (m OfflineMachine) InitialMessages() []mpcutil.Message { return nil }

// Handle implements the mpcutil.Machine interface.
func (m OfflineMachine) Handle(_ mpcutil.Message) []mpcutil.Message { return nil }

// SizeHint implements the surge.SizeHinter interface.
func (m HonestMachine) SizeHint() int {
	return m.OwnID.SizeHint() +
		surge.SizeHint(m.IDs) +
		m.Params.SizeHint() +
		m.State.SizeHint() +
		surge.SizeHint(m.Coms) +
		surge.SizeHint(m.Points) +
		m.RNGShares.SizeHint() +
		m.RZGShares.SizeHint()
}

// Marshal implements the surge.Marshaler interface.
func (m HonestMachine) Marshal(buf []byte, rem int) ([]byte, int, error) {
	buf, rem, err := m.OwnID.Marshal(buf, rem)
	if err != nil {
		return buf, rem, err
	}
	buf, rem, err = surge.Marshal(m.IDs, buf, rem)
	if err != nil {
		return buf, rem, err
	}
	buf, rem, err = m.Params.Marshal(buf, rem)
	if err != nil {
		return buf, rem, err
	}
	buf, rem, err = m.State.Marshal(buf, rem)
	if err != nil {
		return buf, rem, err
	}
	buf, rem, err = surge.Marshal(m.Coms, buf, rem)
	if err != nil {
		return buf, rem, err
	}
	buf, rem, err = surge.Marshal(m.Points, buf, rem)
	if err != nil {
		return buf, rem, err
	}
	buf, rem, err = m.RNGShares.Marshal(buf, rem)
	if err != nil {
		return buf, rem, err
	}
	return m.RZGShares.Marshal(buf, rem)
}

// Unmarshal implements the surge.Unmarshaler interface.
func (m *HonestMachine) Unmarshal(buf []byte, rem int) ([]byte, int, error) {
	buf, rem, err := m.OwnID.Unmarshal(buf, rem)
	if err != nil {
		return buf, rem, err
	}
	buf, rem, err = surge.Unmarshal(&m.IDs, buf, rem)
	if err != nil {
		return buf, rem, err
	}
	buf, rem, err = m.Params.Unmarshal(buf, rem)
	if err != nil {
		return buf, rem, err
	}
	buf, rem, err = m.State.Unmarshal(buf, rem)
	if err != nil {
		return buf, rem, err
	}
	buf, rem, err = surge.Unmarshal(&m.Coms, buf, rem)
	if err != nil {
		return buf, rem, err
	}
	buf, rem, err = surge.Unmarshal(&m.Points, buf, rem)
	if err != nil {
		return buf, rem, err
	}
	buf, rem, err = m.RNGShares.Unmarshal(buf, rem)
	if err != nil {
		return buf, rem, err
	}
	return m.RZGShares.Unmarshal(buf, rem)
}

// SizeHint implements the surge.SizeHinter interface.
func (m MaliciousMachine) SizeHint() int {
	return m.OwnID.SizeHint() +
		surge.SizeHint(m.IDs) +
		surge.SizeHint(m.B) +
		surge.SizeHint(m.Indices) +
		surge.SizeHint(m.Zero)
}

// Marshal implements the surge.Marshaler interface.
func (m MaliciousMachine) Marshal(buf []byte, rem int) ([]byte, int, error) {
	buf, rem, err := m.OwnID.Marshal(buf, rem)
	if err != nil {
		return buf, rem, err
	}
	buf, rem, err = surge.Marshal(m.IDs, buf, rem)
	if err != nil {
		return buf, rem, err
	}
	buf, rem, err = surge.MarshalI32(m.B, buf, rem)
	if err != nil {
		return buf, rem, err
	}
	buf, rem, err = surge.MarshalBool(m.Zero, buf, rem)
	if err != nil {
		return buf, rem, err
	}
	return surge.Marshal(m.Indices, buf, rem)
}

// Unmarshal implements the surge.Unmarshaler interface.
func (m *MaliciousMachine) Unmarshal(buf []byte, rem int) ([]byte, int, error) {
	buf, rem, err := m.OwnID.Unmarshal(buf, rem)
	if err != nil {
		return buf, rem, err
	}
	buf, rem, err = surge.Unmarshal(&m.IDs, buf, rem)
	if err != nil {
		return buf, rem, err
	}
	buf, rem, err = surge.UnmarshalI32(&m.B, buf, rem)
	if err != nil {
		return buf, rem, err
	}
	buf, rem, err = surge.UnmarshalBool(&m.Zero, buf, rem)
	if err != nil {
		return buf, rem, err
	}
	return surge.Unmarshal(&m.Indices, buf, rem)
}

// SizeHint implements the surge.SizeHinter interface.
func (m OfflineMachine) SizeHint() int {
	return mpcutil.ID(m).SizeHint()
}

// Marshal implements the surge.Marshaler interface.
func (m OfflineMachine) Marshal(buf []byte, rem int) ([]byte, int, error) {
	return mpcutil.ID(m).Marshal(buf, rem)
}

// Unmarshal implements the surge.Unmarshaler interface.
func (m *OfflineMachine) Unmarshal(buf []byte, rem int) ([]byte, int, error) {
	return (*mpcutil.ID)(m).Unmarshal(buf, rem)
}
