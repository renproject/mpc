package rkpgutil

import (
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

	RKPGer   rkpg.RKPGer
	Messages []mpcutil.Message
	Points   []secp256k1.Point

	RNGShares, RZGShares shamir.VerifiableShares
}

// NewHonestMachine constructs and returns a new honest machine.
func NewHonestMachine(
	ownID mpcutil.ID,
	ids []mpcutil.ID,
	indices []secp256k1.Fn,
	h secp256k1.Point,
	coms []shamir.Commitment,
	rngShares, rzgShares shamir.VerifiableShares,
) HonestMachine {
	rkpger, shares, _ := rkpg.New(indices, h, rngShares, rzgShares, coms)
	messages := make([]mpcutil.Message, len(ids))
	for i, to := range ids {
		msgShares := make(shamir.Shares, len(shares))
		copy(msgShares, shares)
		messages[i] = &Message{
			ToID:       to,
			FromID:     ownID,
			ShareBatch: msgShares,
		}
	}
	return HonestMachine{
		OwnID: ownID,
		IDs:   ids,

		RKPGer:   rkpger,
		Messages: messages,
		Points:   []secp256k1.Point{},

		RNGShares: rngShares, RZGShares: rzgShares,
	}
}

// ID implements the mpcutil.Machine interface.
func (m HonestMachine) ID() mpcutil.ID { return m.OwnID }

// InitialMessages implements the mpcutil.Machine interface.
func (m HonestMachine) InitialMessages() []mpcutil.Message {
	return m.Messages
}

// Handle implements the mpcutil.Machine interface.
func (m *HonestMachine) Handle(msg mpcutil.Message) []mpcutil.Message {
	message := msg.(*Message)
	points, _ := m.RKPGer.HandleShareBatch(message.ShareBatch)
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

// SizeHint implements the surge.SizeHinter interface.
func (m HonestMachine) SizeHint() int {
	return m.OwnID.SizeHint() +
		surge.SizeHint(m.IDs) +
		m.RKPGer.SizeHint() +
		surge.SizeHint(m.Messages) +
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
	buf, rem, err = m.RKPGer.Marshal(buf, rem)
	if err != nil {
		return buf, rem, err
	}
	buf, rem, err = surge.Marshal(m.Messages, buf, rem)
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
	buf, rem, err = m.RKPGer.Unmarshal(buf, rem)
	if err != nil {
		return buf, rem, err
	}
	buf, rem, err = surge.Unmarshal(&m.Messages, buf, rem)
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
