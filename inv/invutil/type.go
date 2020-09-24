package invutil

// MachineType represents a type of player in the network.
type MachineType byte

const (
	// Honest represents a player that follows the inversion protocol as
	// specified.
	Honest = MachineType(iota)

	// Offline represents a player that is offline.
	Offline

	// Malicious represents a player that deviates from the inversion protocol
	// by sending shares or commitments with incorrect values.
	Malicious
)
