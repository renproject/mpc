package brngutil

import (
	"math/rand"
	"sort"

	"github.com/renproject/secp256k1"
	"github.com/renproject/shamir"
	"github.com/renproject/shamir/shamirutil"

	"github.com/renproject/mpc/brng/table"
)

// RandomValidSharing creates a random and valid sharing for the indices with
// reconstruction threshold k and Pedersen parameter h.
func RandomValidSharing(indices []secp256k1.Secp256k1N, k int, h secp256k1.Point) table.Sharing {
	shares := make(shamir.VerifiableShares, len(indices))
	commitment := shamir.NewCommitmentWithCapacity(k)
	vssharer := shamir.NewVSSharer(indices, h)
	vssharer.Share(&shares, &commitment, secp256k1.RandomSecp256k1N(), k)

	return table.NewSharing(shares, commitment)
}

// RandomInvalidSharing creates a random sharing with a fault for the share
// corresponding to player indices[badIndex].
func RandomInvalidSharing(
	indices []secp256k1.Secp256k1N,
	k int,
	h secp256k1.Point,
	badIndex int,
) table.Sharing {
	shares := make(shamir.VerifiableShares, len(indices))
	commitment := shamir.NewCommitmentWithCapacity(k)
	vssharer := shamir.NewVSSharer(indices, h)
	vssharer.Share(&shares, &commitment, secp256k1.RandomSecp256k1N(), k)

	// Perturb the bad indice.
	perturbShare(&shares[badIndex])

	return table.NewSharing(shares, commitment)
}

// RandomValidRow constructs a random row for the players with the given
// indices with batch size b from sharings with reconstruction threshold k and
// Pedersen parameter h.
func RandomValidRow(indices []secp256k1.Secp256k1N, k, b int, h secp256k1.Point) table.Row {
	row := make(table.Row, b)
	for i := range row {
		row[i] = RandomValidSharing(indices, k, h)
	}
	return row
}

// RandomInvalidRow constructs a random row with faults in the batches given by
// badBatches and for the player with index indices[badIndex].
func RandomInvalidRow(
	indices []secp256k1.Secp256k1N,
	k, b int,
	h secp256k1.Point,
	badIndex int,
	badBatches []int,
) table.Row {
	row := make(table.Row, b)

	j := 0
	for i := range row {
		if j < len(badBatches) && i == badBatches[j] {
			row[i] = RandomInvalidSharing(indices, k, h, badIndex)
			j++
		} else {
			row[i] = RandomValidSharing(indices, k, h)
		}
	}

	return row
}

// RandomValidTable contructs a random valid table for the players with the
// given indices with t rows that have a batch size b, reconstruction threshold
// k and Pedersen parameter h.
func RandomValidTable(indices []secp256k1.Secp256k1N, h secp256k1.Point, k, b, t int) table.Table {
	table := make(table.Table, t)
	for i := range table {
		table[i] = RandomValidRow(indices, k, b, h)
	}
	return table
}

// SlicePos represents the position of a particular element in a given slice.
// It is addressed by batch number and player.
type SlicePos struct {
	batch, player int
}

// NewSlicePos constructs a new SlicePos from the given batch and player
// indices.
func NewSlicePos(batch, player int) SlicePos {
	return SlicePos{batch, player}
}

// RandomInvalidTable constructs a random table with faults in the slice
// corresponding to player indices[badIndex].
func RandomInvalidTable(
	indices []secp256k1.Secp256k1N,
	h secp256k1.Point,
	n, k, b, t, badIndex int,
) (table.Table, []SlicePos) {
	table := make(table.Table, n)
	badIndices := randomIndices(t, rand.Intn(t)+1)
	faultLocations := make([][]int, len(badIndices))

	j := 0
	for i := range table {
		if j < len(badIndices) && i == badIndices[j] {
			badBatches := randomIndices(b, rand.Intn(b)+1)
			faultLocations[j] = badBatches
			table[i] = RandomInvalidRow(indices, k, b, h, badIndex, badBatches)
			j++
		} else {
			table[i] = RandomValidRow(indices, k, b, h)
		}
	}

	var locTranspose []SlicePos
	for i := 0; i < b; i++ {
		for j, batch := range faultLocations {
			for _, b := range batch {
				if b > i {
					break
				} else if b == i {
					locTranspose = append(locTranspose, NewSlicePos(b, badIndices[j]))
				}
			}
		}
	}

	return table, locTranspose
}

// RandomValidSlice constructs a random valid slice for the player with index
// to, where the reconstruction threshold is k, the batch size is b, the height
// of the columns is t and h is the Pedersen parameter.
func RandomValidSlice(
	to secp256k1.Secp256k1N,
	indices []secp256k1.Secp256k1N,
	h secp256k1.Point,
	k, b, t int,
) table.Slice {
	table := RandomValidTable(indices, h, k, b, t)
	slice := table.TakeSlice(to, indices)
	return slice
}

// RandomInvalidSlice constructs a random slice with some faults, and returns
// the slice as well as a list of the faults.
func RandomInvalidSlice(
	to secp256k1.Secp256k1N,
	indices []secp256k1.Secp256k1N,
	h secp256k1.Point,
	n, k, b, t int,
) (table.Slice, []table.Element) {
	badIndex := -1
	for i, index := range indices {
		if index.Eq(&to) {
			badIndex = i
		}
	}
	if badIndex == -1 {
		panic("to index was not found in indices")
	}

	invalidTable, faultLocations := RandomInvalidTable(indices, h, n, k, b, t, badIndex)
	slice := invalidTable.TakeSlice(to, indices)

	var faults []table.Element

	for _, loc := range faultLocations {
		var fault table.Element
		fault.Set(slice[loc.batch][loc.player])
		faults = append(faults, fault)
	}

	return slice, faults
}

// RowIsValid returns true if all of the sharings in the given row are valid
// with respect to the commitments and the shares form a consistent k-sharing.
func RowIsValid(row table.Row, k int, indices []secp256k1.Secp256k1N, h secp256k1.Point) bool {
	reconstructor := shamir.NewReconstructor(indices)
	checker := shamir.NewVSSChecker(h)

	for _, sharing := range row {
		c := sharing.Commitment()
		for _, share := range sharing.Shares() {
			if !checker.IsValid(&c, &share) {
				return false
			}
		}

		if !shamirutil.VsharesAreConsistent(sharing.Shares(), &reconstructor, k) {
			return false
		}
	}

	return true
}

func randomIndices(n, k int) []int {
	indices := make([]int, n)
	for i := range indices {
		indices[i] = i
	}

	rand.Shuffle(len(indices), func(i, j int) {
		indices[i], indices[j] = indices[j], indices[i]
	})
	ret := indices[:k]

	sort.Ints(ret)
	return ret
}

func perturbShare(share *shamir.VerifiableShare) {
	r := rand.Intn(3)
	switch r {
	case 0:
		shamirutil.PerturbValue(share)
	case 1:
		shamirutil.PerturbDecommitment(share)
	case 2:
		shamirutil.PerturbIndex(share)
	default:
		panic("invalid case")
	}
}
