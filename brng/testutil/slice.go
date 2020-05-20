package testutil

import (
	"math/rand"
	"sort"

	"github.com/renproject/mpc/brng"
	"github.com/renproject/secp256k1-go"
	"github.com/renproject/shamir"
	"github.com/renproject/shamir/curve"
	stu "github.com/renproject/shamir/testutil"
)

func RandomValidSharing(indices []secp256k1.Secp256k1N, k int, h curve.Point) brng.Sharing {
	shares := make(shamir.VerifiableShares, len(indices))
	commitment := shamir.NewCommitmentWithCapacity(k)
	vssharer := shamir.NewVSSharer(indices, h)
	vssharer.Share(&shares, &commitment, secp256k1.RandomSecp256k1N(), k)

	return brng.NewSharing(shares, commitment)
}

func RandomInvalidSharing(
	indices []secp256k1.Secp256k1N,
	k int,
	h curve.Point,
	badIndex int,
) brng.Sharing {
	shares := make(shamir.VerifiableShares, len(indices))
	commitment := shamir.NewCommitmentWithCapacity(k)
	vssharer := shamir.NewVSSharer(indices, h)
	vssharer.Share(&shares, &commitment, secp256k1.RandomSecp256k1N(), k)

	// Perturb the bad indice.
	perturbShare(&shares[badIndex])

	return brng.NewSharing(shares, commitment)
}

func RandomValidRow(indices []secp256k1.Secp256k1N, k, b int, h curve.Point) brng.Row {
	row := make(brng.Row, b)
	for i := range row {
		row[i] = RandomValidSharing(indices, k, h)
	}
	return row
}

func RandomInvalidRow(
	indices []secp256k1.Secp256k1N,
	k, b int,
	h curve.Point,
	badIndex int,
	badBatches []int,
) brng.Row {
	row := make(brng.Row, b)

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

func RandomValidTable(indices []secp256k1.Secp256k1N, h curve.Point, k, b, t int) brng.Table {
	table := make(brng.Table, t)
	for i := range table {
		table[i] = RandomValidRow(indices, k, b, h)
	}
	return table
}

func RandomInvalidTable(
	indices []secp256k1.Secp256k1N,
	h curve.Point,
	n, k, b, t, badIndex int,
) (brng.Table, map[int][]int) {
	table := make(brng.Table, n)
	badIndices := randomIndices(t, 1)
	faultLocations := make(map[int][]int)

	j := 0
	for i := range table {
		if j < len(badIndices) && i == badIndices[j] {
			badBatches := randomIndices(b, 1)
			faultLocations[badIndices[j]] = badBatches
			table[i] = RandomInvalidRow(indices, k, b, h, badIndex, badBatches)
			j++
		} else {
			table[i] = RandomValidRow(indices, k, b, h)
		}
	}

	return table, faultLocations
}

func RandomValidSlice(
	to secp256k1.Secp256k1N,
	indices []secp256k1.Secp256k1N,
	h curve.Point,
	k, b, t int,
) brng.Slice {
	table := RandomValidTable(indices, h, k, b, t)
	slice := table.Slice(to, indices)
	return slice
}

func RandomInvalidSlice(
	to secp256k1.Secp256k1N,
	indices []secp256k1.Secp256k1N,
	badIndices []map[int]struct{},
	h curve.Point,
	n, k, b, t int,
) (brng.Slice, []brng.Element) {
	badIndex := -1
	for i, index := range indices {
		if index.Eq(&to) {
			badIndex = i
		}
	}
	if badIndex == -1 {
		panic("to index was not found in indices")
	}

	table, faultLocations := RandomInvalidTable(indices, h, n, k, b, t, badIndex)
	slice := table.Slice(to, indices)

	var faults []brng.Element

	for player, batches := range faultLocations {
		for _, batch := range batches {
			var fault brng.Element
			fault.Set(slice[batch][player])
			faults = append(faults, fault)
		}
	}

	return slice, faults
}

func RandomBadIndices(t, n, b int) []map[int]struct{} {
	badIndices := make([]map[int]struct{}, b)
	for i := range badIndices {
		badIndices[i] = make(map[int]struct{})
	}

	badPlayers := randomIndices(n, t)
	for _, player := range badPlayers {
		r := rand.Intn(b) + 1
		badBatches := randomIndices(b, r)
		for _, batch := range badBatches {
			badIndices[batch][player] = struct{}{}
		}
	}
	return badIndices
}

func RowIsValid(row brng.Row, k int, indices []secp256k1.Secp256k1N, h curve.Point) bool {
	reconstructor := shamir.NewReconstructor(indices)
	checker := shamir.NewVSSChecker(h)

	for _, sharing := range row {
		c := sharing.Commitment()
		for _, share := range sharing.Shares() {
			if !checker.IsValid(&c, &share) {
				return false
			}
		}

		if !stu.VsharesAreConsistent(sharing.Shares(), &reconstructor, k) {
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
		stu.PerturbValue(share)
	case 1:
		stu.PerturbDecommitment(share)
	case 2:
		stu.PerturbIndex(share)
	default:
		panic("invalid case")
	}
}
