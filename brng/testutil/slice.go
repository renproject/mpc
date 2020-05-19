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

func RandomValidElement(to, from secp256k1.Secp256k1N, h curve.Point) brng.Element {
	indices := []secp256k1.Secp256k1N{to}
	shares := make(shamir.VerifiableShares, 1)
	commitment := shamir.NewCommitmentWithCapacity(1)
	vssharer := shamir.NewVSSharer(indices, h)
	vssharer.Share(&shares, &commitment, secp256k1.RandomSecp256k1N(), 1)

	return brng.NewElement(from, shares[0], commitment)
}

func RandomInvalidElement(to, from secp256k1.Secp256k1N, h curve.Point) brng.Element {
	indices := []secp256k1.Secp256k1N{to}
	shares := make(shamir.VerifiableShares, 1)
	commitment := shamir.NewCommitmentWithCapacity(1)
	vssharer := shamir.NewVSSharer(indices, h)
	vssharer.Share(&shares, &commitment, secp256k1.RandomSecp256k1N(), 1)

	// Randomly peturb the share.
	r := rand.Intn(3)
	switch r {
	case 0:
		stu.PerturbIndex(&shares[0])
	case 1:
		stu.PerturbValue(&shares[0])
	case 2:
		stu.PerturbDecommitment(&shares[0])
	default:
		panic("invalid case")
	}

	return brng.NewElement(from, shares[0], commitment)
}

func RandomValidCol(to secp256k1.Secp256k1N, indices []secp256k1.Secp256k1N, h curve.Point) brng.Col {
	col := make(brng.Col, len(indices))
	for i, from := range indices {
		col[i] = RandomValidElement(to, from, h)
	}
	return col
}

func RandomInvalidCol(
	to secp256k1.Secp256k1N,
	indices []secp256k1.Secp256k1N,
	badIndex map[int]struct{},
	h curve.Point,
) brng.Col {
	col := make(brng.Col, len(indices))
	for i, from := range indices {
		if _, ok := badIndex[i]; ok {
			col[i] = RandomInvalidElement(to, from, h)
		} else {
			col[i] = RandomValidElement(to, from, h)
		}
	}
	return col
}

func RandomValidSlice(
	to secp256k1.Secp256k1N,
	indices []secp256k1.Secp256k1N,
	h curve.Point,
	b int,
) brng.Slice {
	slice := make(brng.Slice, b)
	for i := range slice {
		slice[i] = RandomValidCol(to, indices, h)
	}
	return slice
}

func RandomInvalidSlice(
	to secp256k1.Secp256k1N,
	indices []secp256k1.Secp256k1N,
	badIndices []map[int]struct{},
	h curve.Point,
	b int,
) brng.Slice {
	slice := make(brng.Slice, b)
	for i := range slice {
		slice[i] = RandomInvalidCol(to, indices, badIndices[i], h)
	}
	return slice
}

func RandomBadIndices(t, n, b int) []map[int]struct{} {
	badIndices := make([]map[int]struct{}, b)
	badPlayers := randomIndices(t, n)
	for _, player := range badPlayers {
		r := rand.Intn(b) + 1
		badBatches := randomIndices(r, b)
		for _, batch := range badBatches {
			badIndices[batch][player] = struct{}{}
		}
	}
	return badIndices
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
