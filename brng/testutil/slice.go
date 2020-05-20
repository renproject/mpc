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

func RandomValidElement(
	to, from secp256k1.Secp256k1N, h curve.Point,
) brng.Element {
	indices := []secp256k1.Secp256k1N{to}
	shares := make(shamir.VerifiableShares, 1)
	commitment := shamir.NewCommitmentWithCapacity(1)
	vssharer := shamir.NewVSSharer(indices, h)
	vssharer.Share(&shares, &commitment, secp256k1.RandomSecp256k1N(), 1)

	return brng.NewElement(from, shares[0], commitment)
}

func RandomInvalidElement(to, from secp256k1.Secp256k1N, h curve.Point, perturbPart int) brng.Element {
	indices := []secp256k1.Secp256k1N{to}
	shares := make(shamir.VerifiableShares, 1)
	commitment := shamir.NewCommitmentWithCapacity(1)
	vssharer := shamir.NewVSSharer(indices, h)
	vssharer.Share(&shares, &commitment, secp256k1.RandomSecp256k1N(), 1)

	// Randomly peturb the share.
	// pass perturbPart = 2 to only make the commitments invalid
	// while keeping the indices valid
	if perturbPart <= 0 || perturbPart > 3 { perturbPart = 3 }
	r := rand.Intn(perturbPart)
	switch r {
	case 0:
		stu.PerturbValue(&shares[0])
	case 1:
		stu.PerturbDecommitment(&shares[0])
	case 2:
		stu.PerturbIndex(&shares[0])
	default:
		panic("invalid case")
	}

	return brng.NewElement(from, shares[0], commitment)
}

func RandomValidCol(
	to secp256k1.Secp256k1N, indices []secp256k1.Secp256k1N, h curve.Point,
) (brng.Col, shamir.VerifiableShare, shamir.Commitment) {
	col := make(brng.Col, len(indices))
	var sumShares shamir.VerifiableShare
	var sumCommitments shamir.Commitment

	col[0] = RandomValidElement(to, indices[0], h)
	sumShares = col[0].Share()
	sumCommitments.Set(col[0].Commitment())

	for i := 1; i < len(indices); i++ {
		col[i] = RandomValidElement(to, indices[i], h)

		share := col[i].Share()
		commitment := col[i].Commitment()
		sumShares.Add(&sumShares, &share)
		sumCommitments.Add(&sumCommitments, &commitment)
	}

	return col, sumShares, sumCommitments
}

func RandomInvalidCol(
	to secp256k1.Secp256k1N,
	indices []secp256k1.Secp256k1N,
	badIndex map[int]struct{},
	h curve.Point,
	perturbPart int,
) (brng.Col, []brng.Element) {
	col := make(brng.Col, len(indices))
	var faults []brng.Element

	for i, from := range indices {
		if _, ok := badIndex[i]; ok {
			element := RandomInvalidElement(to, from, h, perturbPart)
			col[i] = element
			faults = append(faults, element)
		} else {
			col[i] = RandomValidElement(to, from, h)
		}
	}
	return col, faults
}

func RandomValidSlice(
	to secp256k1.Secp256k1N,
	indices []secp256k1.Secp256k1N,
	h curve.Point,
	b int,
) (brng.Slice, []shamir.VerifiableShare, []shamir.Commitment) {
	slice := make(brng.Slice, b)
	shares := make([]shamir.VerifiableShare, b)
	commitments := make([]shamir.Commitment, b)

	for i := range slice {
		slice[i], shares[i], commitments[i] = RandomValidCol(to, indices, h)
	}

	return slice, shares, commitments
}

func RandomInvalidSlice(
	to secp256k1.Secp256k1N,
	indices []secp256k1.Secp256k1N,
	badIndices []map[int]struct{},
	h curve.Point,
	b int,
) (brng.Slice, []brng.Element) {
	slice := make(brng.Slice, b)
	var faults []brng.Element

	for i := range slice {
		col, colFaults := RandomInvalidCol(to, indices, badIndices[i], h, 3)
		slice[i] = col
		faults = append(faults, colFaults...)
	}
	return slice, faults
}

func RandomFaultySlice(
	to secp256k1.Secp256k1N,
	indices []secp256k1.Secp256k1N,
	badIndices []map[int]struct{},
	h curve.Point,
	b int,
) (brng.Slice, []brng.Element) {
	slice := make(brng.Slice, b)
	var faults []brng.Element

	for i := range slice {
		col, colFaults := RandomInvalidCol(to, indices, badIndices[i], h, 2)
		slice[i] = col
		faults = append(faults, colFaults...)
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
