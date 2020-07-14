package compute_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	. "github.com/renproject/mpc/rng/compute"
	"github.com/renproject/secp256k1"

	"github.com/renproject/shamir"
	"github.com/renproject/shamir/curve"
)

var _ = Describe("RNG computation helper functions", func() {
	trials := 50
	k := 5

	polyEval := func(x secp256k1.Secp256k1N, coeffs []secp256k1.Secp256k1N) secp256k1.Secp256k1N {
		acc := coeffs[len(coeffs)-1]

		for i := len(coeffs) - 2; i >= 0; i-- {
			acc.Mul(&acc, &x)
			acc.Add(&acc, &coeffs[i])
			acc.Normalize()
		}

		return acc
	}

	Specify("commitments for shares should be computed correctly", func() {
		var index secp256k1.Secp256k1N
		var bs [32]byte

		coeffs := make([][]secp256k1.Secp256k1N, k)
		for i := range coeffs {
			coeffs[i] = make([]secp256k1.Secp256k1N, k)
		}

		points := make([][]curve.Point, k)
		for i := range points {
			points[i] = make([]curve.Point, k)
		}

		coms := make([]shamir.Commitment, k)
		for i := range coms {
			coms[i] = shamir.NewCommitmentWithCapacity(k)
		}

		// The idea for this test is to compute the output in two ways. The
		// first way is simply using the function that we are testing. The
		// second way is to compute the result for the scalar type (rather than
		// the elliptice curve point type), and then exponentiate this result
		// to obtain the corresponding curve point. In other words, we are
		// checking that evaluating the polynomial in the exponent (i.e.
		// computing on the commitments) is the same as evaluating the
		// polynomial, and then obtaining the corresponding curve point (i.e.
		// the result in the exponent).

		for i := 0; i < trials; i++ {
			index = secp256k1.RandomSecp256k1N()

			for j := range coeffs {
				for l := range coeffs[j] {
					coeffs[j][l] = secp256k1.RandomSecp256k1N()
					coeffs[j][l].GetB32(bs[:])
					points[j][l].BaseExp(bs)
				}
			}

			for j := range coms {
				coms[j].Set(shamir.Commitment{})
				for l := range points[j] {
					coms[j].AppendPoint(points[l][j])
				}
			}

			output := ShareCommitment(index, coms)

			expected := curve.New()
			for j := 0; j < output.Len(); j++ {
				y := polyEval(index, coeffs[j])
				y.GetB32(bs[:])

				actual := output.GetPoint(j)
				expected.BaseExp(bs)

				Expect(actual.Eq(&expected)).To(BeTrue())
			}
		}
	})

	Specify("shares of shares should be computed correctly", func() {
		var to, from secp256k1.Secp256k1N

		values := make([]secp256k1.Secp256k1N, k)
		decoms := make([]secp256k1.Secp256k1N, k)
		vshares := make(shamir.VerifiableShares, k)

		for i := 0; i < trials; i++ {
			to = secp256k1.RandomSecp256k1N()
			from = secp256k1.RandomSecp256k1N()

			for j := 0; j < k; j++ {
				values[j] = secp256k1.RandomSecp256k1N()
				decoms[j] = secp256k1.RandomSecp256k1N()
			}

			for j := range vshares {
				vshares[j] = shamir.NewVerifiableShare(
					shamir.NewShare(from, values[j]),
					decoms[j],
				)
			}

			output := ShareOfShare(to, vshares)

			// The value of the share should be correct.
			share := output.Share()
			actual := share.Value()
			expected := polyEval(to, values)

			Expect(actual.Eq(&expected)).To(BeTrue())

			// The decommitment of the share should be correct.
			actual = output.Decommitment()
			expected = polyEval(to, decoms)

			Expect(actual.Eq(&expected)).To(BeTrue())
		}
	})
})
