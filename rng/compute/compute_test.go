package compute_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	. "github.com/renproject/mpc/rng/compute"
	"github.com/renproject/secp256k1"

	"github.com/renproject/shamir"
)

var _ = Describe("RNG computation helper functions", func() {
	trials := 50
	k := 5

	polyEval := func(x secp256k1.Fn, coeffs []secp256k1.Fn) secp256k1.Fn {
		acc := coeffs[len(coeffs)-1]

		for i := len(coeffs) - 2; i >= 0; i-- {
			acc.Mul(&acc, &x)
			acc.Add(&acc, &coeffs[i])
		}

		return acc
	}

	Specify("commitments for shares should be computed correctly", func() {
		var index secp256k1.Fn

		coeffs := make([][]secp256k1.Fn, k)
		for i := range coeffs {
			coeffs[i] = make([]secp256k1.Fn, k)
		}

		points := make([][]secp256k1.Point, k)
		for i := range points {
			points[i] = make([]secp256k1.Point, k)
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
			index = secp256k1.RandomFn()

			for j := range coeffs {
				for l := range coeffs[j] {
					coeffs[j][l] = secp256k1.RandomFn()
					points[j][l].BaseExp(&coeffs[j][l])
				}
			}

			for j := range coms {
				coms[j].Set(shamir.Commitment{})
				for l := range points[j] {
					coms[j].Append(points[l][j])
				}
			}

			output := ShareCommitment(index, coms)

			expected := secp256k1.Point{}
			for j := 0; j < output.Len(); j++ {
				y := polyEval(index, coeffs[j])

				actual := output[j]
				expected.BaseExp(&y)

				Expect(actual.Eq(&expected)).To(BeTrue())
			}
		}
	})

	Specify("shares of shares should be computed correctly", func() {
		var to, from secp256k1.Fn

		values := make([]secp256k1.Fn, k)
		decoms := make([]secp256k1.Fn, k)
		vshares := make(shamir.VerifiableShares, k)

		for i := 0; i < trials; i++ {
			to = secp256k1.RandomFn()
			from = secp256k1.RandomFn()

			for j := 0; j < k; j++ {
				values[j] = secp256k1.RandomFn()
				decoms[j] = secp256k1.RandomFn()
			}

			for j := range vshares {
				vshares[j] = shamir.NewVerifiableShare(
					shamir.NewShare(from, values[j]),
					decoms[j],
				)
			}

			output := ShareOfShare(to, vshares)

			// The value of the share should be correct.
			actual := output.Share.Value
			expected := polyEval(to, values)

			Expect(actual.Eq(&expected)).To(BeTrue())

			// The decommitment of the share should be correct.
			actual = output.Decommitment
			expected = polyEval(to, decoms)

			Expect(actual.Eq(&expected)).To(BeTrue())
		}
	})
})
