package mulzkp_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	. "github.com/renproject/mpc/mulopen/mulzkp"

	"github.com/renproject/secp256k1"
)

var _ = Describe("NIZK", func() {
	trials := 100

	RandomTestParams := func() (
		secp256k1.Fn, secp256k1.Fn, secp256k1.Fn, secp256k1.Fn, secp256k1.Fn,
		secp256k1.Point, secp256k1.Point, secp256k1.Point,
	) {
		h := secp256k1.RandomPoint()

		alpha := secp256k1.RandomFn()
		beta := secp256k1.RandomFn()
		rho := secp256k1.RandomFn()
		sigma := secp256k1.RandomFn()
		tau := secp256k1.RandomFn()

		var a, b, hPow secp256k1.Point
		hPow.Scale(&h, &rho)
		a.BaseExp(&alpha)
		a.Add(&a, &hPow)

		hPow.Scale(&h, &sigma)
		b.BaseExp(&beta)
		b.Add(&b, &hPow)

		return alpha, beta, rho, sigma, tau, a, b, h
	}

	RandomCorrectC := func(alpha, beta, tau secp256k1.Fn, h secp256k1.Point) secp256k1.Point {
		var c, hPow secp256k1.Point
		var tmp secp256k1.Fn
		hPow.Scale(&h, &tau)
		tmp.Mul(&alpha, &beta)
		c.BaseExp(&tmp)
		c.Add(&c, &hPow)
		return c
	}

	Context("verifying proofs", func() {
		It("should accept correct proofs", func() {
			for i := 0; i < trials; i++ {
				alpha, beta, rho, sigma, tau, a, b, h := RandomTestParams()
				c := RandomCorrectC(alpha, beta, tau, h)

				proof := CreateProof(&h, &a, &b, &c, alpha, beta, rho, sigma, tau)
				Expect(Verify(&h, &a, &b, &c, &proof)).To(BeTrue())
			}
		})

		It("should reject incorrect proofs", func() {
			for i := 0; i < trials; i++ {
				alpha, beta, rho, sigma, tau, a, b, h := RandomTestParams()
				c := secp256k1.RandomPoint()

				proof := CreateProof(&h, &a, &b, &c, alpha, beta, rho, sigma, tau)
				Expect(Verify(&h, &a, &b, &c, &proof)).To(BeFalse())
			}
		})
	})
})
