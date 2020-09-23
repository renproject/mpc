package zkp_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	. "github.com/renproject/mpc/mulopen/mulzkp/zkp"

	"github.com/renproject/secp256k1"
)

var _ = Describe("ZKP", func() {
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

	Context("correct proofs", func() {
		It("should verify correct proofs", func() {
			var e secp256k1.Fn
			var msg Message
			var w Witness
			var res Response

			for i := 0; i < trials; i++ {
				alpha, beta, rho, sigma, tau, a, b, h := RandomTestParams()
				c := RandomCorrectC(alpha, beta, tau, h)

				msg, w = New(&h, &b, alpha, beta, rho, sigma, tau)
				e = secp256k1.RandomFn()
				res = ResponseForChallenge(&w, &e)

				Expect(Verify(&h, &a, &b, &c, &msg, &res, &e)).To(BeTrue())
			}
		})
	})

	Context("incorrect proofs", func() {
		It("should identify when the commitment is not to the product", func() {
			var e secp256k1.Fn
			var msg Message
			var w Witness
			var res Response

			var c, hPow secp256k1.Point
			var tmp secp256k1.Fn

			for i := 0; i < trials; i++ {
				alpha, beta, rho, sigma, tau, a, b, h := RandomTestParams()
				hPow.ScaleUnsafe(&h, &tau)
				tmp = secp256k1.RandomFn() // Pick exponent not equal to alpha * beta
				c.BaseExpUnsafe(&tmp)
				c.AddUnsafe(&c, &hPow)

				msg, w = New(&h, &b, alpha, beta, rho, sigma, tau)
				e = secp256k1.RandomFn()
				res = ResponseForChallenge(&w, &e)

				Expect(Verify(&h, &a, &b, &c, &msg, &res, &e)).To(BeFalse())
			}
		})

		It("should identify when the commitment to alpha is modified", func() {
			var e secp256k1.Fn
			var msg Message
			var w Witness
			var res Response

			for i := 0; i < trials; i++ {
				alpha, beta, rho, sigma, tau, a, b, h := RandomTestParams()
				c := RandomCorrectC(alpha, beta, tau, h)

				msg, w = New(&h, &b, alpha, beta, rho, sigma, tau)
				e = secp256k1.RandomFn()
				res = ResponseForChallenge(&w, &e)

				a = secp256k1.RandomPoint()

				Expect(Verify(&h, &a, &b, &c, &msg, &res, &e)).To(BeFalse())
			}
		})

		It("should identify when the commitment to beta is modified", func() {
			var e secp256k1.Fn
			var msg Message
			var w Witness
			var res Response

			for i := 0; i < trials; i++ {
				alpha, beta, rho, sigma, tau, a, b, h := RandomTestParams()
				c := RandomCorrectC(alpha, beta, tau, h)

				msg, w = New(&h, &b, alpha, beta, rho, sigma, tau)
				e = secp256k1.RandomFn()
				res = ResponseForChallenge(&w, &e)

				b = secp256k1.RandomPoint()

				Expect(Verify(&h, &a, &b, &c, &msg, &res, &e)).To(BeFalse())
			}
		})
	})
})
