package zkp_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	. "github.com/renproject/mpc/mulopen/mulzkp/zkp"

	"github.com/renproject/secp256k1"
)

var _ = Describe("ZKP", func() {
	var alpha, beta, rho, sigma, tau, tmp secp256k1.Fn
	var a, b, c, h, hPow secp256k1.Point

	RandomiseInputs := func() {
		h = secp256k1.RandomPoint()

		alpha = secp256k1.RandomFn()
		beta = secp256k1.RandomFn()
		rho = secp256k1.RandomFn()
		sigma = secp256k1.RandomFn()
		tau = secp256k1.RandomFn()

		hPow.ScaleUnsafe(&h, &rho)
		a.BaseExpUnsafe(&alpha)
		a.AddUnsafe(&a, &hPow)

		hPow.ScaleUnsafe(&h, &sigma)
		b.BaseExpUnsafe(&beta)
		b.AddUnsafe(&b, &hPow)
	}

	RandomCorrectC := func() {
		hPow.ScaleUnsafe(&h, &tau)
		tmp.MulUnsafe(&alpha, &beta)
		c.BaseExpUnsafe(&tmp)
		c.AddUnsafe(&c, &hPow)
	}

	trials := 100

	Context("correct proofs", func() {
		It("should verify correct proofs", func() {
			var e secp256k1.Fn
			var msg Message
			var w Witness
			var res Response

			for i := 0; i < trials; i++ {
				RandomiseInputs()
				RandomCorrectC()

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

			for i := 0; i < trials; i++ {
				RandomiseInputs()
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
				RandomiseInputs()
				RandomCorrectC()

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
				RandomiseInputs()
				RandomCorrectC()

				msg, w = New(&h, &b, alpha, beta, rho, sigma, tau)
				e = secp256k1.RandomFn()
				res = ResponseForChallenge(&w, &e)

				b = secp256k1.RandomPoint()

				Expect(Verify(&h, &a, &b, &c, &msg, &res, &e)).To(BeFalse())
			}
		})
	})
})
