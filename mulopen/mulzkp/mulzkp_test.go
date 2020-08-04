package mulzkp_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	. "github.com/renproject/mpc/mulopen/mulzkp"

	"github.com/renproject/secp256k1"
)

var _ = Describe("NIZK", func() {
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
		It("should accept correct proofs", func() {
			for i := 0; i < trials; i++ {
				RandomiseInputs()
				RandomCorrectC()

				proof := CreateProof(&h, &a, &b, &c, alpha, beta, rho, sigma, tau)
				Expect(Verify(&h, &a, &b, &c, &proof)).To(BeTrue())
			}
		})
	})
})
