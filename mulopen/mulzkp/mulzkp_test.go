package mulzkp_test

import (
	"math/big"

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

	Context("regression tests", func() {
		It("should work for all valid data representations", func() {
			// Previously determined values that cause failure.
			x := fpFromString(
				"15219999732058972510275533396183360295095030879549381833186073092784072377857")
			y := fpFromString(
				"75198115459349756486702242141665714397911038126795031302503082075055731121695")
			tau := fnFromString(
				"37430899679432857917928767410331150620120005017933395000873046532797167831720")
			aShareValue := fnFromString(
				"13973679974075457691502839412498616997071426457774470448971404364773198085808")
			bShareValue := fnFromString(
				"79262574285439043749582962290255728663115930120072110711583284327560311922319")
			aShareDecommitment := fnFromString(
				"47438613397795755386099911638393784016137600033038749346439868722476712029967")
			bShareDecommitment := fnFromString(
				"7467188277995546385825967069391906914120810235912066586985281208271353906257")
			h := secp256k1.Point{}

			h.SetXY(&x, &y)
			product := secp256k1.Fn{}
			product.Mul(&aShareValue, &bShareValue)
			aShareCommitment := pedersenCommit(&aShareValue, &aShareDecommitment, &h)
			bShareCommitment := pedersenCommit(&bShareValue, &bShareDecommitment, &h)
			productShareCommitment := pedersenCommit(&product, &tau, &h)
			proof := CreateProof(
				&h, &aShareCommitment, &bShareCommitment, &productShareCommitment,
				aShareValue, bShareValue, aShareDecommitment, bShareDecommitment, tau,
			)
			Expect(
				Verify(&h, &aShareCommitment, &bShareCommitment, &productShareCommitment, &proof),
			).To(BeTrue())

			// This causes the representation to change, but the following
			// check should still pass.
			bShareCommitment = pedersenCommit(&bShareValue, &bShareDecommitment, &h)
			Expect(
				Verify(&h, &aShareCommitment, &bShareCommitment, &productShareCommitment, &proof),
			).To(BeTrue())
		})
	})
})

func fpFromString(str string) secp256k1.Fp {
	fpInt, _ := big.NewInt(0).SetString(str, 10)
	buf := [32]byte{}
	fpInt.FillBytes(buf[:])
	fp := secp256k1.Fp{}
	fp.SetB32(buf[:])
	return fp
}

func fnFromString(str string) secp256k1.Fn {
	fnInt, _ := big.NewInt(0).SetString(str, 10)
	buf := [32]byte{}
	fnInt.FillBytes(buf[:])
	fn := secp256k1.Fn{}
	fn.SetB32(buf[:])
	return fn
}

func pedersenCommit(value, decommitment *secp256k1.Fn, h *secp256k1.Point) secp256k1.Point {
	var commitment, hPow secp256k1.Point
	commitment.BaseExp(value)
	hPow.Scale(h, decommitment)
	commitment.Add(&commitment, &hPow)
	return commitment
}
