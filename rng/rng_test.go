package rng_test

import (
	"math/rand"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/renproject/shamir/curve"
	stu "github.com/renproject/shamir/testutil"

	"github.com/renproject/mpc/open"
	"github.com/renproject/mpc/rng"
)

var _ = Describe("Rng", func() {
	rand.Seed(int64(time.Now().Nanosecond()))

	var n, b, k int
	var indices []open.Fn
	var index open.Fn
	var h curve.Point

	// Setup is run before every test. It randomises the test parameters
	Setup := func() (
		int,
		[]open.Fn,
		open.Fn,
		int,
		int,
		curve.Point,
	) {
		// n is the number of players participating in the RNG protocol
		// n ∈ [5, 20]
		n := 5 + rand.Intn(16)

		// indices represent the list of index for each player
		// They are Secp256k1N representations of sequential n values
		indices := stu.SequentialIndices(n)

		// index denotes the current player's index
		// This is a randomly chosen index from indices
		index := indices[rand.Intn(len(indices))]

		// b is the total number of random numbers to be generated
		// in one execution of RNG protocol, i.e. the batch number
		b := 5 + rand.Intn(6)

		// k is the threshold for random number generation, or the
		// minimum number of shares required to reconstruct the secret
		// in the secret sharing scheme. Based on our BRNG to RNG scheme,
		// k is also the number of times BRNG needs to be run before
		// using their outputs to generate an unbiased random number
		k := 3 + rand.Intn(n-3)

		// h is the elliptic curve point, used as the Pedersen Commitment
		// Scheme Parameter
		h := curve.Random()

		return n, indices, index, b, k, h
	}

	BeforeEach(func() {
		n, indices, index, b, k, h = Setup()
	})

	Context("State Transitions and properties", func() {
		Specify("Initialise RNG machine to Init state", func() {
			event, rnger := rng.New(index, indices, uint32(b), uint32(k), h)

			Expect(event).To(Equal(rng.Initialised))
			Expect(rnger.State()).To(Equal(rng.Init))
			Expect(rnger.N()).To(Equal(n))
			Expect(rnger.BatchSize()).To(Equal(uint32(b)))
			Expect(rnger.Threshold()).To(Equal(uint32(k)))
			Expect(rnger.HasConstructedShares()).ToNot(BeTrue())
		})

		Specify("Reset when already in Init state", func() {
			_, rnger := rng.New(index, indices, uint32(b), uint32(k), h)

			event := rnger.Reset()

			Expect(event).To(Equal(rng.Reset))
			Expect(rnger.State()).To(Equal(rng.Init))
			Expect(rnger.N()).To(Equal(n))
			Expect(rnger.BatchSize()).To(Equal(uint32(b)))
			Expect(rnger.Threshold()).To(Equal(uint32(k)))
			Expect(rnger.HasConstructedShares()).ToNot(BeTrue())
		})
	})
})
