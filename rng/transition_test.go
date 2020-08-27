package rng_test

import (
	"math/rand"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/renproject/secp256k1"
	"github.com/renproject/shamir"
	"github.com/renproject/shamir/shamirutil"

	"github.com/renproject/mpc/rng"
	"github.com/renproject/mpc/rng/rngutil"
)

var _ = Describe("RNG/RZG state transitions", func() {
	rand.Seed(int64(time.Now().Nanosecond()))

	RandomTestParameters := func(isZero bool) (
		int,
		[]secp256k1.Fn,
		secp256k1.Fn,
		int,
		int,
		int,
		secp256k1.Point,
	) {
		// Number of players participating in the protocol
		n := 5 + rand.Intn(6)

		// List of player indices
		indices := shamirutil.RandomIndices(n)

		// Current player's index
		index := indices[rand.Intn(len(indices))]

		// Batch size
		b := 3 + rand.Intn(3)

		// Shamir secret sharing threshold
		k := 3 + rand.Intn(n-3)

		var c int
		if isZero {
			c = k - 1
		} else {
			c = k
		}

		// Pedersen commitment scheme parameter
		h := secp256k1.RandomPoint()

		return n, indices, index, b, c, k, h
	}

	// Here false corresponds to RNG, and true corresponds to RZG.
	cases := [2]bool{false, true}

	for _, isZero := range cases {
		isZero := isZero

		Context("creating a new RNGer", func() {
			Specify("when given nil shares, no initial messages should be supplied", func() {
				_, indices, index, b, c, k, h := RandomTestParameters(isZero)
				_, brngCommitmentBatch := rngutil.BRNGOutputBatch(index, b, c, k, h)
				_, directedOpenings, _ := rng.New(index, indices, h, nil, brngCommitmentBatch, isZero)
				Expect(directedOpenings).To(BeNil())
			})

			Specify("when given non nil shares, the initial messages should not be nil", func() {
				_, indices, index, b, c, k, h := RandomTestParameters(isZero)
				brngShareBatch, brngCommitmentBatch := rngutil.BRNGOutputBatch(index, b, c, k, h)
				_, directedOpenings, _ := rng.New(
					index, indices, h, brngShareBatch, brngCommitmentBatch, isZero,
				)
				Expect(directedOpenings).ToNot(BeNil())
			})

			It("should correctly compute the shares and commitments", func() {
				_, indices, index, b, _, k, h := RandomTestParameters(isZero)
				ownSetsOfShares, ownSetsOfCommitments, openingsByPlayer, _ :=
					rngutil.RNGSharesBatch(indices, index, b, k, h, isZero)
				_, directedOpenings, _ := rng.New(
					index, indices, h, ownSetsOfShares, ownSetsOfCommitments, isZero,
				)

				selfOpenings := directedOpenings[index]
				for i, share := range selfOpenings {
					Expect(share.Eq(&openingsByPlayer[index][i])).To(BeTrue())
				}
			})
		})

		Context("handling share batches", func() {
			Specify("invalid share batches should return an error", func() {
				_, indices, index, b, _, k, h := RandomTestParameters(isZero)
				ownSetsOfShares, ownSetsOfCommitments, openingsByPlayer, _ :=
					rngutil.RNGSharesBatch(indices, index, b, k, h, isZero)
				rnger, _, _ := rng.New(index, indices, h, ownSetsOfShares, ownSetsOfCommitments, isZero)

				// Pick an index other than our own.
				from := indices[rand.Intn(len(indices))]
				for from.Eq(&index) {
					from = indices[rand.Intn(len(indices))]
				}

				// Incorrect shares batch length.
				_, err := rnger.HandleShareBatch(openingsByPlayer[from][1:])
				Expect(err).To(HaveOccurred())

				// Invalid share (random value).
				openingsByPlayer[from][rand.Intn(b)].Share.Value = secp256k1.RandomFn()
				_, err = rnger.HandleShareBatch(openingsByPlayer[from])
				Expect(err).To(HaveOccurred())
			})

			Specify("upon receiving the kth valid share batch, the secrets should be reconstructed", func() {
				_, indices, index, b, _, k, h := RandomTestParameters(isZero)
				ownSetsOfShares, ownSetsOfCommitments, openingsByPlayer, _ :=
					rngutil.RNGSharesBatch(indices, index, b, k, h, isZero)
				rnger, _, _ := rng.New(index, indices, h, ownSetsOfShares, ownSetsOfCommitments, isZero)

				// The own player's openings have already been processed.
				count := 1
				for _, from := range indices {
					if from.Eq(&index) {
						continue
					}

					outputShares, err := rnger.HandleShareBatch(openingsByPlayer[from])
					Expect(err).ToNot(HaveOccurred())
					count++

					if count == k {
						Expect(outputShares).ToNot(BeNil())
						Expect(len(outputShares)).To(Equal(b))
					} else {
						Expect(outputShares).To(BeNil())
					}
				}
			})

			It("the reconstructed secrets should be valid with respect to the commitments", func() {
				_, indices, index, b, _, k, h := RandomTestParameters(isZero)
				ownSetsOfShares, ownSetsOfCommitments, openingsByPlayer, _ :=
					rngutil.RNGSharesBatch(indices, index, b, k, h, isZero)
				rnger, _, commitments := rng.New(
					index, indices, h, ownSetsOfShares, ownSetsOfCommitments, isZero,
				)

				var shares shamir.VerifiableShares
				for _, from := range indices {
					shares, _ = rnger.HandleShareBatch(openingsByPlayer[from])
					if shares != nil {
						break
					}
				}

				// The reconstructed verifiable shares of the batch of unbiased
				// random numbers should be valid against the commitments for
				// those unbiased random numbers.
				for i, c := range commitments {
					Expect(shamir.IsValid(h, &c, &shares[i])).To(BeTrue())
				}
			})
		})

		Context("panics", func() {
			Specify("insecure pedersen parameter", func() {
				_, indices, index, b, c, k, h := RandomTestParameters(isZero)
				inf := secp256k1.NewPointInfinity()
				brngShareBatch, brngCommitmentBatch := rngutil.BRNGOutputBatch(index, b, c, k, h)
				Expect(func() {
					rng.New(index, indices, inf, brngShareBatch, brngCommitmentBatch, isZero)
				}).To(Panic())
			})

			Specify("too small commitment batch size", func() {
				_, indices, index, b, c, k, h := RandomTestParameters(isZero)
				brngShareBatch, _ := rngutil.BRNGOutputBatch(index, b, c, k, h)
				Expect(func() {
					rng.New(index, indices, h, brngShareBatch, [][]shamir.Commitment{}, isZero)
				}).To(Panic())
			})

			Specify("too small commitment threshold (k)", func() {
				_, indices, index, b, c, k, h := RandomTestParameters(isZero)
				brngShareBatch, brngCommitmentBatch := rngutil.BRNGOutputBatch(index, b, c, k, h)
				// For RNG, the number of coefficients that are specified needs
				// to be at least 2, whereas for RZG it only needs to be at
				// least 1.
				if !isZero {
					brngCommitmentBatch[0] = brngCommitmentBatch[0][:1]
				} else {
					brngCommitmentBatch[0] = brngCommitmentBatch[0][:0]
				}
				Expect(func() {
					rng.New(index, indices, h, brngShareBatch, brngCommitmentBatch, isZero)
				}).To(Panic())
			})

			Specify("incorrect share batch size", func() {
				_, indices, index, b, c, k, h := RandomTestParameters(isZero)
				brngShareBatch, brngCommitmentBatch := rngutil.BRNGOutputBatch(index, b, c, k, h)
				brngShareBatch = brngShareBatch[1:]
				Expect(func() {
					rng.New(index, indices, h, brngShareBatch, brngCommitmentBatch, isZero)
				}).To(Panic())
			})

			Specify("inconsistent commitment dimensions", func() {
				_, indices, index, b, c, k, h := RandomTestParameters(isZero)
				// This test requires the batch size to be at least 2.
				if b == 1 {
					b++
				}
				brngShareBatch, brngCommitmentBatch := rngutil.BRNGOutputBatch(index, b, c, k, h)
				brngCommitmentBatch[1] = brngCommitmentBatch[1][1:]
				Expect(func() {
					rng.New(index, indices, h, brngShareBatch, brngCommitmentBatch, isZero)
				}).To(Panic())
			})

			Specify("inconsistent commitment dimensions (threshold)", func() {
				_, indices, index, b, c, k, h := RandomTestParameters(isZero)
				brngShareBatch, brngCommitmentBatch := rngutil.BRNGOutputBatch(index, b, c, k, h)
				brngCommitmentBatch[0][0] = shamir.Commitment{}
				Expect(func() {
					rng.New(index, indices, h, brngShareBatch, brngCommitmentBatch, isZero)
				}).To(Panic())
			})

			Specify("inconsistent share dimensions", func() {
				_, indices, index, b, c, k, h := RandomTestParameters(isZero)
				brngShareBatch, brngCommitmentBatch := rngutil.BRNGOutputBatch(index, b, c, k, h)
				brngShareBatch[0] = brngShareBatch[0][1:]
				Expect(func() {
					rng.New(index, indices, h, brngShareBatch, brngCommitmentBatch, isZero)
				}).To(Panic())
			})
		})
	}
})
