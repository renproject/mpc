package rng_test

import (
	"fmt"
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

	var n, b, c, k int
	var indices, otherIndices []secp256k1.Fn
	var index secp256k1.Fn
	var h secp256k1.Point

	// FIXME
	fmt.Println(n)

	// Setup is run before every test. It randomises the test parameters.
	Setup := func() (
		int,
		[]secp256k1.Fn,
		[]secp256k1.Fn,
		secp256k1.Fn,
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

		// List of indices excluding the player index
		otherIndices := make([]secp256k1.Fn, 0, len(indices)-1)
		for _, i := range indices {
			if i.Eq(&index) {
				continue
			}
			otherIndices = append(otherIndices, i)
		}

		// Batch size
		b := 3 + rand.Intn(3)

		// Shamir secret sharing threshold
		k := 3 + rand.Intn(n-3)

		// Pedersen commitment scheme parameter
		h := secp256k1.RandomPoint()

		return n, indices, otherIndices, index, b, k, h
	}

	TransitionToWaitingOpen := func(rnger *rng.RNGer, isZero bool) (
		[]shamir.VerifiableShares,
		[][]shamir.Commitment,
		map[secp256k1.Fn]shamir.VerifiableShares,
	) {
		ownSetsOfShares, ownSetsOfCommitments, openingsByPlayer, _ :=
			rngutil.RNGSharesBatch(indices, index, b, k, h, isZero)
		*rnger, _, _ = rng.New(index, indices, h, ownSetsOfShares, ownSetsOfCommitments, isZero)

		return ownSetsOfShares, ownSetsOfCommitments, openingsByPlayer
	}

	TransitionToDone := func(rnger *rng.RNGer, isZero bool) (
		[]shamir.VerifiableShares,
		[][]shamir.Commitment,
		map[secp256k1.Fn]shamir.VerifiableShares,
		shamir.VerifiableShares,
		[]shamir.Commitment,
	) {
		ownSetsOfShares, ownSetsOfCommitments, openingsByPlayer, _ :=
			rngutil.RNGSharesBatch(indices, index, b, k, h, isZero)
		var commitments []shamir.Commitment
		*rnger, _, commitments = rng.New(index, indices, h, ownSetsOfShares, ownSetsOfCommitments, isZero)

		var shares shamir.VerifiableShares
		for _, from := range otherIndices[:k-1] {
			shares, _ = rnger.TransitionOpen(openingsByPlayer[from])
		}

		return ownSetsOfShares, ownSetsOfCommitments, openingsByPlayer, shares, commitments
	}

	BeforeEach(func() {
		n, indices, otherIndices, index, b, k, h = Setup()
	})

	// Here false corresponds to RNG, and true corresponds to RZG.
	cases := [2]bool{false, true}

	for _, isZero := range cases {
		isZero := isZero

		Context("State Transitions and Events", func() {
			BeforeEach(func() {
				// In RNG, we generate a polynomial with c = k coefficients,
				// whereas in RZG we only have c = k - 1 coefficients.
				if isZero {
					c = k - 1
				} else {
					c = k
				}
			})

			/*
				Specify("state machine initialisation", func() {
					event, rnger := rng.New(index, indices, uint32(b), uint32(k), h, nil, nil, false)

					Expect(event).To(Equal(rng.Initialised))
					Expect(rnger.State()).To(Equal(rng.Init))
					Expect(rnger.N()).To(Equal(n))
					Expect(rnger.BatchSize()).To(Equal(uint32(b)))
					Expect(rnger.Threshold()).To(Equal(uint32(k)))
					Expect(rnger.HasConstructedShares()).ToNot(BeTrue())

					for _, index := range indices {
						Expect(rnger.DirectedOpenings(index)).To(BeNil())
					}
				})
			*/

			Context("Init state transitions", func() {
				Specify("valid BRNG shares and commitments -> WaitingOpen", func() {
					setsOfShares, setsOfCommitments := rngutil.BRNGOutputBatch(index, b, c, h)
					_, directedOpenings, _ := rng.New(index, indices, h, setsOfShares, setsOfCommitments, isZero)

					// With valid shares, the shares for the directed opens
					// should be computed.
					for _, j := range indices {
						shares := directedOpenings[j]
						for _, share := range shares {
							Expect(share).ToNot(Equal(shamir.VerifiableShares{}))
						}
					}
				})

				Specify("empty sets of shares and valid commitments -> WaitingOpen", func() {
					_, setsOfCommitments := rngutil.BRNGOutputBatch(index, b, c, h)
					_, directedOpenings, _ := rng.New(index, indices, h, []shamir.VerifiableShares{}, setsOfCommitments, isZero)

					// With empty shares, the shares for the directed opens
					// should not be computed.
					for _, j := range indices {
						shares := directedOpenings[j]
						for _, share := range shares {
							Expect(share).To(Equal(shamir.VerifiableShares{}))
						}
					}
				})

				Specify("shares with incorrect batch size -> WaitingOpen", func() {
					setsOfShares, setsOfCommitments := rngutil.BRNGOutputBatch(index, b, c, h)
					_, directedOpenings, _ := rng.New(index, indices, h, setsOfShares[1:], setsOfCommitments, isZero)

					// With invalid shares, the shares for the directed opens
					// should not be computed.
					for _, j := range indices {
						shares := directedOpenings[j]
						for _, share := range shares {
							Expect(share).To(Equal(shamir.VerifiableShares{}))
						}
					}
				})

				Specify("shares with incorrect threshold size -> panic", func() {
					setsOfShares, setsOfCommitments := rngutil.BRNGOutputBatch(index, b, c, h)

					// Make the number of shares be incorrect.
					setsOfShares[0] = setsOfShares[0][1:]
					Expect(func() {
						_, _, _ = rng.New(index, indices, h, setsOfShares, setsOfCommitments, isZero)
					}).To(Panic())
				})

				Specify("invalid commitments -> panic", func() {
					setsOfShares, setsOfCommitments := rngutil.BRNGOutputBatch(index, b, c, h)

					// Incorrect threshold.
					j := rand.Intn(c)
					wrongK := setsOfCommitments
					wrongK[0] = append(wrongK[0][:j], wrongK[0][j+1:]...)
					Expect(func() {
						_, _, _ = rng.New(index, indices, h, setsOfShares, wrongK, isZero)
					}).To(Panic())
					Expect(func() {
						_, _, _ = rng.New(index, indices, h, []shamir.VerifiableShares{}, wrongK, isZero)
					}).To(Panic())
				})
			})

			Context("WaitingOpen state transitions", func() {
				var rnger rng.RNGer
				var openingsByPlayer map[secp256k1.Fn]shamir.VerifiableShares

				JustBeforeEach(func() {
					_, _, openingsByPlayer = TransitionToWaitingOpen(&rnger, isZero)
				})

				Specify("invalid directed opening -> do nothing", func() {
					from := otherIndices[rand.Intn(len(otherIndices))]

					// Openings length not equal to batch size
					_, err := rnger.TransitionOpen(openingsByPlayer[from][1:])

					Expect(err).To(HaveOccurred())

					// Sender index is randomly chosen, so does not exist in
					// the initial player indices
					shamirutil.PerturbIndex(&openingsByPlayer[from][rand.Intn(b)])
					_, err = rnger.TransitionOpen(openingsByPlayer[from])

					Expect(err).To(HaveOccurred())
				})

				Specify("directed opening (not yet k) -> WaitingOpen", func() {
					from := otherIndices[rand.Intn(len(otherIndices))]
					_, err := rnger.TransitionOpen(openingsByPlayer[from])
					Expect(err).ToNot(HaveOccurred())
				})

				Specify("kth directed open -> Done", func() {
					for i, from := range otherIndices {
						// The own player's openings have already been
						// processed.
						count := i + 1

						shares, err := rnger.TransitionOpen(openingsByPlayer[from])
						Expect(err).ToNot(HaveOccurred())

						if count == k-1 {
							Expect(len(shares)).To(Equal(b))
							break
						}
					}
				})
			})
		})

		Context("Computations", func() {
			It("should correctly compute the shares and commitments", func() {
				ownSetsOfShares, ownSetsOfCommitments, openingsByPlayer, _ :=
					rngutil.RNGSharesBatch(indices, index, b, k, h, isZero)
				_, directedOpenings, _ := rng.New(index, indices, h, ownSetsOfShares, ownSetsOfCommitments, isZero)

				selfOpenings := directedOpenings[index]
				for i, share := range selfOpenings {
					Expect(share.Eq(&openingsByPlayer[index][i])).To(BeTrue())
				}
			})

			It("should compute valid shares and commitments for the random number", func() {
				rnger := rng.RNGer{}
				_, _, _, shares, commitments := TransitionToDone(&rnger, isZero)

				// The reconstructed verifiable shares of the batch of unbiased
				// random numbers should be valid against the commitments for
				// those unbiased random numbers.
				for i, c := range commitments {
					Expect(shamir.IsValid(h, &c, &shares[i])).To(BeTrue())
				}
			})
		})
	}
})
