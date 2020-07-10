package rng_test

import (
	"math/rand"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/renproject/secp256k1-go"
	"github.com/renproject/shamir"
	"github.com/renproject/shamir/curve"
	"github.com/renproject/shamir/shamirutil"

	"github.com/renproject/mpc/open"
	"github.com/renproject/mpc/rng"
	"github.com/renproject/mpc/rng/rngutil"
)

var _ = Describe("RNG/RZG state transitions", func() {
	rand.Seed(int64(time.Now().Nanosecond()))

	var n, b, c, k int
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
		// n is the number of players participating in the RZG protocol
		// n ∈ [5, 10]
		n := 5 + rand.Intn(6)

		// indices represent the list of index for each player
		// They are Secp256k1N representations of sequential n values
		indices := shamirutil.RandomIndices(n)

		// index denotes the current player's index
		// This is a randomly chosen index from indices
		index := indices[rand.Intn(len(indices))]

		// b is the total number of random numbers to be generated in one
		// execution of RZG protocol, i.e. the batch number
		b := 3 + rand.Intn(3)

		// k is the threshold for random number generation, or the minimum
		// number of shares required to reconstruct the secret in the
		// secret sharing scheme. Based on our BRNG to RZG scheme, k is
		// also the number of times BRNG needs to be run before using their
		// outputs to generate an unbiased random number
		k := 3 + rand.Intn(n-3)

		// h is the elliptic curve point, used as the Pedersen Commitment
		// Scheme Parameter
		h := curve.Random()

		return n, indices, index, b, k, h
	}

	BeforeEach(func() {
		n, indices, index, b, k, h = Setup()
	})

	cases := [2]bool{false, true}

	for _, isZero := range cases {
		isZero := isZero

		Context("State Transitions and Events", func() {
			BeforeEach(func() {
				if isZero {
					c = k - 1
				} else {
					c = k
				}
			})

			Specify("Initialise RZG machine to Init state", func() {
				event, rzger := rng.New(index, indices, uint32(b), uint32(k), h)

				Expect(event).To(Equal(rng.Initialised))
				Expect(rzger.State()).To(Equal(rng.Init))
				Expect(rzger.N()).To(Equal(n))
				Expect(rzger.BatchSize()).To(Equal(uint32(b)))
				Expect(rzger.Threshold()).To(Equal(uint32(k)))
				Expect(rzger.HasConstructedShares()).ToNot(BeTrue())

				for _, index := range indices {
					Expect(rzger.DirectedOpenings(index)).To(BeNil())
				}
			})

			Context("When in Init state", func() {
				Specify("Reset", func() {
					// If an RZG machine in the Init state is reset, it
					// continues to be in the init state
					_, rzger := rng.New(index, indices, uint32(b), uint32(k), h)

					event := rzger.Reset()

					Expect(event).To(Equal(rng.Reset))
					Expect(rzger.State()).To(Equal(rng.Init))
					Expect(rzger.N()).To(Equal(n))
					Expect(rzger.BatchSize()).To(Equal(uint32(b)))
					Expect(rzger.Threshold()).To(Equal(uint32(k)))
					Expect(rzger.HasConstructedShares()).ToNot(BeTrue())

					for _, index := range indices {
						Expect(rzger.DirectedOpenings(index)).To(BeNil())
					}
				})

				Specify("Supply valid BRNG shares/commitments", func() {
					// If an RZG machine in the Init state is supplied with
					// valid sets of shares and commitments from its own BRNG
					// outputs it transitions to the WaitingOpen state
					setsOfShares, setsOfCommitments := rngutil.BRNGOutputBatch(index, b, c, h)

					// Once we have `b` sets of shares and commitments we are
					// ready to transition the RZG machine
					_, rzger := rng.New(index, indices, uint32(b), uint32(k), h)
					event := rzger.TransitionShares(setsOfShares, setsOfCommitments, isZero)

					Expect(event).To(Equal(rng.SharesConstructed))
					Expect(rzger.State()).To(Equal(rng.WaitingOpen))
					Expect(rzger.HasConstructedShares()).To(BeTrue())

					for _, j := range indices {
						shares := rzger.DirectedOpenings(j)
						for _, share := range shares {
							Expect(share).ToNot(Equal(shamir.VerifiableShares{}))
						}
					}
				})

				Specify("Supply empty sets of shares", func() {
					// If an RZG machine is supplied with BRNG output
					// commitments, but empty shares, those shares are simply
					// ignored. The machine still proceeds computing the
					// commitments and moves to the WaitingOpen state while
					// returning the CommitmentsConstructed event.
					_, setsOfCommitments := rngutil.BRNGOutputBatch(index, b, c, h)

					// Initialise three RZG replicas
					_, rzger := rng.New(index, indices, uint32(b), uint32(k), h)

					event := rzger.TransitionShares([]shamir.VerifiableShares{}, setsOfCommitments, isZero)

					Expect(event).To(Equal(rng.CommitmentsConstructed))
					Expect(rzger.State()).To(Equal(rng.WaitingOpen))
					Expect(rzger.HasConstructedShares()).To(BeTrue())

					// verify that the constructed shares are simply empty
					for _, j := range indices {
						shares := rzger.DirectedOpenings(j)
						for _, share := range shares {
							Expect(share).To(Equal(shamir.VerifiableShares{}))
						}
					}
				})

				Specify("Supply sets of shares of length not equal to the batch size", func() {
					// Sets of shares of length not equal to the batch size of
					// the RNG machine are ignored, simply proceeding to
					// processing the commitments
					setsOfShares, setsOfCommitments := rngutil.BRNGOutputBatch(index, b, c, h)

					_, rzger := rng.New(index, indices, uint32(b), uint32(k), h)

					event := rzger.TransitionShares(setsOfShares[1:], setsOfCommitments, isZero)

					Expect(event).To(Equal(rng.CommitmentsConstructed))
					Expect(rzger.State()).To(Equal(rng.WaitingOpen))
					Expect(rzger.HasConstructedShares()).To(BeTrue())

					// verify that the constructed shares are simply empty
					for _, j := range indices {
						shares := rzger.DirectedOpenings(j)
						for _, share := range shares {
							Expect(share).To(Equal(shamir.VerifiableShares{}))
						}
					}
				})

				Specify("Supply single invalid set of shares (not of threshold size)", func() {
					// If an RZG machine is supplied with BRNG output shares
					// that match the RZG machine's batch size, but with one or
					// more of the set of shares not of length equal to the
					// reconstruction threshold, then it refutes our assumption
					// about the correctness of sets of shares in case they are
					// of appropriate batch size. The RZG machine hence panics,
					// and continues to be in its initial state
					setsOfShares, setsOfCommitments := rngutil.BRNGOutputBatch(index, b, c, h)
					_, rzger := rng.New(index, indices, uint32(b), uint32(k), h)

					// fool around with one of the set of shares so as to not
					// let its length match the threshold
					setsOfShares[0] = setsOfShares[0][1:]

					Expect(func() {
						rzger.TransitionShares(setsOfShares, setsOfCommitments, isZero)
					}).To(Panic())

					Expect(rzger.State()).To(Equal(rng.Init))
					Expect(rzger.HasConstructedShares()).ToNot(BeTrue())
				})

				Specify("Supply invalid sets of commitments", func() {
					// If an RZG machine is supplied with BRNG outputs that
					// have different lengths (batch size) for shares and
					// commitment, whereby the commitments are of incorrect
					// size, we panic because it refutes our assumption about
					// the correctness of the sets of commitments
					setsOfShares, setsOfCommitments := rngutil.BRNGOutputBatch(index, b, c, h)
					_, rzger := rng.New(index, indices, uint32(b), uint32(k), h)

					// Incorrect batch length.
					j := rand.Intn(b)
					wrongBatch := setsOfCommitments
					wrongBatch = append(wrongBatch[:j], wrongBatch[j+1:]...)
					Expect(func() { rzger.TransitionShares(setsOfShares, wrongBatch, isZero) }).To(Panic())
					Expect(func() {
						rzger.TransitionShares([]shamir.VerifiableShares{}, wrongBatch, isZero)
					}).To(Panic())

					// Incorrect threshold.
					j = rand.Intn(c)
					wrongK := setsOfCommitments
					wrongK[0] = append(wrongK[0][:j], wrongK[0][j+1:]...)
					Expect(func() { rzger.TransitionShares(setsOfShares, wrongK, isZero) }).To(Panic())
					Expect(func() {
						rzger.TransitionShares([]shamir.VerifiableShares{}, wrongK, isZero)
					}).To(Panic())

					Expect(rzger.State()).To(Equal(rng.Init))
					Expect(rzger.HasConstructedShares()).ToNot(BeTrue())
				})

				Specify("Supply invalid set of commitments", func() {
					// If an RZG machine is supplied with BRNG outputs that
					// have at least one commitment, not of appropriate
					// capacity (k-1) we panic because it refutes our
					// assumption about the correctness of the sets of
					// commitments
					setsOfShares, setsOfCommitments := rngutil.BRNGOutputBatch(index, b, c, h)
					_, rzger := rng.New(index, indices, uint32(b), uint32(k), h)
					j := rand.Intn(b)
					ii := rand.Intn(k - 1)
					setsOfCommitments[j] = append(setsOfCommitments[j][:ii], setsOfCommitments[j][ii+1:]...)
					Expect(func() {
						rzger.TransitionShares(setsOfShares, setsOfCommitments, isZero)
					}).To(Panic())
				})

				Specify("Supply directed opening", func() {
					// If an RZG machine in the Init state is supplied with a
					// valid directed opening it does not react to that and
					// simply ignores it. Only after having constructed its own
					// shares, and being in the WaitingOpen state, it will
					// handle the directed openings

					// initialise player's RZG machine and supply openings
					_, rzger := rng.New(index, indices, uint32(b), uint32(k), h)
					event := rzger.TransitionOpen(shamir.VerifiableShares{})

					Expect(event).To(Equal(rng.OpeningsIgnored))
					Expect(rzger.State()).To(Equal(rng.Init))
					Expect(rzger.HasConstructedShares()).ToNot(BeTrue())
				})
			})

			Context("When in WaitingOpen state", func() {
				var rzger rng.RNGer
				var openingsByPlayer map[open.Fn]shamir.VerifiableShares
				var ownSetsOfShares []shamir.VerifiableShares
				var ownSetsOfCommitments [][]shamir.Commitment

				// TransitionToWaitingOpen generates a new instance of RZG
				// machine and transitions it to the `WaitingOpen` state
				TransitionToWaitingOpen := func(
					index open.Fn,
					indices []open.Fn,
					b, k int,
					h curve.Point,
				) {
					_, rzger = rng.New(index, indices, uint32(b), uint32(k), h)

					ownSetsOfShares, ownSetsOfCommitments, openingsByPlayer, _ =
						rngutil.RNGSharesBatch(indices, index, b, k, h, isZero)

					event := rzger.TransitionShares(ownSetsOfShares, ownSetsOfCommitments, isZero)
					Expect(event).To(Equal(rng.SharesConstructed))
				}

				JustBeforeEach(func() {
					TransitionToWaitingOpen(index, indices, b, k, h)
				})

				Specify("Reset", func() {
					// When an RZG machine in the WaitingOpen state is reset,
					// it transitions to the Init state having forgotten its
					// constructed shares
					event := rzger.Reset()

					Expect(event).To(Equal(rng.Reset))
					Expect(rzger.State()).To(Equal(rng.Init))
					Expect(rzger.HasConstructedShares()).ToNot(BeTrue())
				})

				Specify("Supply BRNG shares", func() {
					// When an RZG machine in the WaitingOpen state is supplied
					// BRNG shares it simply ignores them and continues to be
					// in the same state
					setsOfShares, setsOfCommitments := rngutil.BRNGOutputBatch(index, b, c, h)
					event := rzger.TransitionShares(setsOfShares, setsOfCommitments, isZero)

					Expect(event).To(Equal(rng.SharesIgnored))
					Expect(rzger.State()).To(Equal(rng.WaitingOpen))
				})

				Specify("Supply invalid directed opening", func() {
					// When the RZG machine receives an invalid set of directed
					// openings from another player in any form (mismatching
					// length, invalid index of player, etc), it simply ignores
					// those openings and continues to be in the same state
					//
					// get a random player who is not the current RZG machine's
					// player
					from := rngutil.RandomOtherIndex(indices, &index)

					// Openings length not equal to batch size
					event := rzger.TransitionOpen(openingsByPlayer[from][1:])
					Expect(event).To(Equal(rng.OpeningsIgnored))
					Expect(rzger.State()).To(Equal(rng.WaitingOpen))

					// Sender index is randomly chosen, so does not exist in
					// the initial player indices
					shamirutil.PerturbIndex(&openingsByPlayer[from][rand.Intn(b)])
					event = rzger.TransitionOpen(openingsByPlayer[from])
					Expect(event).To(Equal(rng.OpeningsIgnored))
					Expect(rzger.State()).To(Equal(rng.WaitingOpen))
				})

				Specify("Supply directed opening", func() {
					// When the RZG machine receives a valid set of directed
					// openings from another player it adds those to its opener
					// and continues to be in the WaitingOpen state.
					//
					// get a random player who is not the current RZG machine's
					// player
					from := rngutil.RandomOtherIndex(indices, &index)

					event := rzger.TransitionOpen(openingsByPlayer[from])

					Expect(event).To(Equal(rng.OpeningsAdded))
					Expect(rzger.State()).To(Equal(rng.WaitingOpen))
				})

				Specify("Supply directed opening when k-1 openings are already ready", func() {
					// When the RZG machine receives a valid set of directed
					// openings from another player and if this is the kth set
					// (including its own), then the RZG machine is ready to
					// reconstruct the b unbiased random numbers
					//
					// The own player's openings have already been processed
					count := 1

					for _, from := range indices {
						// Ignore if its the current RZG player
						if from.Eq(&index) {
							continue
						}

						if count == k-1 {
							event := rzger.TransitionOpen(openingsByPlayer[from])

							Expect(event).To(Equal(rng.RNGsReconstructed))
							Expect(rzger.State()).To(Equal(rng.Done))
							Expect(len(rzger.ReconstructedShares())).To(Equal(b))

							break
						}

						if count < k-1 {
							event := rzger.TransitionOpen(openingsByPlayer[from])

							Expect(event).To(Equal(rng.OpeningsAdded))
							Expect(rzger.State()).To(Equal(rng.WaitingOpen))
							count = count + 1
						}
					}
				})

				Specify("directed opens should be nil for invalid indices", func() {
					// The chance that a random index is valid is negligible.
					invalidIndex := secp256k1.RandomSecp256k1N()
					Expect(rzger.DirectedOpenings(invalidIndex)).To(BeNil())
				})
			})

			Context("When in Done state", func() {
				var rzger rng.RNGer
				var openingsByPlayer map[open.Fn]shamir.VerifiableShares
				var ownSetsOfShares []shamir.VerifiableShares
				var ownSetsOfCommitments [][]shamir.Commitment

				// TransitionToDone generates a new instance of RZG machine and
				// transitions it to the `Done` state by providing own BRNG
				// outputs as well as other players' directed openings to
				// reconstruct all the unbiased random numbers
				TransitionToDone := func(
					index open.Fn,
					indices []open.Fn,
					b, k int,
					h curve.Point,
				) {
					_, rzger = rng.New(index, indices, uint32(b), uint32(k), h)

					ownSetsOfShares, ownSetsOfCommitments, openingsByPlayer, _ =
						rngutil.RNGSharesBatch(indices, index, b, k, h, isZero)

					_ = rzger.TransitionShares(ownSetsOfShares, ownSetsOfCommitments, isZero)

					count := 1
					for _, from := range indices {
						if from.Eq(&index) {
							continue
						}
						if count == k {
							break
						}

						_ = rzger.TransitionOpen(openingsByPlayer[from])
						count++
					}

					Expect(rzger.State()).To(Equal(rng.Done))
					Expect(len(rzger.ReconstructedShares())).To(Equal(b))
				}

				JustBeforeEach(func() {
					TransitionToDone(index, indices, b, k, h)
				})

				Specify("Supply BRNG shares", func() {
					// When an RZG machine in the Done state is supplied own
					// shares it simply ignores them, and continues to be in
					// the same state
					event := rzger.TransitionShares(ownSetsOfShares, ownSetsOfCommitments, isZero)

					Expect(event).To(Equal(rng.SharesIgnored))
					Expect(rzger.State()).To(Equal(rng.Done))
				})

				Specify("Supply directed opening", func() {
					// When an RZG machine in the Done state is supplied with
					// valid directed openings, it simply ignores them and
					// continues to be in the same state
					from := rngutil.RandomOtherIndex(indices, &index)

					event := rzger.TransitionOpen(openingsByPlayer[from])

					Expect(event).To(Equal(rng.OpeningsIgnored))
					Expect(rzger.State()).To(Equal(rng.Done))
				})

				Specify("Reset", func() {
					// When an RZG machine in the Done state is supplied with a
					// Reset instruction, it transitions to the Init state, and
					// forgets its secrets and shares.
					event := rzger.Reset()

					Expect(event).To(Equal(rng.Reset))
					Expect(rzger.State()).To(Equal(rng.Init))
					Expect(rzger.HasConstructedShares()).ToNot(BeTrue())
					Expect(rzger.ReconstructedShares()).To(BeNil())
				})
			})
		})

		Context("Computations", func() {
			It("Correctly computes own shares and commitments", func() {
				_, rzger := rng.New(index, indices, uint32(b), uint32(k), h)

				ownSetsOfShares, ownSetsOfCommitments, openingsByPlayer, _ :=
					rngutil.RNGSharesBatch(indices, index, b, k, h, isZero)

				rzger.TransitionShares(ownSetsOfShares, ownSetsOfCommitments, isZero)

				// fetch the directed openings computed for the state machine
				// itself
				selfOpenings := rzger.DirectedOpenings(index)

				// The directed openings from the RZG machine should be equal
				// to what we have computed in the utils
				for i, share := range selfOpenings {
					Expect(share.Eq(&openingsByPlayer[index][i])).To(BeTrue())
				}
			})

			It("Correctly computes share of unbiased random number, for the entire batch", func() {
				_, rzger := rng.New(index, indices, uint32(b), uint32(k), h)

				ownSetsOfShares, ownSetsOfCommitments, openingsByPlayer, _ :=
					rngutil.RNGSharesBatch(indices, index, b, k, h, isZero)

				_ = rzger.TransitionShares(ownSetsOfShares, ownSetsOfCommitments, isZero)

				count := 1
				for _, from := range indices {
					if from.Eq(&index) {
						continue
					}
					if count == k {
						break
					}

					_ = rzger.TransitionOpen(openingsByPlayer[from])
					count++
				}

				Expect(rzger.State()).To(Equal(rng.Done))
				Expect(len(rzger.ReconstructedShares())).To(Equal(b))

				// the reconstructed verifiable shares of the batch of unbiased
				// random numbers should be valid against the commitments for
				// those unbiased random numbers
				vssChecker := shamir.NewVSSChecker(h)
				commitments := rzger.Commitments()
				vshares := rzger.ReconstructedShares()

				for i, c := range commitments {
					Expect(vssChecker.IsValid(&c, &vshares[i])).To(BeTrue())
				}
			})
		})
	}
})
