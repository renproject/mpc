package rng_test

import (
	"bytes"
	"math/rand"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/renproject/secp256k1-go"
	"github.com/renproject/shamir"
	"github.com/renproject/shamir/curve"
	"github.com/renproject/shamir/shamirutil"
	"github.com/renproject/surge"

	"github.com/renproject/mpc/mpcutil"
	"github.com/renproject/mpc/open"
	"github.com/renproject/mpc/rng"
	"github.com/renproject/mpc/rng/rngutil"
)

var _ = Describe("RNG", func() {
	rand.Seed(int64(time.Now().Nanosecond()))

	Describe("RNG Properties", func() {
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
			// n ∈ [5, 10]
			n := 5 + rand.Intn(6)

			// indices represent the list of index for each player
			// They are Secp256k1N representations of sequential n values
			indices := shamirutil.RandomIndices(n)

			// index denotes the current player's index
			// This is a randomly chosen index from indices
			index := indices[rand.Intn(len(indices))]

			// b is the total number of random numbers to be generated in one
			// execution of RNG protocol, i.e. the batch number
			b := 3 + rand.Intn(3)

			// k is the threshold for random number generation, or the minimum
			// number of shares required to reconstruct the secret in the
			// secret sharing scheme. Based on our BRNG to RNG scheme, k is
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

		Context("State Transitions and Events", func() {
			Specify("Initialise RNG machine to Init state", func() {
				event, rnger := rng.New(index, indices, uint32(b), uint32(k), h)

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

			Context("When in Init state", func() {
				Specify("Reset", func() {
					// If an RNG machine in the Init state is reset, it
					// continues to be in the init state
					_, rnger := rng.New(index, indices, uint32(b), uint32(k), h)

					event := rnger.Reset()

					Expect(event).To(Equal(rng.Reset))
					Expect(rnger.State()).To(Equal(rng.Init))
					Expect(rnger.N()).To(Equal(n))
					Expect(rnger.BatchSize()).To(Equal(uint32(b)))
					Expect(rnger.Threshold()).To(Equal(uint32(k)))
					Expect(rnger.HasConstructedShares()).ToNot(BeTrue())

					for _, index := range indices {
						Expect(rnger.DirectedOpenings(index)).To(BeNil())
					}
				})

				Specify("Supply valid BRNG shares/commitments", func() {
					// If an RNG machine in the Init state is supplied with
					// valid sets of shares and commitments from its own BRNG
					// outputs it transitions to the WaitingOpen state
					setsOfShares, setsOfCommitments := rngutil.GetBrngOutputs(indices, index, b, k, h)

					// Once we have `b` sets of shares and commitments we are
					// ready to transition the RNG machine
					_, rnger := rng.New(index, indices, uint32(b), uint32(k), h)
					event := rnger.TransitionShares(setsOfShares, setsOfCommitments)

					Expect(event).To(Equal(rng.SharesConstructed))
					Expect(rnger.State()).To(Equal(rng.WaitingOpen))
					Expect(rnger.HasConstructedShares()).To(BeTrue())

					for _, j := range indices {
						shares := rnger.DirectedOpenings(j)
						for _, share := range shares {
							Expect(share).ToNot(Equal(shamir.VerifiableShares{}))
						}
					}
				})

				Specify("Supply valid BRNG shares/commitments when k = 1", func() {
					k = 1
					setsOfShares, setsOfCommitments := rngutil.GetBrngOutputs(indices, index, b, k, h)
					_, rnger := rng.New(index, indices, uint32(b), uint32(k), h)
					event := rnger.TransitionShares(setsOfShares, setsOfCommitments)

					Expect(event).To(Equal(rng.RNGsReconstructed))
					Expect(rnger.State()).To(Equal(rng.Done))
					Expect(rnger.HasConstructedShares()).To(BeTrue())
				})

				Specify("Supply empty sets of shares", func() {
					// If an RNG machine is supplied with BRNG output
					// commitments, but empty shares, those shares are simply
					// ignored. The machine still proceeds computing the
					// commitments and moves to the WaitingOpen state while
					// returning the CommitmentsConstructed event.
					_, setsOfCommitments := rngutil.GetBrngOutputs(indices, index, b, k, h)

					// Initialise three RNG replicas
					_, rnger := rng.New(index, indices, uint32(b), uint32(k), h)

					event := rnger.TransitionShares([]shamir.VerifiableShares{}, setsOfCommitments)

					Expect(event).To(Equal(rng.CommitmentsConstructed))
					Expect(rnger.State()).To(Equal(rng.WaitingOpen))
					Expect(rnger.HasConstructedShares()).To(BeTrue())

					// verify that the constructed shares are simply empty
					for _, j := range indices {
						shares := rnger.DirectedOpenings(j)
						for _, share := range shares {
							Expect(share).To(Equal(shamir.VerifiableShares{}))
						}
					}
				})

				Specify("Supply sets of shares of length not equal to the batch size", func() {
					// Sets of shares of length not equal to the batch size of
					// the RNG machine are ignored, simply proceeding to
					// processing the commitments
					setsOfShares, setsOfCommitments := rngutil.GetBrngOutputs(indices, index, b, k, h)

					// Initialise three RNG replicas
					_, rnger := rng.New(index, indices, uint32(b), uint32(k), h)

					event := rnger.TransitionShares(setsOfShares[1:], setsOfCommitments)

					Expect(event).To(Equal(rng.CommitmentsConstructed))
					Expect(rnger.State()).To(Equal(rng.WaitingOpen))
					Expect(rnger.HasConstructedShares()).To(BeTrue())

					// verify that the constructed shares are simply empty
					for _, j := range indices {
						shares := rnger.DirectedOpenings(j)
						for _, share := range shares {
							Expect(share).To(Equal(shamir.VerifiableShares{}))
						}
					}
				})

				Specify("Supply single invalid set of shares (not of threshold size)", func() {
					// If an RNG machine is supplied with BRNG output shares
					// that match the RNG machine's batch size, but with one or
					// more of the set of shares not of length equal to the
					// reconstruction threshold, then it refutes our assumption
					// about the correctness of sets of shares in case they are
					// of appropriate batch size. The RNG machine hence panics,
					// and continues to be in its initial state
					setsOfShares, setsOfCommitments := rngutil.GetBrngOutputs(indices, index, b, k, h)
					_, rnger := rng.New(index, indices, uint32(b), uint32(k), h)

					// fool around with one of the set of shares so as to not
					// let its length match the threshold
					setsOfShares[0] = setsOfShares[0][1:]

					Expect(func() { rnger.TransitionShares(setsOfShares, setsOfCommitments) }).To(Panic())

					Expect(rnger.State()).To(Equal(rng.Init))
					Expect(rnger.HasConstructedShares()).ToNot(BeTrue())
				})

				Specify("Supply invalid sets of commitments", func() {
					// If an RNG machine is supplied with BRNG outputs that
					// have different lengths (batch size) for shares and
					// commitment, whereby the commitments are of incorrect
					// size, we panic because it refutes our assumption about
					// the correctness of the sets of commitments
					setsOfShares, setsOfCommitments := rngutil.GetBrngOutputs(indices, index, b, k, h)
					_, rnger := rng.New(index, indices, uint32(b), uint32(k), h)

					// Incorrect batch length.
					j := rand.Intn(b)
					wrongBatch := setsOfCommitments
					wrongBatch = append(wrongBatch[:j], wrongBatch[j+1:]...)
					Expect(func() { rnger.TransitionShares(setsOfShares, wrongBatch) }).To(Panic())
					Expect(func() {
						rnger.TransitionShares([]shamir.VerifiableShares{}, wrongBatch)
					}).To(Panic())

					// Incorrect threshold.
					j = rand.Intn(k)
					wrongK := setsOfCommitments
					wrongK[0] = append(wrongK[0][:j], wrongK[0][j+1:]...)
					Expect(func() { rnger.TransitionShares(setsOfShares, wrongK) }).To(Panic())
					Expect(func() {
						rnger.TransitionShares([]shamir.VerifiableShares{}, wrongK)
					}).To(Panic())

					Expect(rnger.State()).To(Equal(rng.Init))
					Expect(rnger.HasConstructedShares()).ToNot(BeTrue())
				})

				Specify("Supply directed opening", func() {
					// If an RNG machine in the Init state is supplied with a
					// valid directed opening it does not react to that and
					// simply ignores it. Only after having constructed its own
					// shares, and being in the WaitingOpen state, it will
					// handle the directed openings

					// get a `from` index that is different than own index
					from := indices[rand.Intn(len(indices))]
					for from.Eq(&index) {
						from = indices[rand.Intn(len(indices))]
					}

					// get this `from` index's sets of shares and commitments
					// also compute its openings for the player
					setsOfShares, setsOfCommitments := rngutil.GetBrngOutputs(indices, from, b, k, h)
					openings, _ := rngutil.GetDirectedOpenings(setsOfShares, setsOfCommitments, index)

					// initialise player's RNG machine and supply openings
					_, rnger := rng.New(index, indices, uint32(b), uint32(k), h)
					event := rnger.TransitionOpen(from, openings)

					Expect(event).To(Equal(rng.OpeningsIgnored))
					Expect(rnger.State()).To(Equal(rng.Init))
					Expect(rnger.HasConstructedShares()).ToNot(BeTrue())
				})
			})

			Context("When in WaitingOpen state", func() {
				var rnger rng.RNGer
				var openingsByPlayer map[open.Fn]shamir.VerifiableShares
				var ownSetsOfShares []shamir.VerifiableShares
				var ownSetsOfCommitments [][]shamir.Commitment

				// TransitionToWaitingOpen generates a new instance of RNG
				// machine and transitions it to the `WaitingOpen` state
				TransitionToWaitingOpen := func(
					index open.Fn,
					indices []open.Fn,
					b, k int,
					h curve.Point,
				) {
					_, rnger = rng.New(index, indices, uint32(b), uint32(k), h)

					openingsByPlayer, _, ownSetsOfShares, ownSetsOfCommitments =
						rngutil.GetAllDirectedOpenings(indices, index, b, k, h)

					event := rnger.TransitionShares(ownSetsOfShares, ownSetsOfCommitments)
					Expect(event).To(Equal(rng.SharesConstructed))
				}

				JustBeforeEach(func() {
					TransitionToWaitingOpen(index, indices, b, k, h)
				})

				Specify("Reset", func() {
					// When an RNG machine in the WaitingOpen state is reset,
					// it transitions to the Init state having forgotten its
					// constructed shares
					event := rnger.Reset()

					Expect(event).To(Equal(rng.Reset))
					Expect(rnger.State()).To(Equal(rng.Init))
					Expect(rnger.HasConstructedShares()).ToNot(BeTrue())
				})

				Specify("Supply BRNG shares", func() {
					// When an RNG machine in the WaitingOpen state is supplied
					// BRNG shares it simply ignores them and continues to be
					// in the same state
					setsOfShares, setsOfCommitments := rngutil.GetBrngOutputs(indices, index, b, k, h)
					event := rnger.TransitionShares(setsOfShares, setsOfCommitments)

					Expect(event).To(Equal(rng.SharesIgnored))
					Expect(rnger.State()).To(Equal(rng.WaitingOpen))
				})

				Specify("Supply invalid directed opening", func() {
					// When the RNG machine receives an invalid set of directed
					// openings from another player in any form (mismatching
					// length, invalid index of player, etc), it simply ignores
					// those openings and continues to be in the same state
					//
					// get a random player who is not the current RNG machine's
					// player
					from := indices[rand.Intn(len(indices))]
					for from.Eq(&index) {
						from = indices[rand.Intn(len(indices))]
					}

					// Openings length not equal to batch size
					event := rnger.TransitionOpen(from, openingsByPlayer[from][1:])
					Expect(event).To(Equal(rng.OpeningsIgnored))
					Expect(rnger.State()).To(Equal(rng.WaitingOpen))

					// Sender index is randomly chosen, so does not exist in
					// the initial player indices
					event = rnger.TransitionOpen(secp256k1.RandomSecp256k1N(), openingsByPlayer[from])
					Expect(event).To(Equal(rng.OpeningsIgnored))
					Expect(rnger.State()).To(Equal(rng.WaitingOpen))
				})

				Specify("Supply directed opening", func() {
					// When the RNG machine receives a valid set of directed
					// openings from another player it adds those to its opener
					// and continues to be in the WaitingOpen state.
					//
					// get a random player who is not the current RNG machine's
					// player
					from := indices[rand.Intn(len(indices))]
					for from.Eq(&index) {
						from = indices[rand.Intn(len(indices))]
					}

					event := rnger.TransitionOpen(from, openingsByPlayer[from])

					Expect(event).To(Equal(rng.OpeningsAdded))
					Expect(rnger.State()).To(Equal(rng.WaitingOpen))
				})

				Specify("Supply directed opening when k-1 openings are already ready", func() {
					// When the RNG machine receives a valid set of directed
					// openings from another player and if this is the kth set
					// (including its own), then the RNG machine is ready to
					// reconstruct the b unbiased random numbers
					//
					// The own player's openings have already been processed
					count := 1

					for _, from := range indices {
						// Ignore if its the current RNG player
						if from.Eq(&index) {
							continue
						}

						if count == k-1 {
							event := rnger.TransitionOpen(from, openingsByPlayer[from])

							Expect(event).To(Equal(rng.RNGsReconstructed))
							Expect(rnger.State()).To(Equal(rng.Done))
							Expect(len(rnger.ReconstructedShares())).To(Equal(b))

							break
						}

						if count < k-1 {
							event := rnger.TransitionOpen(from, openingsByPlayer[from])

							Expect(event).To(Equal(rng.OpeningsAdded))
							Expect(rnger.State()).To(Equal(rng.WaitingOpen))
							count = count + 1
						}
					}
				})

				Specify("directed opens should be nil for invalid indices", func() {
					// The chance that a random index is valid is negligible.
					invalidIndex := secp256k1.RandomSecp256k1N()
					Expect(rnger.DirectedOpenings(invalidIndex)).To(BeNil())
				})
			})

			Context("When in Done state", func() {
				var rnger rng.RNGer
				var openingsByPlayer map[open.Fn]shamir.VerifiableShares
				var ownSetsOfShares []shamir.VerifiableShares
				var ownSetsOfCommitments [][]shamir.Commitment

				// TransitionToDone generates a new instance of RNG machine and
				// transitions it to the `Done` state by providing own BRNG
				// outputs as well as other players' directed openings to
				// reconstruct all the unbiased random numbers
				TransitionToDone := func(
					index open.Fn,
					indices []open.Fn,
					b, k int,
					h curve.Point,
				) {
					_, rnger = rng.New(index, indices, uint32(b), uint32(k), h)

					openingsByPlayer, _, ownSetsOfShares, ownSetsOfCommitments =
						rngutil.GetAllDirectedOpenings(indices, index, b, k, h)

					_ = rnger.TransitionShares(ownSetsOfShares, ownSetsOfCommitments)

					count := 1
					for _, from := range indices {
						if from.Eq(&index) {
							continue
						}
						if count == k {
							break
						}

						_ = rnger.TransitionOpen(from, openingsByPlayer[from])
						count++
					}

					Expect(rnger.State()).To(Equal(rng.Done))
					Expect(len(rnger.ReconstructedShares())).To(Equal(b))
				}

				JustBeforeEach(func() {
					TransitionToDone(index, indices, b, k, h)
				})

				Specify("Supply BRNG shares", func() {
					// When an RNG machine in the Done state is supplied own
					// shares it simply ignores them, and continues to be in
					// the same state
					event := rnger.TransitionShares(ownSetsOfShares, ownSetsOfCommitments)

					Expect(event).To(Equal(rng.SharesIgnored))
					Expect(rnger.State()).To(Equal(rng.Done))
				})

				Specify("Supply directed opening", func() {
					// When an RNG machine in the Done state is supplied with
					// valid directed openings, it simply ignores them and
					// continues to be in the same state
					from := indices[rand.Intn(len(indices))]
					for from.Eq(&index) {
						from = indices[rand.Intn(len(indices))]
					}

					event := rnger.TransitionOpen(from, openingsByPlayer[from])

					Expect(event).To(Equal(rng.OpeningsIgnored))
					Expect(rnger.State()).To(Equal(rng.Done))
				})

				Specify("Reset", func() {
					// When an RNG machine in the Done state is supplied with a
					// Reset instruction, it transitions to the Init state, and
					// forgets its secrets and shares.
					event := rnger.Reset()

					Expect(event).To(Equal(rng.Reset))
					Expect(rnger.State()).To(Equal(rng.Init))
					Expect(rnger.HasConstructedShares()).ToNot(BeTrue())
					Expect(rnger.ReconstructedShares()).To(BeNil())
				})
			})
		})

		Context("Computations", func() {
			It("Correctly computes own shares and commitments", func() {
				_, rnger := rng.New(index, indices, uint32(b), uint32(k), h)

				openingsByPlayer, _, ownSetsOfShares, ownSetsOfCommitments :=
					rngutil.GetAllDirectedOpenings(indices, index, b, k, h)

				rnger.TransitionShares(ownSetsOfShares, ownSetsOfCommitments)

				// fetch the directed openings computed for the state machine
				// itself
				selfOpenings := rnger.DirectedOpenings(index)

				// The directed openings from the RNG machine should be equal
				// to what we have computed in the utils
				for i, share := range selfOpenings {
					Expect(share.Eq(&openingsByPlayer[index][i])).To(BeTrue())
				}
			})

			It("Correctly computes share of unbiased random number, for the entire batch", func() {
				_, rnger := rng.New(index, indices, uint32(b), uint32(k), h)

				openingsByPlayer, _, ownSetsOfShares, ownSetsOfCommitments :=
					rngutil.GetAllDirectedOpenings(indices, index, b, k, h)

				_ = rnger.TransitionShares(ownSetsOfShares, ownSetsOfCommitments)

				count := 1
				for _, from := range indices {
					if count == k {
						break
					}

					_ = rnger.TransitionOpen(from, openingsByPlayer[from])
				}

				Expect(rnger.State()).To(Equal(rng.Done))
				Expect(len(rnger.ReconstructedShares())).To(Equal(b))

				// the reconstructed verifiable shares of the batch of unbiased
				// random numbers should be valid against the commitments for
				// those unbiased random numbers
				vssChecker := shamir.NewVSSChecker(h)
				commitments := rnger.Commitments()
				vshares := rnger.ReconstructedShares()
				for i, c := range commitments {
					Expect(vssChecker.IsValid(&c, &vshares[i])).To(BeTrue())
				}
			})
		})

		Context("Marshaling and Unmarshaling", func() {
			var rnger rng.RNGer
			var openingsByPlayer map[open.Fn]shamir.VerifiableShares
			var ownSetsOfShares []shamir.VerifiableShares
			var ownSetsOfCommitments [][]shamir.Commitment

			JustBeforeEach(func() {
				_, rnger = rng.New(index, indices, uint32(b), uint32(k), h)
				openingsByPlayer, _, ownSetsOfShares, ownSetsOfCommitments =
					rngutil.GetAllDirectedOpenings(indices, index, b, k, h)

				rnger.TransitionShares(ownSetsOfShares, ownSetsOfCommitments)
			})

			It("Should correctly marshal and unmarshal (WaitingOpen)", func() {
				buf := bytes.NewBuffer([]byte{})

				m, err := rnger.Marshal(buf, rnger.SizeHint())
				Expect(err).ToNot(HaveOccurred())
				Expect(m).To(Equal(0))

				var rnger2 rng.RNGer
				m, err = rnger2.Unmarshal(buf, rnger.SizeHint())
				Expect(err).ToNot(HaveOccurred())
				Expect(m).To(Equal(0))

				Expect(rnger.BatchSize()).To(Equal(rnger2.BatchSize()))
				Expect(rnger.State()).To(Equal(rnger2.State()))
				Expect(rnger.N()).To(Equal(rnger2.N()))
				Expect(rnger.Threshold()).To(Equal(rnger2.Threshold()))
				Expect(rnger.ReconstructedShares()).To(Equal(rnger2.ReconstructedShares()))

				for _, j := range indices {
					expectedShares := rnger.DirectedOpenings(j)
					shares := rnger2.DirectedOpenings(j)

					Expect(expectedShares).To(Equal(shares))
				}
			})

			It("should correctly marshal and unmarshal (Done)", func() {
				count := 1
				for _, from := range indices {
					if count == k {
						break
					}

					_ = rnger.TransitionOpen(from, openingsByPlayer[from])
				}
				Expect(rnger.State()).To(Equal(rng.Done))
				Expect(len(rnger.ReconstructedShares())).To(Equal(b))

				buf := bytes.NewBuffer([]byte{})

				m, err := rnger.Marshal(buf, rnger.SizeHint())
				Expect(err).ToNot(HaveOccurred())
				Expect(m).To(Equal(0))

				var rnger2 rng.RNGer
				m, err = rnger2.Unmarshal(buf, rnger.SizeHint())
				Expect(err).ToNot(HaveOccurred())
				Expect(m).To(Equal(0))

				Expect(rnger.BatchSize()).To(Equal(rnger2.BatchSize()))
				Expect(rnger.State()).To(Equal(rnger2.State()))
				Expect(rnger.N()).To(Equal(rnger2.N()))
				Expect(rnger.Threshold()).To(Equal(rnger2.Threshold()))
				Expect(rnger.ReconstructedShares()).To(Equal(rnger2.ReconstructedShares()))

				for _, j := range indices {
					expectedShares := rnger.DirectedOpenings(j)
					shares := rnger2.DirectedOpenings(j)

					Expect(expectedShares).To(Equal(shares))
				}
			})

			It("Should fail when marshaling with not enough bytes", func() {
				buf := bytes.NewBuffer([]byte{})

				for i := 0; i < rnger.SizeHint(); i++ {
					buf.Reset()
					_, err := rnger.Marshal(buf, i)
					Expect(err).To(HaveOccurred())
				}
			})

			It("Should fail when unmarshaling with not enough bytes", func() {
				bs, _ := surge.ToBinary(rnger)

				var rnger2 rng.RNGer
				for i := 0; i < rnger.SizeHint(); i++ {
					buf := bytes.NewBuffer(bs)

					_, err := rnger2.Unmarshal(buf, i)
					Expect(err).To(HaveOccurred())
				}
			})
		})
	})

	Describe("Network Simulation", func() {
		Specify("RNG machines should reconstruct the consistent shares for random numbers", func() {
			// Randomise RNG network scenario
			n := 5 + rand.Intn(6)
			indices := shamirutil.SequentialIndices(n)
			b := 3 + rand.Intn(3)
			k := 3 + rand.Intn(n-3)
			h := curve.Random()

			// Machines (players) participating in the RNG protocol
			ids := make([]mpcutil.ID, n)
			machines := make([]mpcutil.Machine, n)

			// Get BRNG outputs for all players
			setsOfSharesByPlayer, setsOfCommitmentsByPlayer :=
				rngutil.GetAllSharesAndCommitments(indices, b, k, h)

			// Append machines to the network
			for i, index := range indices {
				id := mpcutil.ID(i)
				rngMachine := rngutil.NewRngMachine(
					id, index, indices, b, k, h,
					setsOfSharesByPlayer[index],
					setsOfCommitmentsByPlayer[index],
					false,
				)
				machines[i] = &rngMachine
				ids[i] = id
			}

			nOffline := rand.Intn(n - k + 1)
			shuffleMsgs, isOffline := mpcutil.MessageShufflerDropper(ids, nOffline)
			network := mpcutil.NewNetwork(machines, shuffleMsgs)
			network.SetCaptureHist(true)

			err := network.Run()
			Expect(err).ToNot(HaveOccurred())

			// ID of the first online machine
			i := 0
			for isOffline[machines[i].ID()] {
				i = i + 1
			}

			// Get the unbiased random numbers calculated by that RNG machine
			referenceRNShares := machines[i].(*rngutil.RngMachine).RandomNumbersShares()
			referenceCommitments := machines[i].(*rngutil.RngMachine).Commitments()

			// checker to check validity of verifiable shares against
			// commitments
			vssChecker := shamir.NewVSSChecker(h)

			for j := i + 1; j < len(machines); j++ {
				// Ignore if that machine is offline
				if isOffline[machines[j].ID()] {
					continue
				}

				rnShares := machines[j].(*rngutil.RngMachine).RandomNumbersShares()
				Expect(len(referenceRNShares)).To(Equal(len(rnShares)))

				// Every player has computed the same commitments for the batch
				// of unbiased random numbers
				comms := machines[j].(*rngutil.RngMachine).Commitments()
				for l, c := range comms {
					Expect(c.Eq(&referenceCommitments[l])).To(BeTrue())
				}

				// Verify that each machine's share of the unbiased random
				// number (for all batches) are valid with respect to the
				// reference commitments
				for l, vshare := range rnShares {
					Expect(vssChecker.IsValid(&comms[l], &vshare)).To(BeTrue())
				}
			}

			// Form the indices for machines that were online and a
			// reconstructor for those indices
			onlineIndices := make([]open.Fn, 0, len(machines))
			for j := 0; j < len(machines); j++ {
				if isOffline[machines[j].ID()] {
					continue
				}
				evaluationPoint := machines[j].(*rngutil.RngMachine).Index()
				onlineIndices = append(onlineIndices, evaluationPoint)
			}
			reconstructor := shamir.NewReconstructor(onlineIndices)

			// For every batch in batch size, the shares that every player has
			// should be consistent
			for i := 0; i < b; i++ {
				shares := make(shamir.Shares, 0, len(machines))

				for j := 0; j < len(machines); j++ {
					if isOffline[machines[j].ID()] {
						continue
					}

					vshare := machines[j].(*rngutil.RngMachine).RandomNumbersShares()[i]

					shares = append(shares, vshare.Share())
				}

				Expect(shamirutil.SharesAreConsistent(shares, &reconstructor, k-1)).ToNot(BeTrue())
				Expect(shamirutil.SharesAreConsistent(shares, &reconstructor, k)).To(BeTrue())
			}
		})

		Specify("With not all RNG machines contributing their BRNG shares", func() {
			// Randomise RNG network scenario
			n := 15 + rand.Intn(6)
			indices := shamirutil.SequentialIndices(n)
			b := 3 + rand.Intn(3)
			k := rngutil.Min(3+rand.Intn(n-3), 7)
			h := curve.Random()

			// Machines (players) participating in the RNG protocol
			ids := make([]mpcutil.ID, n)
			machines := make([]mpcutil.Machine, n)

			// Get BRNG outputs for all players
			setsOfSharesByPlayer, setsOfCommitmentsByPlayer :=
				rngutil.GetAllSharesAndCommitments(indices, b, k, h)

			// Append machine IDs and get offline machines
			hasEmptyShares := make(map[mpcutil.ID]bool)
			for i := range indices {
				id := mpcutil.ID(i)
				ids[i] = id
				hasEmptyShares[id] = false
			}
			nOffline := rand.Intn(n - k + 1)
			shuffleMsgs, isOffline := mpcutil.MessageShufflerDropper(ids, nOffline)

			// Mark some machines as being idle specifically, at the most k+1
			// should not be idle so (n - nOffline) - k - 1 should be idle
			// because only (n - nOffline) machines are online
			idleCount := 0
			for j := range indices {
				if isOffline[mpcutil.ID(j)] {
					continue
				}

				if idleCount == rngutil.Max(0, (n-nOffline)-k-1) {
					break
				}

				hasEmptyShares[mpcutil.ID(j)] = true
				idleCount++
			}

			// Append machines to the network
			for i, index := range indices {
				id := mpcutil.ID(i)
				rngMachine := rngutil.NewRngMachine(
					id, index, indices, b, k, h,
					setsOfSharesByPlayer[index],
					setsOfCommitmentsByPlayer[index],
					hasEmptyShares[id],
				)
				machines[i] = &rngMachine
			}

			network := mpcutil.NewNetwork(machines, shuffleMsgs)
			network.SetCaptureHist(true)

			err := network.Run()
			Expect(err).ToNot(HaveOccurred())

			// ID of the first online machine
			i := 0
			for isOffline[machines[i].ID()] {
				i = i + 1
			}

			// Get the unbiased random numbers calculated by that RNG machine
			referenceRNShares := machines[i].(*rngutil.RngMachine).RandomNumbersShares()
			referenceCommitments := machines[i].(*rngutil.RngMachine).Commitments()

			// checker to check validity of verifiable shares against
			// commitments
			vssChecker := shamir.NewVSSChecker(h)

			for j := i + 1; j < len(machines); j++ {
				// Ignore if that machine is offline
				if isOffline[machines[j].ID()] {
					continue
				}

				rnShares := machines[j].(*rngutil.RngMachine).RandomNumbersShares()
				Expect(len(referenceRNShares)).To(Equal(len(rnShares)))

				// Every player has computed the same commitments for the batch
				// of unbiased random numbers
				comms := machines[j].(*rngutil.RngMachine).Commitments()
				for l, c := range comms {
					Expect(c.Eq(&referenceCommitments[l])).To(BeTrue())
				}

				// Verify that each machine's share of the unbiased random
				// number (for all batches) are valid with respect to the
				// reference commitments
				for l, vshare := range rnShares {
					Expect(vssChecker.IsValid(&comms[l], &vshare)).To(BeTrue())
				}
			}

			// Form the indices for machines that were online and a
			// reconstructor for those indices
			onlineIndices := make([]open.Fn, 0, len(machines))
			for j := 0; j < len(machines); j++ {
				if isOffline[machines[j].ID()] {
					continue
				}
				evaluationPoint := machines[j].(*rngutil.RngMachine).Index()
				onlineIndices = append(onlineIndices, evaluationPoint)
			}
			reconstructor := shamir.NewReconstructor(onlineIndices)

			// For every batch in batch size, the shares that every player has
			// should be consistent
			for i := 0; i < b; i++ {
				shares := make(shamir.Shares, 0, len(machines))

				for j := 0; j < len(machines); j++ {
					if isOffline[machines[j].ID()] {
						continue
					}

					vshare := machines[j].(*rngutil.RngMachine).RandomNumbersShares()[i]

					shares = append(shares, vshare.Share())
				}

				Expect(shamirutil.SharesAreConsistent(shares, &reconstructor, k-1)).ToNot(BeTrue())
				Expect(shamirutil.SharesAreConsistent(shares, &reconstructor, k)).To(BeTrue())
			}
		})
	})
})
