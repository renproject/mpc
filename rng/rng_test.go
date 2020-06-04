package rng_test

import (
	"bytes"
	"math/rand"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/renproject/shamir"
	"github.com/renproject/shamir/curve"
	stu "github.com/renproject/shamir/testutil"
	"github.com/renproject/surge"

	"github.com/renproject/mpc/open"
	"github.com/renproject/mpc/rng"
	rtu "github.com/renproject/mpc/rng/testutil"
	mtu "github.com/renproject/mpc/testutil"
)

var _ = Describe("Rng", func() {
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
			indices := stu.SequentialIndices(n)

			// index denotes the current player's index
			// This is a randomly chosen index from indices
			index := indices[rand.Intn(len(indices))]

			// b is the total number of random numbers to be generated
			// in one execution of RNG protocol, i.e. the batch number
			b := 3 + rand.Intn(3)

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

		Context("State Transitions and Events", func() {
			Specify("Initialise RNG machine to Init state", func() {
				event, rnger := rng.New(index, indices, uint32(b), uint32(k), h)

				Expect(event).To(Equal(rng.Initialised))
				Expect(rnger.State()).To(Equal(rng.Init))
				Expect(rnger.N()).To(Equal(n))
				Expect(rnger.BatchSize()).To(Equal(uint32(b)))
				Expect(rnger.Threshold()).To(Equal(uint32(k)))
				Expect(rnger.HasConstructedShares()).ToNot(BeTrue())
			})

			Context("When in Init state", func() {
				Specify("Reset", func() {
					// If an RNG machine in the Init state is reset, it continues to be
					// in the init state
					_, rnger := rng.New(index, indices, uint32(b), uint32(k), h)

					event := rnger.Reset()

					Expect(event).To(Equal(rng.Reset))
					Expect(rnger.State()).To(Equal(rng.Init))
					Expect(rnger.N()).To(Equal(n))
					Expect(rnger.BatchSize()).To(Equal(uint32(b)))
					Expect(rnger.Threshold()).To(Equal(uint32(k)))
					Expect(rnger.HasConstructedShares()).ToNot(BeTrue())
				})

				Specify("Supply valid BRNG shares/commitments", func() {
					// If an RNG machine in the Init state is supplied with
					// valid sets of shares and commitments from its own BRNG outputs
					// it transitions to the WaitingOpen state
					setsOfShares, setsOfCommitments := rtu.GetBrngOutputs(indices, index, b, k, h)

					// Once we have `b` sets of shares and commitments
					// we are ready to transition the RNG machine
					_, rnger := rng.New(index, indices, uint32(b), uint32(k), h)
					event := rnger.TransitionShares(setsOfShares, setsOfCommitments)

					Expect(event).To(Equal(rng.SharesConstructed))
					Expect(rnger.State()).To(Equal(rng.WaitingOpen))
					Expect(rnger.HasConstructedShares()).To(BeTrue())
				})

				Specify("Supply invalid sets of shares", func() {
					// If an RNG machine is supplied with BRNG output shares that don't match the
					// RNG machine's batch size, those shares are simply ignored. But the machine
					// still proceeds computing the commitments and moves to the WaitingOpen state
					// while returning the CommitmentsConstructed event
					setsOfShares, setsOfCommitments := rtu.GetBrngOutputs(indices, index, b, k, h)

					// Initialise two RNG replicas
					_, rnger := rng.New(index, indices, uint32(b), uint32(k), h)
					_, rnger2 := rng.New(index, indices, uint32(b), uint32(k), h)

					event := rnger.TransitionShares([]shamir.VerifiableShares{}, setsOfCommitments)
					event2 := rnger2.TransitionShares(setsOfShares, setsOfCommitments)

					Expect(event).To(Equal(rng.CommitmentsConstructed))
					Expect(rnger.State()).To(Equal(rng.WaitingOpen))
					Expect(rnger.HasConstructedShares()).To(BeTrue())

					Expect(event2).To(Equal(rng.SharesConstructed))
					Expect(rnger2.State()).To(Equal(rng.WaitingOpen))
					Expect(rnger2.HasConstructedShares()).To(BeTrue())

					// verify that the constructed shares are simply empty for rnger
					// while they are non-empty for rnger2
					shares, commitments := rnger.ConstructedSetsOfShares()
					shares2, commitments2 := rnger2.ConstructedSetsOfShares()
					for i, share := range shares {
						Expect(share).To(Equal(shamir.VerifiableShares{}))
						Expect(shares2[i]).ToNot(Equal(shamir.VerifiableShares{}))
					}

					// verify that the constructed commitments are equal for both
					Expect(len(commitments)).To(Equal(b))
					Expect(len(commitments)).To(Equal(len(commitments2)))
					for i, cs := range commitments {
						Expect(len(cs)).To(Equal(len(indices)))
						for j, c := range cs {
							Expect(commitments2[i][j].Eq(&c)).To(BeTrue())
						}
					}
				})

				Specify("Supply single invalid set of shares (not of threshold size)", func() {
					// If an RNG machine is supplied with BRNG output shares that match the
					// RNG machine's batch size, but with one or more of the set of shares
					// not of length equal to the reconstruction threshold, then it refutes
					// our assumption about the correctness of sets of shares in case they
					// are of appropriate batch size. The RNG machine hence panics, and continues
					// to be in its initial state
					setsOfShares, setsOfCommitments := rtu.GetBrngOutputs(indices, index, b, k, h)
					_, rnger := rng.New(index, indices, uint32(b), uint32(k), h)

					// fool around with one of the set of shares
					// so as to not let its length match the threshold
					setsOfShares[0] = setsOfShares[0][1:]

					Expect(func() { rnger.TransitionShares(setsOfShares, setsOfCommitments) }).To(Panic())

					Expect(rnger.State()).To(Equal(rng.Init))
					Expect(rnger.HasConstructedShares()).ToNot(BeTrue())
				})

				Specify("Supply invalid sets of commitments", func() {
					// If an RNG machine is supplied with BRNG outputs that have different
					// lengths (batch size) for shares and commitment, whereby the commitments
					// are of incorrect size, we panic because it refutes our assumption
					// about the correctness of the sets of commitments
					setsOfShares, setsOfCommitments := rtu.GetBrngOutputs(indices, index, b, k, h)
					_, rnger := rng.New(index, indices, uint32(b), uint32(k), h)
					j := rand.Intn(b)
					setsOfCommitments = append(setsOfCommitments[:j], setsOfCommitments[j+1:]...)
					Expect(func() { rnger.TransitionShares(setsOfShares, setsOfCommitments) }).To(Panic())

					Expect(rnger.State()).To(Equal(rng.Init))
					Expect(rnger.HasConstructedShares()).ToNot(BeTrue())
				})

				Specify("Supply directed opening", func() {
					// If an RNG machine in the Init state is supplied with a valid directed opening
					// it does not react to that and simply ignores it
					// Only after having constructed its own shares, and being in the WaitingOpen
					// state, it will handle the directed openings

					// get a `from` index that is different than own index
					from := indices[rand.Intn(len(indices))]
					for from.Eq(&index) {
						from = indices[rand.Intn(len(indices))]
					}

					// get this `from` index's sets of shares and commitments
					// also compute its openings for the player
					setsOfShares, setsOfCommitments := rtu.GetBrngOutputs(indices, index, b, k, h)
					openings, commitments := rtu.GetDirectedOpenings(setsOfShares, setsOfCommitments, index)

					// initialise player's RNG machine and supply openings
					_, rnger := rng.New(index, indices, uint32(b), uint32(k), h)
					event := rnger.TransitionOpen(from, openings, commitments)

					Expect(event).To(Equal(rng.OpeningsIgnored))
					Expect(rnger.State()).To(Equal(rng.Init))
					Expect(rnger.HasConstructedShares()).ToNot(BeTrue())
				})
			})

			Context("When in WaitingOpen state", func() {
				var rnger rng.RNGer
				var openingsByPlayer map[open.Fn]shamir.VerifiableShares
				var commitmentsByPlayer map[open.Fn][]shamir.Commitment
				var ownSetsOfShares []shamir.VerifiableShares
				var ownSetsOfCommitments [][]shamir.Commitment

				// TransitionToWaitingOpen generates a new instance of RNG machine
				// and transitions it to the `WaitingOpen` state
				TransitionToWaitingOpen := func(
					index open.Fn,
					indices []open.Fn,
					b, k int,
					h curve.Point,
				) {
					_, rnger = rng.New(index, indices, uint32(b), uint32(k), h)

					openingsByPlayer, commitmentsByPlayer, ownSetsOfShares, ownSetsOfCommitments = rtu.GetAllDirectedOpenings(indices, index, b, k, h)

					event := rnger.TransitionShares(ownSetsOfShares, ownSetsOfCommitments)
					Expect(event).To(Equal(rng.SharesConstructed))
				}

				JustBeforeEach(func() {
					TransitionToWaitingOpen(index, indices, b, k, h)
				})

				Specify("Reset", func() {
					// When an RNG machine in the WaitingOpen state is reset, it transitions
					// to the Init state having forgotten its constructed shares
					event := rnger.Reset()

					Expect(event).To(Equal(rng.Reset))
					Expect(rnger.State()).To(Equal(rng.Init))
					Expect(rnger.HasConstructedShares()).ToNot(BeTrue())
				})

				Specify("Supply BRNG shares", func() {
					// When an RNG machine in the WaitingOpen state is supplied BRNG shares
					// it simply ignores them and continues to be in the same state
					setsOfShares, setsOfCommitments := rtu.GetBrngOutputs(indices, index, b, k, h)
					event := rnger.TransitionShares(setsOfShares, setsOfCommitments)

					Expect(event).To(Equal(rng.SharesIgnored))
					Expect(rnger.State()).To(Equal(rng.WaitingOpen))
				})

				Specify("Supply directed opening", func() {
					// When the RNG machine receives a valid set of directed openings from another player
					// it adds those to its opener and continues to be in the WaitingOpen state.
					//
					// get a random player who is not the current RNG machine's player
					from := indices[rand.Intn(len(indices))]
					for from.Eq(&index) {
						from = indices[rand.Intn(len(indices))]
					}

					event := rnger.TransitionOpen(from, openingsByPlayer[from], commitmentsByPlayer[from])

					Expect(event).To(Equal(rng.OpeningsAdded))
					Expect(rnger.State()).To(Equal(rng.WaitingOpen))
				})

				Specify("Supply directed opening when k-1 openings are already ready", func() {
					// When the RNG machine receives a valid set of directed openings from another player
					// and if this is the kth set (including its own), then the RNG machine is ready
					// to reconstruct the b unbiased random numbers
					//
					// The own player's openings have already been processed
					count := 1

					for _, from := range indices {
						// Ignore if its the current RNG player
						if from.Eq(&index) {
							continue
						}

						if count == k-1 {
							event := rnger.TransitionOpen(from, openingsByPlayer[from], commitmentsByPlayer[from])

							Expect(event).To(Equal(rng.RNGsReconstructed))
							Expect(rnger.State()).To(Equal(rng.Done))
							Expect(len(rnger.ReconstructedRandomNumbers())).To(Equal(b))

							break
						}

						if count < k-1 {
							event := rnger.TransitionOpen(from, openingsByPlayer[from], commitmentsByPlayer[from])

							Expect(event).To(Equal(rng.OpeningsAdded))
							Expect(rnger.State()).To(Equal(rng.WaitingOpen))
							count = count + 1
						}
					}
				})
			})

			Context("When in Done state", func() {
				var rnger rng.RNGer
				var openingsByPlayer map[open.Fn]shamir.VerifiableShares
				var commitmentsByPlayer map[open.Fn][]shamir.Commitment
				var ownSetsOfShares []shamir.VerifiableShares
				var ownSetsOfCommitments [][]shamir.Commitment

				// TransitionToDone generates a new instance of RNG machine and
				// transitions it to the `Done` state by providing own BRNG outputs
				// as well as other players' directed openings to reconstruct
				// all the unbiased random numbers
				TransitionToDone := func(
					index open.Fn,
					indices []open.Fn,
					b, k int,
					h curve.Point,
				) {
					_, rnger = rng.New(index, indices, uint32(b), uint32(k), h)

					openingsByPlayer, commitmentsByPlayer, ownSetsOfShares, ownSetsOfCommitments = rtu.GetAllDirectedOpenings(indices, index, b, k, h)

					_ = rnger.TransitionShares(ownSetsOfShares, ownSetsOfCommitments)

					count := 1
					for _, from := range indices {
						if count == k {
							break
						}

						_ = rnger.TransitionOpen(from, openingsByPlayer[from], commitmentsByPlayer[from])
					}

					Expect(rnger.State()).To(Equal(rng.Done))
					Expect(len(rnger.ReconstructedRandomNumbers())).To(Equal(b))
				}

				JustBeforeEach(func() {
					TransitionToDone(index, indices, b, k, h)
				})

				Specify("Supply BRNG shares", func() {
					// When an RNG machine in the Done state is supplied own shares
					// it simply ignores them, and continues to be in the same state
					event := rnger.TransitionShares(ownSetsOfShares, ownSetsOfCommitments)

					Expect(event).To(Equal(rng.SharesIgnored))
					Expect(rnger.State()).To(Equal(rng.Done))
				})

				Specify("Supply directed opening", func() {
					// When an RNG machine in the Done state is supplied with valid
					// directed openings, it simply ignores them and continues
					// to be in the same state
					from := indices[rand.Intn(len(indices))]
					for from.Eq(&index) {
						from = indices[rand.Intn(len(indices))]
					}

					event := rnger.TransitionOpen(from, openingsByPlayer[from], commitmentsByPlayer[from])

					Expect(event).To(Equal(rng.OpeningsIgnored))
					Expect(rnger.State()).To(Equal(rng.Done))
				})

				Specify("Reset", func() {
					// When an RNG machine in the Done state is supplied with a Reset
					// instruction, it transitions to the Init state, and forgets
					// its secrets and shares.
					event := rnger.Reset()

					Expect(event).To(Equal(rng.Reset))
					Expect(rnger.State()).To(Equal(rng.Init))
					Expect(rnger.HasConstructedShares()).ToNot(BeTrue())
					Expect(rnger.ReconstructedRandomNumbers()).To(BeNil())
				})
			})
		})

		Context("Computations", func() {
			It("Correctly computes own shares and commitments", func() {
				_, rnger := rng.New(index, indices, uint32(b), uint32(k), h)

				openingsByPlayer, commitmentsByPlayer, ownSetsOfShares, ownSetsOfCommitments := rtu.GetAllDirectedOpenings(indices, index, b, k, h)

				rnger.TransitionShares(ownSetsOfShares, ownSetsOfCommitments)

				// fetch the directed openings computed for the state machine itself
				selfOpenings, selfCommitments := rnger.DirectedOpenings(index)

				// The directed openings from the RNG machine should be equal
				// to what we have computed in the utils
				for i, share := range selfOpenings {
					Expect(share.Eq(&openingsByPlayer[index][i])).To(BeTrue())
					Expect(selfCommitments[i].Eq(&commitmentsByPlayer[index][i])).To(BeTrue())
				}
			})
		})

		Context("Marshaling and Unmarshaling", func() {
			var rnger rng.RNGer
			var openingsByPlayer map[open.Fn]shamir.VerifiableShares
			var commitmentsByPlayer map[open.Fn][]shamir.Commitment
			var ownSetsOfShares []shamir.VerifiableShares
			var ownSetsOfCommitments [][]shamir.Commitment

			JustBeforeEach(func() {
				_, rnger = rng.New(index, indices, uint32(b), uint32(k), h)
				openingsByPlayer, commitmentsByPlayer, ownSetsOfShares, ownSetsOfCommitments = rtu.GetAllDirectedOpenings(indices, index, b, k, h)

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
				Expect(rnger.ReconstructedRandomNumbers()).To(Equal(rnger2.ReconstructedRandomNumbers()))

				expectedShares, expectedCommitments := rnger.ConstructedSetsOfShares()
				shares, commitments := rnger2.ConstructedSetsOfShares()

				Expect(expectedShares).To(Equal(shares))
				Expect(expectedCommitments).To(Equal(commitments))
			})

			It("should correctly marshal and unmarshal (Done)", func() {
				count := 1
				for _, from := range indices {
					if count == k {
						break
					}

					_ = rnger.TransitionOpen(from, openingsByPlayer[from], commitmentsByPlayer[from])
				}
				Expect(rnger.State()).To(Equal(rng.Done))
				Expect(len(rnger.ReconstructedRandomNumbers())).To(Equal(b))

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
				Expect(rnger.ReconstructedRandomNumbers()).To(Equal(rnger2.ReconstructedRandomNumbers()))

				expectedShares, expectedCommitments := rnger.ConstructedSetsOfShares()
				shares, commitments := rnger2.ConstructedSetsOfShares()

				Expect(expectedShares).To(Equal(shares))
				Expect(expectedCommitments).To(Equal(commitments))
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
		var ids []mtu.ID
		var machines []mtu.Machine
		var network mtu.Network
		var shuffleMsgs func([]mtu.Message)
		var isOffline map[mtu.ID]bool

		JustBeforeEach(func() {
			// Randomise RNG network scenario
			n := 5 + rand.Intn(6)
			indices := stu.SequentialIndices(n)
			b := 3 + rand.Intn(3)
			k := 3 + rand.Intn(n-3)
			h := curve.Random()

			// Machines (players) participating in the RNG protocol
			ids = make([]mtu.ID, n)
			machines = make([]mtu.Machine, n)

			// Get BRNG outputs for all players
			setsOfSharesByPlayer, setsOfCommitmentsByPlayer := rtu.GetAllSharesAndCommitments(indices, b, k, h)

			// Append machines to the network
			for i, index := range indices {
				id := mtu.ID(i)
				rngMachine := rtu.NewRngMachine(
					id, index, indices, b, k, h,
					setsOfSharesByPlayer[index],
					setsOfCommitmentsByPlayer[index],
				)
				machines[i] = &rngMachine
				ids[i] = id
			}

			nOffline := rand.Intn(n - k + 1)
			shuffleMsgs, isOffline = mtu.MessageShufflerDropper(ids, nOffline)
			network = mtu.NewNetwork(machines, shuffleMsgs)
			network.SetCaptureHist(true)
		})

		Specify("RNG machines should reconstruct the same random numbers", func() {
			err := network.Run()
			Expect(err).ToNot(HaveOccurred())

			// ID of the first online machine
			i := 0
			for isOffline[machines[i].ID()] {
				i = i + 1
			}

			// Get the unbiased random numbers calculated by that RNG machine
			referenceRandomNumbers := machines[i].(*rtu.RngMachine).UnbiasedRandomNumbers()

			for j := i + 1; j < len(machines); j++ {
				// Ignore if that machine is offline
				if isOffline[machines[j].ID()] {
					continue
				}

				randomNumbers := machines[j].(*rtu.RngMachine).UnbiasedRandomNumbers()

				Expect(len(referenceRandomNumbers)).To(Equal(len(randomNumbers)))
				for ii, randomNumber := range randomNumbers {
					Expect(randomNumber.Eq(&referenceRandomNumbers[ii])).To(BeTrue())
				}
			}
		})
	})
})
