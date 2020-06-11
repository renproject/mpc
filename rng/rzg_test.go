package rng_test

import (
	"math/rand"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/renproject/secp256k1-go"
	"github.com/renproject/shamir"
	"github.com/renproject/shamir/curve"
	stu "github.com/renproject/shamir/testutil"

	"github.com/renproject/mpc/open"
	"github.com/renproject/mpc/rng"
	rtu "github.com/renproject/mpc/rng/testutil"
	mtu "github.com/renproject/mpc/testutil"
)

var _ = Describe("Rzg", func() {
	rand.Seed(int64(time.Now().Nanosecond()))

	Describe("RZG Properties", func() {
		var n, b, k int
		var indices []open.Fn
		var index open.Fn
		var h curve.Point
		var isZero bool

		// Setup is run before every test. It randomises the test parameters
		Setup := func() (
			int,
			[]open.Fn,
			open.Fn,
			int,
			int,
			curve.Point,
			bool,
		) {
			// n is the number of players participating in the RZG protocol
			// n ∈ [5, 10]
			n := 5 + rand.Intn(6)

			// indices represent the list of index for each player
			// They are Secp256k1N representations of sequential n values
			indices := stu.RandomIndices(n)

			// index denotes the current player's index
			// This is a randomly chosen index from indices
			index := indices[rand.Intn(len(indices))]

			// b is the total number of random numbers to be generated
			// in one execution of RZG protocol, i.e. the batch number
			b := 3 + rand.Intn(3)

			// k is the threshold for random number generation, or the
			// minimum number of shares required to reconstruct the secret
			// in the secret sharing scheme. Based on our BRNG to RZG scheme,
			// k is also the number of times BRNG needs to be run before
			// using their outputs to generate an unbiased random number
			k := 3 + rand.Intn(n-3)

			// h is the elliptic curve point, used as the Pedersen Commitment
			// Scheme Parameter
			h := curve.Random()

			return n, indices, index, b, k, h, true
		}

		BeforeEach(func() {
			n, indices, index, b, k, h, isZero = Setup()
		})

		Context("State Transitions and Events", func() {
			Specify("Initialise RZG machine to Init state", func() {
				event, rzger := rng.New(index, indices, uint32(b), uint32(k), h)

				Expect(event).To(Equal(rng.Initialised))
				Expect(rzger.State()).To(Equal(rng.Init))
				Expect(rzger.N()).To(Equal(n))
				Expect(rzger.BatchSize()).To(Equal(uint32(b)))
				Expect(rzger.Threshold()).To(Equal(uint32(k)))
				Expect(rzger.HasConstructedShares()).ToNot(BeTrue())

				for _, index := range indices {
					directedOpeningShares := rzger.DirectedOpenings(index)
					Expect(directedOpeningShares).To(BeNil())
				}
			})

			Context("When in Init state", func() {
				Specify("Reset", func() {
					// If an RZG machine in the Init state is reset, it continues to be
					// in the init state
					_, rzger := rng.New(index, indices, uint32(b), uint32(k), h)

					event := rzger.Reset()

					Expect(event).To(Equal(rng.Reset))
					Expect(rzger.State()).To(Equal(rng.Init))
					Expect(rzger.N()).To(Equal(n))
					Expect(rzger.BatchSize()).To(Equal(uint32(b)))
					Expect(rzger.Threshold()).To(Equal(uint32(k)))
					Expect(rzger.HasConstructedShares()).ToNot(BeTrue())

					for _, index := range indices {
						directedOpeningShares := rzger.DirectedOpenings(index)
						Expect(directedOpeningShares).To(BeNil())
					}
				})

				Specify("Supply valid BRNG shares/commitments", func() {
					// If an RZG machine in the Init state is supplied with
					// valid sets of shares and commitments from its own BRNG outputs
					// it transitions to the WaitingOpen state
					setsOfShares, setsOfCommitments := rtu.GetBrngOutputs(indices, index, b, k, h, isZero)

					// Once we have `b` sets of shares and commitments
					// we are ready to transition the RZG machine
					_, rzger := rng.New(index, indices, uint32(b), uint32(k), h)
					event := rzger.TransitionShares(setsOfShares, setsOfCommitments, isZero)

					Expect(event).To(Equal(rng.SharesConstructed))
					Expect(rzger.State()).To(Equal(rng.WaitingOpen))
					Expect(rzger.HasConstructedShares()).To(BeTrue())
				})

				Specify("Supply invalid sets of shares", func() {
					// If an RZG machine is supplied with BRNG output shares that don't match the
					// RZG machine's batch size, those shares are simply ignored. But the machine
					// still proceeds computing the commitments and moves to the WaitingOpen state
					// while returning the CommitmentsConstructed event
					setsOfShares, setsOfCommitments := rtu.GetBrngOutputs(indices, index, b, k, h, isZero)

					// Initialise two RZG replicas
					_, rzger := rng.New(index, indices, uint32(b), uint32(k), h)
					_, rzger2 := rng.New(index, indices, uint32(b), uint32(k), h)

					event := rzger.TransitionShares([]shamir.VerifiableShares{}, setsOfCommitments, isZero)
					event2 := rzger2.TransitionShares(setsOfShares, setsOfCommitments, isZero)

					Expect(event).To(Equal(rng.CommitmentsConstructed))
					Expect(rzger.State()).To(Equal(rng.WaitingOpen))
					Expect(rzger.HasConstructedShares()).To(BeTrue())

					Expect(event2).To(Equal(rng.SharesConstructed))
					Expect(rzger2.State()).To(Equal(rng.WaitingOpen))
					Expect(rzger2.HasConstructedShares()).To(BeTrue())

					// verify that the constructed shares are simply empty for rnger
					// while they are non-empty for rnger2
					for _, j := range indices {
						shares := rzger.DirectedOpenings(j)
						shares2 := rzger2.DirectedOpenings(j)
						for i, share := range shares {
							Expect(share).To(Equal(shamir.VerifiableShares{}))
							Expect(shares2[i]).ToNot(Equal(shamir.VerifiableShares{}))
						}
					}

					// verify that the constructed commitments are equal for both
					commitment := rzger.Commitments()
					commitment2 := rzger2.Commitments()
					Expect(len(commitment)).To(Equal(b))
					Expect(len(commitment)).To(Equal(len(commitment2)))
					for i, c := range commitment {
						Expect(c.Len()).To(Equal(k - 1))
						Expect(commitment2[i].Eq(&c)).To(BeTrue())
					}
				})

				Specify("Supply single invalid set of shares (not of threshold size)", func() {
					// If an RZG machine is supplied with BRNG output shares that match the
					// RZG machine's batch size, but with one or more of the set of shares
					// not of length equal to the reconstruction threshold, then it refutes
					// our assumption about the correctness of sets of shares in case they
					// are of appropriate batch size. The RZG machine hence panics, and continues
					// to be in its initial state
					setsOfShares, setsOfCommitments := rtu.GetBrngOutputs(indices, index, b, k, h, isZero)
					_, rzger := rng.New(index, indices, uint32(b), uint32(k), h)

					// fool around with one of the set of shares
					// so as to not let its length match the threshold
					setsOfShares[0] = setsOfShares[0][1:]

					Expect(func() { rzger.TransitionShares(setsOfShares, setsOfCommitments, isZero) }).To(Panic())

					Expect(rzger.State()).To(Equal(rng.Init))
					Expect(rzger.HasConstructedShares()).ToNot(BeTrue())
				})

				Specify("Supply invalid sets of commitments", func() {
					// If an RZG machine is supplied with BRNG outputs that have different
					// lengths (batch size) for shares and commitment, whereby the commitments
					// are of incorrect size, we panic because it refutes our assumption
					// about the correctness of the sets of commitments
					setsOfShares, setsOfCommitments := rtu.GetBrngOutputs(indices, index, b, k, h, isZero)
					_, rzger := rng.New(index, indices, uint32(b), uint32(k), h)
					j := rand.Intn(b)
					setsOfCommitments = append(setsOfCommitments[:j], setsOfCommitments[j+1:]...)
					Expect(func() { rzger.TransitionShares(setsOfShares, setsOfCommitments, isZero) }).To(Panic())

					Expect(rzger.State()).To(Equal(rng.Init))
					Expect(rzger.HasConstructedShares()).ToNot(BeTrue())
				})

				Specify("Supply invalid set of commitments", func() {
					// If an RZG machine is supplied with BRNG outputs that have at least one commitment,
					// not of appropriate capacity (k-1) we panic because it refutes our assumption
					// about the correctness of the sets of commitments
					setsOfShares, setsOfCommitments := rtu.GetBrngOutputs(indices, index, b, k, h, isZero)
					_, rzger := rng.New(index, indices, uint32(b), uint32(k), h)
					j := rand.Intn(b)
					ii := rand.Intn(k - 1)
					setsOfCommitments[j] = append(setsOfCommitments[j][:ii], setsOfCommitments[j][ii+1:]...)
					Expect(func() { rzger.TransitionShares(setsOfShares, setsOfCommitments, isZero) }).To(Panic())
				})

				Specify("Supply directed opening", func() {
					// If an RZG machine in the Init state is supplied with a valid directed opening
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
					setsOfShares, setsOfCommitments := rtu.GetBrngOutputs(indices, index, b, k, h, isZero)
					openings, _ := rtu.GetDirectedOpenings(setsOfShares, setsOfCommitments, index, isZero)

					// initialise player's RZG machine and supply openings
					_, rzger := rng.New(index, indices, uint32(b), uint32(k), h)
					event := rzger.TransitionOpen(from, openings)

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

				// TransitionToWaitingOpen generates a new instance of RZG machine
				// and transitions it to the `WaitingOpen` state
				TransitionToWaitingOpen := func(
					index open.Fn,
					indices []open.Fn,
					b, k int,
					h curve.Point,
				) {
					_, rzger = rng.New(index, indices, uint32(b), uint32(k), h)

					openingsByPlayer, _, ownSetsOfShares, ownSetsOfCommitments = rtu.GetAllDirectedOpenings(indices, index, b, k, h, isZero)

					event := rzger.TransitionShares(ownSetsOfShares, ownSetsOfCommitments, isZero)
					Expect(event).To(Equal(rng.SharesConstructed))
				}

				JustBeforeEach(func() {
					TransitionToWaitingOpen(index, indices, b, k, h)
				})

				Specify("Reset", func() {
					// When an RZG machine in the WaitingOpen state is reset, it transitions
					// to the Init state having forgotten its constructed shares
					event := rzger.Reset()

					Expect(event).To(Equal(rng.Reset))
					Expect(rzger.State()).To(Equal(rng.Init))
					Expect(rzger.HasConstructedShares()).ToNot(BeTrue())
				})

				Specify("Supply BRNG shares", func() {
					// When an RZG machine in the WaitingOpen state is supplied BRNG shares
					// it simply ignores them and continues to be in the same state
					setsOfShares, setsOfCommitments := rtu.GetBrngOutputs(indices, index, b, k, h, isZero)
					event := rzger.TransitionShares(setsOfShares, setsOfCommitments, isZero)

					Expect(event).To(Equal(rng.SharesIgnored))
					Expect(rzger.State()).To(Equal(rng.WaitingOpen))
				})

				Specify("Supply invalid directed opening", func() {
					// When the RZG machine receives an invalid set of directed openings from another player
					// in any form (mismatching length, invalid index of player, etc), it
					// simply ignores those openings and continues to be in the same state
					//
					// get a random player who is not the current RZG machine's player
					from := indices[rand.Intn(len(indices))]
					for from.Eq(&index) {
						from = indices[rand.Intn(len(indices))]
					}

					// Openings length not equal to batch size
					event := rzger.TransitionOpen(from, openingsByPlayer[from][1:])
					Expect(event).To(Equal(rng.OpeningsIgnored))
					Expect(rzger.State()).To(Equal(rng.WaitingOpen))

					// Sender index is randomly chosen, so does not exist in the initial player indices
					event = rzger.TransitionOpen(secp256k1.RandomSecp256k1N(), openingsByPlayer[from])
					Expect(event).To(Equal(rng.OpeningsIgnored))
					Expect(rzger.State()).To(Equal(rng.WaitingOpen))
				})

				Specify("Supply directed opening", func() {
					// When the RZG machine receives a valid set of directed openings from another player
					// it adds those to its opener and continues to be in the WaitingOpen state.
					//
					// get a random player who is not the current RZG machine's player
					from := indices[rand.Intn(len(indices))]
					for from.Eq(&index) {
						from = indices[rand.Intn(len(indices))]
					}

					event := rzger.TransitionOpen(from, openingsByPlayer[from])

					Expect(event).To(Equal(rng.OpeningsAdded))
					Expect(rzger.State()).To(Equal(rng.WaitingOpen))
				})

				Specify("Supply directed opening when k-1 openings are already ready", func() {
					// When the RZG machine receives a valid set of directed openings from another player
					// and if this is the kth set (including its own), then the RZG machine is ready
					// to reconstruct the b unbiased random numbers
					//
					// The own player's openings have already been processed
					count := 1

					for _, from := range indices {
						// Ignore if its the current RZG player
						if from.Eq(&index) {
							continue
						}

						if count == k-1 {
							event := rzger.TransitionOpen(from, openingsByPlayer[from])

							Expect(event).To(Equal(rng.RNGsReconstructed))
							Expect(rzger.State()).To(Equal(rng.Done))
							Expect(len(rzger.ReconstructedShares())).To(Equal(b))

							break
						}

						if count < k-1 {
							event := rzger.TransitionOpen(from, openingsByPlayer[from])

							Expect(event).To(Equal(rng.OpeningsAdded))
							Expect(rzger.State()).To(Equal(rng.WaitingOpen))
							count = count + 1
						}
					}
				})
			})

			Context("When in Done state", func() {
				var rzger rng.RNGer
				var openingsByPlayer map[open.Fn]shamir.VerifiableShares
				var ownSetsOfShares []shamir.VerifiableShares
				var ownSetsOfCommitments [][]shamir.Commitment

				// TransitionToDone generates a new instance of RZG machine and
				// transitions it to the `Done` state by providing own BRNG outputs
				// as well as other players' directed openings to reconstruct
				// all the unbiased random numbers
				TransitionToDone := func(
					index open.Fn,
					indices []open.Fn,
					b, k int,
					h curve.Point,
				) {
					_, rzger = rng.New(index, indices, uint32(b), uint32(k), h)

					openingsByPlayer, _, ownSetsOfShares, ownSetsOfCommitments = rtu.GetAllDirectedOpenings(indices, index, b, k, h, isZero)

					_ = rzger.TransitionShares(ownSetsOfShares, ownSetsOfCommitments, isZero)

					count := 1
					for _, from := range indices {
						if count == k {
							break
						}

						_ = rzger.TransitionOpen(from, openingsByPlayer[from])
					}

					Expect(rzger.State()).To(Equal(rng.Done))
					Expect(len(rzger.ReconstructedShares())).To(Equal(b))
				}

				JustBeforeEach(func() {
					TransitionToDone(index, indices, b, k, h)
				})

				Specify("Supply BRNG shares", func() {
					// When an RZG machine in the Done state is supplied own shares
					// it simply ignores them, and continues to be in the same state
					event := rzger.TransitionShares(ownSetsOfShares, ownSetsOfCommitments, isZero)

					Expect(event).To(Equal(rng.SharesIgnored))
					Expect(rzger.State()).To(Equal(rng.Done))
				})

				Specify("Supply directed opening", func() {
					// When an RZG machine in the Done state is supplied with valid
					// directed openings, it simply ignores them and continues
					// to be in the same state
					from := indices[rand.Intn(len(indices))]
					for from.Eq(&index) {
						from = indices[rand.Intn(len(indices))]
					}

					event := rzger.TransitionOpen(from, openingsByPlayer[from])

					Expect(event).To(Equal(rng.OpeningsIgnored))
					Expect(rzger.State()).To(Equal(rng.Done))
				})

				Specify("Reset", func() {
					// When an RZG machine in the Done state is supplied with a Reset
					// instruction, it transitions to the Init state, and forgets
					// its secrets and shares.
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

				openingsByPlayer, _, ownSetsOfShares, ownSetsOfCommitments := rtu.GetAllDirectedOpenings(indices, index, b, k, h, isZero)

				rzger.TransitionShares(ownSetsOfShares, ownSetsOfCommitments, isZero)

				// fetch the directed openings computed for the state machine itself
				selfOpenings := rzger.DirectedOpenings(index)

				// The directed openings from the RZG machine should be equal
				// to what we have computed in the utils
				for i, share := range selfOpenings {
					Expect(share.Eq(&openingsByPlayer[index][i])).To(BeTrue())
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
		var b, k int

		JustBeforeEach(func() {
			// Randomise RZG network scenario
			n := 5 + rand.Intn(6)
			indices := stu.RandomIndices(n)
			b = 3 + rand.Intn(3)
			k = 3 + rand.Intn(n-3)
			h := curve.Random()
			isZero := true

			// Machines (players) participating in the RZG protocol
			ids = make([]mtu.ID, n)
			machines = make([]mtu.Machine, n)

			// Get BRNG outputs for all players
			setsOfSharesByPlayer, setsOfCommitmentsByPlayer := rtu.GetAllSharesAndCommitments(indices, b, k, h, isZero)

			// Append machines to the network
			for i, index := range indices {
				id := mtu.ID(i)
				rngMachine := rtu.NewRngMachine(
					id, index, indices, b, k, h, isZero,
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

		Specify("RZG machines should reconstruct zero as all random numbers", func() {
			err := network.Run()
			Expect(err).ToNot(HaveOccurred())

			// ID of the first online machine
			i := 0
			for isOffline[machines[i].ID()] {
				i = i + 1
			}

			// Get the unbiased random numbers calculated by that RZG machine
			referenceRNShares := machines[i].(*rtu.RngMachine).RandomNumbersShares()
			referenceCommitments := machines[i].(*rtu.RngMachine).Commitments()

			for j := i + 1; j < len(machines); j++ {
				// Ignore if that machine is offline
				if isOffline[machines[j].ID()] {
					continue
				}

				rnShares := machines[j].(*rtu.RngMachine).RandomNumbersShares()
				rnCommitments := machines[j].(*rtu.RngMachine).Commitments()
				Expect(len(referenceRNShares)).To(Equal(len(rnShares)))

				for l, c := range rnCommitments {
					Expect(c.Eq(&referenceCommitments[l])).To(BeTrue())
				}
			}

			// TODO:
			// Verify that each machine's share of the unbiased random number (all zeroes)
			// are valid with respect to the reference commitments

			// For every batch in batch size, the shares that every player has
			// should be consistent
			for i := 0; i < b; i++ {
				indices := make([]open.Fn, 0, len(machines))
				shares := make(shamir.Shares, 0, len(machines))

				for j := 0; j < len(machines); j++ {
					if isOffline[machines[j].ID()] {
						continue
					}

					evaluationPoint := machines[j].(*rtu.RngMachine).Index()
					evaluation := machines[j].(*rtu.RngMachine).RandomNumbersShares()[i]
					share := shamir.NewShare(evaluationPoint, evaluation)

					indices = append(indices, evaluationPoint)
					shares = append(shares, share)
				}

				reconstructor := shamir.NewReconstructor(indices)
				Expect(stu.SharesAreConsistent(shares, &reconstructor, k-1)).ToNot(BeTrue())
				Expect(stu.SharesAreConsistent(shares, &reconstructor, k)).To(BeTrue())

				expectedSecret := secp256k1.ZeroSecp256k1N()
				secret, err := reconstructor.Open(shares)
				Expect(err).ToNot(HaveOccurred())
				Expect(secret.Eq(&expectedSecret)).To(BeTrue())
			}
		})
	})
})
