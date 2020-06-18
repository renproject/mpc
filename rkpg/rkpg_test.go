package rkpg_test

import (
	"bytes"
	"math/rand"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/renproject/shamir"
	"github.com/renproject/shamir/curve"
	"github.com/renproject/shamir/shamirutil"

	"github.com/renproject/mpc/mpcutil"
	"github.com/renproject/mpc/open"
	"github.com/renproject/mpc/rkpg"
	"github.com/renproject/mpc/rkpg/rkpgutil"
	"github.com/renproject/mpc/rng/rngutil"
)

var _ = Describe("Rkpg", func() {
	rand.Seed(int64(time.Now().Nanosecond()))

	Describe("RKPG Properties", func() {
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

		InStateInit := func(
			index open.Fn,
			indices []open.Fn,
			b, k int,
			h curve.Point,
		) rkpg.RKPGer {
			event, rkpger := rkpg.New(index, indices, uint32(b), uint32(k), h)
			Expect(event).To(Equal(rkpg.Initialised))

			return rkpger
		}

		InStateWaitingRNG := func(
			index open.Fn,
			indices []open.Fn,
			b, k int,
			h curve.Point,
			rngShares []shamir.VerifiableShares,
			rngCommitments [][]shamir.Commitment,
		) rkpg.RKPGer {
			rkpger := InStateInit(index, indices, b, k, h)

			event := rkpger.TransitionRNGShares(rngShares, rngCommitments)
			Expect(event).To(Equal(rkpg.RNGInputsAccepted))
			Expect(rkpger.State()).To(Equal(rkpg.WaitingRNG))

			return rkpger
		}

		InStateRNGsReady := func(
			index open.Fn,
			indices []open.Fn,
			b, k int,
			h curve.Point,
			rngShares []shamir.VerifiableShares,
			rngCommitments [][]shamir.Commitment,
			rngOpeningsByPlayer map[open.Fn]shamir.VerifiableShares,
		) rkpg.RKPGer {
			rkpger := InStateWaitingRNG(index, indices, b, k, h, rngShares, rngCommitments)

			for _, fromIndex := range indices {
				if fromIndex.Eq(&index) {
					continue
				}

				event := rkpger.TransitionRNGOpen(fromIndex, rngOpeningsByPlayer[fromIndex])
				if event == rkpg.RNGReady {
					break
				}
			}

			Expect(rkpger.State()).To(Equal(rkpg.RNGsReady))

			return rkpger
		}

		InStateWaitingRZG := func(
			index open.Fn,
			indices []open.Fn,
			b, k int,
			h curve.Point,
			rngShares []shamir.VerifiableShares,
			rngCommitments [][]shamir.Commitment,
			rngOpeningsByPlayer map[open.Fn]shamir.VerifiableShares,
			rzgShares []shamir.VerifiableShares,
			rzgCommitments [][]shamir.Commitment,
		) rkpg.RKPGer {
			rkpger := InStateRNGsReady(index, indices, b, k, h, rngShares, rngCommitments, rngOpeningsByPlayer)

			event := rkpger.TransitionRZGShares(rzgShares, rzgCommitments)
			Expect(event).To(Equal(rkpg.RZGInputsAccepted))
			Expect(rkpger.State()).To(Equal(rkpg.WaitingRZG))

			return rkpger
		}

		InStateWaitingOpen := func(
			index open.Fn,
			indices []open.Fn,
			b, k int,
			h curve.Point,
			rngShares []shamir.VerifiableShares,
			rngCommitments [][]shamir.Commitment,
			rngOpeningsByPlayer map[open.Fn]shamir.VerifiableShares,
			rzgShares []shamir.VerifiableShares,
			rzgCommitments [][]shamir.Commitment,
			rzgOpeningsByPlayer map[open.Fn]shamir.VerifiableShares,
		) rkpg.RKPGer {
			rkpger := InStateWaitingRZG(index, indices, b, k, h, rngShares, rngCommitments, rngOpeningsByPlayer, rzgShares, rzgCommitments)

			for _, fromIndex := range indices {
				if fromIndex.Eq(&index) {
					continue
				}

				event := rkpger.TransitionRZGOpen(fromIndex, rzgOpeningsByPlayer[fromIndex])
				if event == rkpg.RZGReady {
					break
				}
			}

			Expect(rkpger.State()).To(Equal(rkpg.WaitingOpen))

			return rkpger
		}

		InState := func(
			state rkpg.State,
			indices []open.Fn,
			b, k int,
			h curve.Point,
			rngSharesByPlayer map[open.Fn][]shamir.VerifiableShares,
			rngCommitmentsByPlayer map[open.Fn][][]shamir.Commitment,
			rzgSharesByPlayer map[open.Fn][]shamir.VerifiableShares,
			rzgCommitmentsByPlayer map[open.Fn][][]shamir.Commitment,
		) []rkpg.RKPGer {
			// Declare slice to hold the RKPGers
			rkpgers := make([]rkpg.RKPGer, len(indices))

			// Create new RKPGers
			for i, index := range indices {
				event, rkpger := rkpg.New(index, indices, uint32(b), uint32(k), h)
				Expect(event).To(Equal(rkpg.Initialised))
				Expect(rkpger.State()).To(Equal(rkpg.Init))
				rkpgers[i] = rkpger
			}
			if state == rkpg.Init {
				return rkpgers
			}

			// Transition to WaitingRNG state
			for i, index := range indices {
				event := rkpgers[i].TransitionRNGShares(
					rngSharesByPlayer[index],
					rngCommitmentsByPlayer[index],
				)
				Expect(event).To(Equal(rkpg.RNGInputsAccepted))
				Expect(rkpgers[i].State()).To(Equal(rkpg.WaitingRNG))
			}
			if state == rkpg.WaitingRNG {
				return rkpgers
			}

			// Transition to RNGsReady state
			for i, ownIndex := range indices {
				for j, otherIndex := range indices {
					if otherIndex.Eq(&ownIndex) {
						continue
					}

					rngOpenings := rkpgers[j].DirectedRNGOpenings(ownIndex)
					event := rkpgers[i].TransitionRNGOpen(otherIndex, rngOpenings)
					if event == rkpg.RNGReady {
						break
					}
				}

				Expect(rkpgers[i].State()).To(Equal(rkpg.RNGsReady))
			}
			if state == rkpg.RNGsReady {
				return rkpgers
			}

			// Transition to WaitingRZG state
			for i, index := range indices {
				event := rkpgers[i].TransitionRZGShares(
					rzgSharesByPlayer[index],
					rzgCommitmentsByPlayer[index],
				)
				Expect(event).To(Equal(rkpg.RZGInputsAccepted))
				Expect(rkpgers[i].State()).To(Equal(rkpg.WaitingRZG))
			}
			if state == rkpg.WaitingRZG {
				return rkpgers
			}

			// Transition to WaitingOpen state
			for i, ownIndex := range indices {
				for j, otherIndex := range indices {
					if otherIndex.Eq(&ownIndex) {
						continue
					}

					rzgOpenings := rkpgers[j].DirectedRZGOpenings(ownIndex)
					event := rkpgers[i].TransitionRZGOpen(otherIndex, rzgOpenings)
					if event == rkpg.RZGReady {
						break
					}
				}

				Expect(rkpgers[i].State()).To(Equal(rkpg.WaitingOpen))
			}
			if state == rkpg.WaitingOpen {
				return rkpgers
			}

			// Transition to Done state
			for i, ownIndex := range indices {
				for j, otherIndex := range indices {
					if otherIndex.Eq(&ownIndex) {
						continue
					}

					hidingOpenings := rkpgers[j].HidingOpenings()
					event := rkpgers[i].TransitionHidingOpenings(hidingOpenings)
					if event == rkpg.KeyPairsReady {
						break
					}
				}

				Expect(rkpgers[i].State()).To(Equal(rkpg.Done))
			}

			return rkpgers
		}

		RandomIndexExcept := func(
			index open.Fn,
			indices []open.Fn,
		) (int, open.Fn) {
			j := rand.Intn(len(indices))
			for indices[j].Eq(&index) {
				j = rand.Intn(len(indices))
			}

			return j, indices[j]
		}

		BeforeEach(func() {
			n, indices, index, b, k, h = Setup()
		})

		Context("Initialisation", func() {
			Specify("Initialise RKPG state machine", func() {
				event, rkpger := rkpg.New(index, indices, uint32(b), uint32(k), h)

				Expect(event).To(Equal(rkpg.Initialised))
				Expect(rkpger.State()).To(Equal(rkpg.Init))
				Expect(rkpger.N()).To(Equal(n))
				Expect(rkpger.BatchSize()).To(Equal(uint32(b)))
				Expect(rkpger.Threshold()).To(Equal(uint32(k)))
			})
		})

		Context("State Transitions", func() {
			Context("Init state", func() {
				var rkpger rkpg.RKPGer
				var rngShares []shamir.VerifiableShares
				var rngCommitments [][]shamir.Commitment

				JustBeforeEach(func() {
					rngShares, rngCommitments = rngutil.GetBrngOutputs(
						indices, index, b, k, h, false,
					)

					rkpger = InStateInit(index, indices, b, k, h)
				})

				Specify("Supply valid BRNG shares for RNG", func() {
					event := rkpger.TransitionRNGShares(rngShares, rngCommitments)

					Expect(event).To(Equal(rkpg.RNGInputsAccepted))
					Expect(rkpger.State()).To(Equal(rkpg.WaitingRNG))
					for i := range indices {
						directedOpenings := rkpger.DirectedRNGOpenings(indices[i])
						Expect(cap(directedOpenings)).To(Equal(b))
						Expect(len(directedOpenings)).To(Equal(b))
					}
				})

				Specify("Supply invalid BRNG shares with valid commitments for RNG", func() {
					event := rkpger.TransitionRNGShares([]shamir.VerifiableShares{}, rngCommitments)

					Expect(event).To(Equal(rkpg.RNGInputsAccepted))
					Expect(rkpger.State()).To(Equal(rkpg.WaitingRNG))
					for i := range indices {
						directedOpenings := rkpger.DirectedRNGOpenings(indices[i])
						Expect(cap(directedOpenings)).To(Equal(b))
						Expect(len(directedOpenings)).To(Equal(0))
					}
				})

				Specify("Supply invalid BRNG commitments (defeats the assumption) for RNG", func() {
					Expect(func() {
						rkpger.TransitionRNGShares(rngShares, rngCommitments[1:])
					}).To(Panic())

					rngShares[0] = rngShares[0][1:]
					Expect(func() {
						rkpger.TransitionRNGShares(rngShares, rngCommitments)
					}).To(Panic())
				})

				It("Should ignore any other message", func() {
					rzgShares, rzgCommitments := rngutil.GetBrngOutputs(
						indices, index, b, k, h, true,
					)
					event := rkpger.TransitionRZGShares(rzgShares, rzgCommitments)
					Expect(event).To(Equal(rkpg.RZGInputsIgnored))
					Expect(rkpger.State()).To(Equal(rkpg.Init))
				})
			})

			Context("WaitingRNG state", func() {
				var rkpger rkpg.RKPGer
				var rngShares []shamir.VerifiableShares
				var rngCommitments [][]shamir.Commitment
				var rngOpeningsByPlayer map[open.Fn]shamir.VerifiableShares

				JustBeforeEach(func() {
					rngOpeningsByPlayer, _, rngShares, rngCommitments = rngutil.GetAllDirectedOpenings(
						indices, index, b, k, h, false,
					)

					rkpger = InStateWaitingRNG(index, indices, b, k, h, rngShares, rngCommitments)
				})

				Specify("Supply valid RNG openings", func() {
					_, otherIndex := RandomIndexExcept(index, indices)

					event := rkpger.TransitionRNGOpen(otherIndex, rngOpeningsByPlayer[otherIndex])
					Expect(event).To(Equal(rkpg.RNGOpeningsAccepted))
					Expect(rkpger.State()).To(Equal(rkpg.WaitingRNG))
				})

				Specify("Supply kth valid RNG openings", func() {
					// The player has already passed their own openings
					count := 1

					for _, fromIndex := range indices {
						if fromIndex.Eq(&index) {
							continue
						}

						// If this is the kth set of openings
						if count == k-1 {
							event := rkpger.TransitionRNGOpen(fromIndex, rngOpeningsByPlayer[fromIndex])
							Expect(event).To(Equal(rkpg.RNGReady))
							Expect(rkpger.State()).To(Equal(rkpg.RNGsReady))
							break
						}

						// If this is not the kth set of openings
						if count < k-1 {
							event := rkpger.TransitionRNGOpen(fromIndex, rngOpeningsByPlayer[fromIndex])
							Expect(event).To(Equal(rkpg.RNGOpeningsAccepted))
							Expect(rkpger.State()).To(Equal(rkpg.WaitingRNG))
							count = count + 1
						}
					}
				})

				Specify("Supply invalid RNG openings", func() {
					// Invalid length for the set of openings
					_, otherIndex := RandomIndexExcept(index, indices)
					event := rkpger.TransitionRNGOpen(otherIndex, rngOpeningsByPlayer[otherIndex][1:])
					Expect(event).To(Equal(rkpg.RNGOpeningsIgnored))
					Expect(rkpger.State()).To(Equal(rkpg.WaitingRNG))

					// Perturb index
					// Choose a random share that will be perturbed
					l := rand.Intn(b)
					_, otherIndex = RandomIndexExcept(index, indices)
					shamirutil.PerturbIndex(&rngOpeningsByPlayer[otherIndex][l])
					event = rkpger.TransitionRNGOpen(otherIndex, rngOpeningsByPlayer[otherIndex])
					Expect(event).To(Equal(rkpg.RNGOpeningsIgnored))
					Expect(rkpger.State()).To(Equal(rkpg.WaitingRNG))

					// Perturb value
					// Choose a random share that will be perturbed
					l = rand.Intn(b)
					_, otherIndex = RandomIndexExcept(index, indices)
					shamirutil.PerturbValue(&rngOpeningsByPlayer[otherIndex][l])
					event = rkpger.TransitionRNGOpen(otherIndex, rngOpeningsByPlayer[otherIndex])
					Expect(event).To(Equal(rkpg.RNGOpeningsIgnored))
					Expect(rkpger.State()).To(Equal(rkpg.WaitingRNG))

					// Perturb decommitment
					// Choose a random share that will be perturbed
					l = rand.Intn(b)
					_, otherIndex = RandomIndexExcept(index, indices)
					shamirutil.PerturbDecommitment(&rngOpeningsByPlayer[otherIndex][l])
					event = rkpger.TransitionRNGOpen(otherIndex, rngOpeningsByPlayer[otherIndex])
					Expect(event).To(Equal(rkpg.RNGOpeningsIgnored))
					Expect(rkpger.State()).To(Equal(rkpg.WaitingRNG))
				})

				It("Should ignore any other message", func() {
					rngShares, rngCommitments := rngutil.GetBrngOutputs(
						indices, index, b, k, h, false,
					)

					rzgShares, rzgCommitments := rngutil.GetBrngOutputs(
						indices, index, b, k, h, true,
					)

					event := rkpger.TransitionRNGShares(rngShares, rngCommitments)
					Expect(event).To(Equal(rkpg.RNGInputsIgnored))
					Expect(rkpger.State()).To(Equal(rkpg.WaitingRNG))

					event = rkpger.TransitionRZGShares(rzgShares, rzgCommitments)
					Expect(event).To(Equal(rkpg.RZGInputsIgnored))
					Expect(rkpger.State()).To(Equal(rkpg.WaitingRNG))
				})
			})

			Context("RNGsReady state", func() {
				var rkpger rkpg.RKPGer
				var rngShares []shamir.VerifiableShares
				var rngCommitments [][]shamir.Commitment
				var rngOpeningsByPlayer map[open.Fn]shamir.VerifiableShares
				var rzgShares []shamir.VerifiableShares
				var rzgCommitments [][]shamir.Commitment

				JustBeforeEach(func() {
					rngOpeningsByPlayer, _, rngShares, rngCommitments = rngutil.GetAllDirectedOpenings(
						indices, index, b, k, h, false,
					)

					rzgShares, rzgCommitments = rngutil.GetBrngOutputs(
						indices, index, b, k, h, true,
					)

					rkpger = InStateRNGsReady(
						index, indices, b, k, h,
						rngShares, rngCommitments, rngOpeningsByPlayer,
					)
				})

				Specify("Supply valid BRNG shares for RZG", func() {
					event := rkpger.TransitionRZGShares(rzgShares, rzgCommitments)

					Expect(event).To(Equal(rkpg.RZGInputsAccepted))
					Expect(rkpger.State()).To(Equal(rkpg.WaitingRZG))
					for i := range indices {
						directedOpenings := rkpger.DirectedRZGOpenings(indices[i])
						Expect(cap(directedOpenings)).To(Equal(b))
						Expect(len(directedOpenings)).To(Equal(b))
					}
				})

				Specify("Supply invalid BRNG shares for RZG", func() {
					event := rkpger.TransitionRZGShares([]shamir.VerifiableShares{}, rzgCommitments)

					Expect(event).To(Equal(rkpg.RZGInputsAccepted))
					Expect(rkpger.State()).To(Equal(rkpg.WaitingRZG))
					for i := range indices {
						directedOpenings := rkpger.DirectedRZGOpenings(indices[i])
						Expect(cap(directedOpenings)).To(Equal(b))
						Expect(len(directedOpenings)).To(Equal(0))
					}
				})

				Specify("Supply invalid BRNG commitments (defeats the assumption) for RZG", func() {
					Expect(func() {
						rkpger.TransitionRZGShares(rzgShares, rzgCommitments[1:])
					}).To(Panic())

					rzgShares[0] = rzgShares[0][1:]
					Expect(func() {
						rkpger.TransitionRZGShares(rzgShares, rzgCommitments)
					}).To(Panic())
				})

				It("Should ignore any other message", func() {
					event := rkpger.TransitionRNGShares(rngShares, rngCommitments)
					Expect(event).To(Equal(rkpg.RNGInputsIgnored))
					Expect(rkpger.State()).To(Equal(rkpg.RNGsReady))

					_, fromIndex := RandomIndexExcept(index, indices)
					event = rkpger.TransitionRNGOpen(fromIndex, rngOpeningsByPlayer[fromIndex])
					Expect(event).To(Equal(rkpg.RNGOpeningsIgnored))
					Expect(rkpger.State()).To(Equal(rkpg.RNGsReady))
				})
			})

			Context("WaitingRZG state", func() {
				var rkpger rkpg.RKPGer
				var rngShares []shamir.VerifiableShares
				var rngCommitments [][]shamir.Commitment
				var rngOpeningsByPlayer map[open.Fn]shamir.VerifiableShares
				var rzgShares []shamir.VerifiableShares
				var rzgCommitments [][]shamir.Commitment
				var rzgOpeningsByPlayer map[open.Fn]shamir.VerifiableShares

				JustBeforeEach(func() {
					rngOpeningsByPlayer, _, rngShares, rngCommitments = rngutil.GetAllDirectedOpenings(
						indices, index, b, k, h, false,
					)

					rzgOpeningsByPlayer, _, rzgShares, rzgCommitments = rngutil.GetAllDirectedOpenings(
						indices, index, b, k, h, true,
					)

					rkpger = InStateWaitingRZG(
						index, indices, b, k, h,
						rngShares, rngCommitments, rngOpeningsByPlayer,
						rzgShares, rzgCommitments,
					)
				})

				Specify("Supply valid RZG openings", func() {
					_, otherIndex := RandomIndexExcept(index, indices)

					event := rkpger.TransitionRZGOpen(otherIndex, rzgOpeningsByPlayer[otherIndex])
					Expect(event).To(Equal(rkpg.RZGOpeningsAccepted))
					Expect(rkpger.State()).To(Equal(rkpg.WaitingRZG))
				})

				Specify("Supply kth valid RZG openings", func() {
					// The player has already passed their own openings
					count := 1

					for _, fromIndex := range indices {
						if fromIndex.Eq(&index) {
							continue
						}

						// If this is the kth set of openings
						if count == k-1 {
							event := rkpger.TransitionRZGOpen(fromIndex, rzgOpeningsByPlayer[fromIndex])
							Expect(event).To(Equal(rkpg.RZGReady))
							Expect(rkpger.State()).To(Equal(rkpg.WaitingOpen))
							break
						}

						// If this is not the kth set of openings
						if count < k-1 {
							event := rkpger.TransitionRZGOpen(fromIndex, rzgOpeningsByPlayer[fromIndex])
							Expect(event).To(Equal(rkpg.RZGOpeningsAccepted))
							Expect(rkpger.State()).To(Equal(rkpg.WaitingRZG))
							count = count + 1
						}
					}
				})

				Specify("Supply invalid RZG openings", func() {
					// Invalid length for the set of openings
					_, otherIndex := RandomIndexExcept(index, indices)
					event := rkpger.TransitionRZGOpen(otherIndex, rzgOpeningsByPlayer[otherIndex][1:])
					Expect(event).To(Equal(rkpg.RZGOpeningsIgnored))
					Expect(rkpger.State()).To(Equal(rkpg.WaitingRZG))

					// Perturb index
					// Choose a random share that will be perturbed
					l := rand.Intn(b)
					_, otherIndex = RandomIndexExcept(index, indices)
					shamirutil.PerturbIndex(&rzgOpeningsByPlayer[otherIndex][l])
					event = rkpger.TransitionRZGOpen(otherIndex, rzgOpeningsByPlayer[otherIndex])
					Expect(event).To(Equal(rkpg.RZGOpeningsIgnored))
					Expect(rkpger.State()).To(Equal(rkpg.WaitingRZG))

					// Perturb value
					// Choose a random share that will be perturbed
					l = rand.Intn(b)
					_, otherIndex = RandomIndexExcept(index, indices)
					shamirutil.PerturbValue(&rzgOpeningsByPlayer[otherIndex][l])
					event = rkpger.TransitionRZGOpen(otherIndex, rzgOpeningsByPlayer[otherIndex])
					Expect(event).To(Equal(rkpg.RZGOpeningsIgnored))
					Expect(rkpger.State()).To(Equal(rkpg.WaitingRZG))

					// Perturb decommitment
					// Choose a random share that will be perturbed
					l = rand.Intn(b)
					_, otherIndex = RandomIndexExcept(index, indices)
					shamirutil.PerturbDecommitment(&rzgOpeningsByPlayer[otherIndex][l])
					event = rkpger.TransitionRZGOpen(otherIndex, rzgOpeningsByPlayer[otherIndex])
					Expect(event).To(Equal(rkpg.RZGOpeningsIgnored))
					Expect(rkpger.State()).To(Equal(rkpg.WaitingRZG))
				})

				It("Should ignore any other message", func() {
					event := rkpger.TransitionRNGShares(rngShares, rngCommitments)
					Expect(event).To(Equal(rkpg.RNGInputsIgnored))
					Expect(rkpger.State()).To(Equal(rkpg.WaitingRZG))

					_, fromIndex := RandomIndexExcept(index, indices)
					event = rkpger.TransitionRNGOpen(fromIndex, rngOpeningsByPlayer[fromIndex])
					Expect(event).To(Equal(rkpg.RNGOpeningsIgnored))
					Expect(rkpger.State()).To(Equal(rkpg.WaitingRZG))

					event = rkpger.TransitionRZGShares(rzgShares, rzgCommitments)
					Expect(event).To(Equal(rkpg.RZGInputsIgnored))
					Expect(rkpger.State()).To(Equal(rkpg.WaitingRZG))
				})
			})

			Context("WaitingOpen state", func() {
				var rkpgers []rkpg.RKPGer

				JustBeforeEach(func() {
					rngSharesByPlayer, rngCommitmentsByPlayer := rngutil.GetAllSharesAndCommitments(indices, b, k, h, false)
					rzgSharesByPlayer, rzgCommitmentsByPlayer := rngutil.GetAllSharesAndCommitments(indices, b, k, h, true)

					rkpgers = InState(
						rkpg.WaitingOpen,
						indices, b, k, h,
						rngSharesByPlayer, rngCommitmentsByPlayer,
						rzgSharesByPlayer, rzgCommitmentsByPlayer,
					)
				})

				Specify("Supply valid hiding openings", func() {
					// For every player
					for i, toIndex := range indices {
						// Choose another player at random
						j, _ := RandomIndexExcept(toIndex, indices)

						// Fetch the share-hiding openings
						hidingOpenings := rkpgers[j].HidingOpenings()

						// Broadcasted openings reach the `to` player
						event := rkpgers[i].TransitionHidingOpenings(hidingOpenings)

						Expect(event).To(Equal(rkpg.HidingOpeningsAccepted))
						Expect(rkpgers[i].State()).To(Equal(rkpg.WaitingOpen))
					}
				})

				Specify("Supply kth valid hiding openings", func() {
					// For every player
					for i, toIndex := range indices {
						// The players themselves have provided one set of openings
						count := 1

						// From other players
						for j, fromIndex := range indices {
							if fromIndex.Eq(&toIndex) {
								continue
							}

							// If the Done state has already reached, it simply ignores
							// the new hiding openings
							if count == k {
								// Ensure that it is in fact in the Done state
								Expect(rkpgers[i].State()).To(Equal(rkpg.Done))

								hidingOpenings := rkpgers[j].HidingOpenings()
								event := rkpgers[i].TransitionHidingOpenings(hidingOpenings)
								Expect(event).To(Equal(rkpg.HidingOpeningsIgnored))
								Expect(rkpgers[i].State()).To(Equal(rkpg.Done))
							}

							// If this is the kth set of openings
							if count == k-1 {
								hidingOpenings := rkpgers[j].HidingOpenings()
								event := rkpgers[i].TransitionHidingOpenings(hidingOpenings)
								Expect(event).To(Equal(rkpg.KeyPairsReady))
								Expect(rkpgers[i].State()).To(Equal(rkpg.Done))
								count = count + 1
							}

							// If this is not the kth set of openings
							if count < k-1 {
								hidingOpenings := rkpgers[j].HidingOpenings()
								event := rkpgers[i].TransitionHidingOpenings(hidingOpenings)
								Expect(event).To(Equal(rkpg.HidingOpeningsAccepted))
								Expect(rkpgers[i].State()).To(Equal(rkpg.WaitingOpen))
								count = count + 1
							}
						}
					}
				})

				Specify("Supply invalid hiding openings", func() {
					// For every player
					for i, toIndex := range indices {
						// Modify length of the set of openings
						j, _ := RandomIndexExcept(toIndex, indices)
						hidingOpenings := rkpgers[j].HidingOpenings()
						l := rand.Intn(b)
						hidingOpenings = append(hidingOpenings[:l], hidingOpenings[l+1:]...)
						event := rkpgers[i].TransitionHidingOpenings(hidingOpenings)
						Expect(event).To(Equal(rkpg.HidingOpeningsIgnored))
						Expect(rkpgers[i].State()).To(Equal(rkpg.WaitingOpen))

						// Perturb index
						j, _ = RandomIndexExcept(toIndex, indices)
						hidingOpenings = rkpgers[j].HidingOpenings()
						l = rand.Intn(b)
						shamirutil.PerturbIndex(&hidingOpenings[l])
						event = rkpgers[i].TransitionHidingOpenings(hidingOpenings)
						Expect(event).To(Equal(rkpg.HidingOpeningsIgnored))
						Expect(rkpgers[i].State()).To(Equal(rkpg.WaitingOpen))

						// Perturb value
						j, _ = RandomIndexExcept(toIndex, indices)
						hidingOpenings = rkpgers[j].HidingOpenings()
						l = rand.Intn(b)
						shamirutil.PerturbValue(&hidingOpenings[l])
						event = rkpgers[i].TransitionHidingOpenings(hidingOpenings)
						Expect(event).To(Equal(rkpg.HidingOpeningsIgnored))
						Expect(rkpgers[i].State()).To(Equal(rkpg.WaitingOpen))

						// Perturb decommitment
						j, _ = RandomIndexExcept(toIndex, indices)
						hidingOpenings = rkpgers[j].HidingOpenings()
						l = rand.Intn(b)
						shamirutil.PerturbDecommitment(&hidingOpenings[l])
						event = rkpgers[i].TransitionHidingOpenings(hidingOpenings)
						Expect(event).To(Equal(rkpg.HidingOpeningsIgnored))
						Expect(rkpgers[i].State()).To(Equal(rkpg.WaitingOpen))
					}
				})

				It("Should ignore any other message", func() {
					i := 0
					toIndex := indices[i]
					rngOpeningsByPlayer, _, rngShares, rngCommitments := rngutil.GetAllDirectedOpenings(indices, toIndex, b, k, h, false)
					rzgOpeningsByPlayer, _, rzgShares, rzgCommitments := rngutil.GetAllDirectedOpenings(indices, toIndex, b, k, h, true)

					_, fromIndex := RandomIndexExcept(toIndex, indices)

					event := rkpgers[i].TransitionRNGShares(rngShares, rngCommitments)
					Expect(event).To(Equal(rkpg.RNGInputsIgnored))
					Expect(rkpgers[i].State()).To(Equal(rkpg.WaitingOpen))

					event = rkpgers[i].TransitionRNGOpen(fromIndex, rngOpeningsByPlayer[fromIndex])
					Expect(event).To(Equal(rkpg.RNGOpeningsIgnored))
					Expect(rkpgers[i].State()).To(Equal(rkpg.WaitingOpen))

					event = rkpgers[i].TransitionRZGShares(rzgShares, rzgCommitments)
					Expect(event).To(Equal(rkpg.RZGInputsIgnored))
					Expect(rkpgers[i].State()).To(Equal(rkpg.WaitingOpen))

					event = rkpgers[i].TransitionRZGOpen(fromIndex, rzgOpeningsByPlayer[fromIndex])
					Expect(event).To(Equal(rkpg.RZGOpeningsIgnored))
					Expect(rkpgers[i].State()).To(Equal(rkpg.WaitingOpen))
				})
			})

			Context("Done state", func() {
				var rkpgers []rkpg.RKPGer

				JustBeforeEach(func() {
					rngSharesByPlayer, rngCommitmentsByPlayer := rngutil.GetAllSharesAndCommitments(indices, b, k, h, false)
					rzgSharesByPlayer, rzgCommitmentsByPlayer := rngutil.GetAllSharesAndCommitments(indices, b, k, h, true)

					rkpgers = InState(
						rkpg.Done,
						indices, b, k, h,
						rngSharesByPlayer, rngCommitmentsByPlayer,
						rzgSharesByPlayer, rzgCommitmentsByPlayer,
					)
				})

				It("Should respond with keypairs", func() {
					// VSS Checker to validate vshares
					vssChecker := shamir.NewVSSChecker(h)

					// Initialise array to hold the batch of verifiable shares
					batchOfVerifiableShares := make([]shamir.VerifiableShares, b)

					// Fetch commitments, keypairs, shares from the first player
					refCommitments := rkpgers[0].RNGCommitments()
					refKeypairs, refShares := rkpgers[0].KeyPairs()

					// Start populating the batch of verifiable shares
					for j := 0; j < b; j++ {
						batchOfVerifiableShares[j] = append(batchOfVerifiableShares[j], refShares[j])
					}

					for i := 1; i < len(indices); i++ {
						commitments := rkpgers[i].RNGCommitments()
						keypairs, shares := rkpgers[i].KeyPairs()

						// Commitments should be the same
						for j, c := range commitments {
							Expect(c.Eq(&refCommitments[j])).To(BeTrue())
							Expect(vssChecker.IsValid(&c, &shares[j])).To(BeTrue())
						}

						// Keypairs should be the same
						for j, keypair := range keypairs {
							Expect(keypair.Eq(&refKeypairs[j])).To(BeTrue())
						}

						// Populate the verifiable shares to the batch of verifiable shares
						for j := 0; j < b; j++ {
							batchOfVerifiableShares[j] = append(batchOfVerifiableShares[j], shares[j])
						}
					}

					// Batch of verifiable shares should be consistent
					reconstructor := shamir.NewReconstructor(indices)
					for j := 0; j < b; j++ {
						Expect(shamirutil.VsharesAreConsistent(batchOfVerifiableShares[j], &reconstructor, k)).To(BeTrue())
					}
				})

				It("Should reset to Init state", func() {
					for i := range indices {
						event := rkpgers[i].Reset()
						Expect(event).To(Equal(rkpg.ResetDone))
						Expect(rkpgers[i].State()).To(Equal(rkpg.Init))

						// Ensure that the public keys are reset to points at infinity
						pointAtInfinity := curve.Infinity()
						publicKeys, shares := rkpgers[i].KeyPairs()
						for _, publicKey := range publicKeys {
							Expect(publicKey.Eq(&pointAtInfinity)).To(BeTrue())
						}

						// Ensure that the shares are reset
						Expect(shares).To(BeNil())
					}
				})

				It("Should ignore any other message", func() {
					i := 0
					toIndex := indices[i]
					rngOpeningsByPlayer, _, rngShares, rngCommitments := rngutil.GetAllDirectedOpenings(indices, toIndex, b, k, h, false)
					rzgOpeningsByPlayer, _, rzgShares, rzgCommitments := rngutil.GetAllDirectedOpenings(indices, toIndex, b, k, h, true)

					j, fromIndex := RandomIndexExcept(toIndex, indices)

					event := rkpgers[i].TransitionRNGShares(rngShares, rngCommitments)
					Expect(event).To(Equal(rkpg.RNGInputsIgnored))
					Expect(rkpgers[i].State()).To(Equal(rkpg.Done))

					event = rkpgers[i].TransitionRNGOpen(fromIndex, rngOpeningsByPlayer[fromIndex])
					Expect(event).To(Equal(rkpg.RNGOpeningsIgnored))
					Expect(rkpgers[i].State()).To(Equal(rkpg.Done))

					event = rkpgers[i].TransitionRZGShares(rzgShares, rzgCommitments)
					Expect(event).To(Equal(rkpg.RZGInputsIgnored))
					Expect(rkpgers[i].State()).To(Equal(rkpg.Done))

					event = rkpgers[i].TransitionRZGOpen(fromIndex, rzgOpeningsByPlayer[fromIndex])
					Expect(event).To(Equal(rkpg.RZGOpeningsIgnored))
					Expect(rkpgers[i].State()).To(Equal(rkpg.Done))

					hidingOpenings := rkpgers[j].HidingOpenings()
					event = rkpgers[i].TransitionHidingOpenings(hidingOpenings)
					Expect(event).To(Equal(rkpg.HidingOpeningsIgnored))
					Expect(rkpgers[i].State()).To(Equal(rkpg.Done))
				})
			})
		})

		Context("Marshaling and Unmarshaling", func() {
			var rngShares []shamir.VerifiableShares
			var rzgShares []shamir.VerifiableShares
			var rngCommitments [][]shamir.Commitment
			var rzgCommitments [][]shamir.Commitment
			var rngOpeningsByPlayer map[open.Fn]shamir.VerifiableShares
			var rzgOpeningsByPlayer map[open.Fn]shamir.VerifiableShares
			buf := bytes.NewBuffer([]byte{})

			JustBeforeEach(func() {
				rngOpeningsByPlayer, _, rngShares, rngCommitments = rngutil.GetAllDirectedOpenings(indices, index, b, k, h, false)
				rzgOpeningsByPlayer, _, rzgShares, rzgCommitments = rngutil.GetAllDirectedOpenings(indices, index, b, k, h, true)
			})

			It("Init state", func() {
				rkpger := InStateInit(index, indices, b, k, h)

				buf.Reset()
				m, err := rkpger.Marshal(buf, rkpger.SizeHint())
				Expect(err).ToNot(HaveOccurred())
				Expect(m).To(Equal(0))

				var rkpger2 rkpg.RKPGer
				m, err = rkpger2.Unmarshal(buf, rkpger.SizeHint())
				Expect(err).ToNot(HaveOccurred())
				Expect(m).To(Equal(0))
			})

			It("WaitingRNG state", func() {
				rkpger := InStateWaitingRNG(
					index, indices, b, k, h,
					rngShares, rngCommitments,
				)

				buf.Reset()
				m, err := rkpger.Marshal(buf, rkpger.SizeHint())
				Expect(err).ToNot(HaveOccurred())
				Expect(m).To(Equal(0))

				var rkpger2 rkpg.RKPGer
				m, err = rkpger2.Unmarshal(buf, rkpger.SizeHint())
				Expect(err).ToNot(HaveOccurred())
				Expect(m).To(Equal(0))
			})

			It("RNGsReady state", func() {
				rkpger := InStateRNGsReady(
					index, indices, b, k, h,
					rngShares, rngCommitments, rngOpeningsByPlayer,
				)

				buf.Reset()
				m, err := rkpger.Marshal(buf, rkpger.SizeHint())
				Expect(err).ToNot(HaveOccurred())
				Expect(m).To(Equal(0))

				var rkpger2 rkpg.RKPGer
				m, err = rkpger2.Unmarshal(buf, rkpger.SizeHint())
				Expect(err).ToNot(HaveOccurred())
				Expect(m).To(Equal(0))
			})

			It("WaitingRZG state", func() {
				rkpger := InStateWaitingRZG(
					index, indices, b, k, h,
					rngShares, rngCommitments, rngOpeningsByPlayer,
					rzgShares, rzgCommitments,
				)

				buf.Reset()
				m, err := rkpger.Marshal(buf, rkpger.SizeHint())
				Expect(err).ToNot(HaveOccurred())
				Expect(m).To(Equal(0))

				var rkpger2 rkpg.RKPGer
				m, err = rkpger2.Unmarshal(buf, rkpger.SizeHint())
				Expect(err).ToNot(HaveOccurred())
				Expect(m).To(Equal(0))
			})

			It("WaitingOpen state", func() {
				rkpger := InStateWaitingOpen(
					index, indices, b, k, h,
					rngShares, rngCommitments, rngOpeningsByPlayer,
					rzgShares, rzgCommitments, rzgOpeningsByPlayer,
				)

				buf.Reset()
				m, err := rkpger.Marshal(buf, rkpger.SizeHint())
				Expect(err).ToNot(HaveOccurred())
				Expect(m).To(Equal(0))

				var rkpger2 rkpg.RKPGer
				m, err = rkpger2.Unmarshal(buf, rkpger.SizeHint())
				Expect(err).ToNot(HaveOccurred())
				Expect(m).To(Equal(0))
			})

			It("Done state", func() {
				rngSharesByPlayer, rngCommitmentsByPlayer := rngutil.GetAllSharesAndCommitments(indices, b, k, h, false)
				rzgSharesByPlayer, rzgCommitmentsByPlayer := rngutil.GetAllSharesAndCommitments(indices, b, k, h, true)
				rkpgers := InState(
					rkpg.Done,
					indices, b, k, h,
					rngSharesByPlayer, rngCommitmentsByPlayer,
					rzgSharesByPlayer, rzgCommitmentsByPlayer,
				)

				for i := range indices {
					// Error marshaling with byte size less than the size hint
					for b := 0; b < rkpgers[i].SizeHint(); b++ {
						buf.Reset()
						_, err := rkpgers[i].Marshal(buf, b)
						Expect(err).To(HaveOccurred())
					}

					m, err := rkpgers[i].Marshal(buf, rkpgers[i].SizeHint())
					Expect(err).ToNot(HaveOccurred())
					Expect(m).To(Equal(0))

					var rkpger2 rkpg.RKPGer
					m, err = rkpger2.Unmarshal(buf, rkpgers[i].SizeHint())
					Expect(err).ToNot(HaveOccurred())
					Expect(m).To(Equal(0))
				}
			})

			It("Should not be able to unmarshal with insufficient bytes", func() {
				rkpger := InStateWaitingOpen(
					index, indices, b, k, h,
					rngShares, rngCommitments, rngOpeningsByPlayer,
					rzgShares, rzgCommitments, rzgOpeningsByPlayer,
				)

				buf.Reset()
				m, err := rkpger.Marshal(buf, rkpger.SizeHint())
				Expect(err).ToNot(HaveOccurred())
				Expect(m).To(Equal(0))

				var rkpger2 rkpg.RKPGer
				for b := 0; b < rkpger.SizeHint(); b++ {
					_, err := rkpger2.Unmarshal(buf, b)
					Expect(err).To(HaveOccurred())
				}
			})
		})
	})

	Describe("Network Simulation", func() {
		var ids []mpcutil.ID
		var machines []mpcutil.Machine
		var network mpcutil.Network
		var shuffleMsgs func([]mpcutil.Message)
		var isOffline map[mpcutil.ID]bool
		var b, k int
		var h curve.Point

		JustBeforeEach(func() {
			// Randomise RKPG network scenario
			n := 5 + rand.Intn(6)
			indices := shamirutil.RandomIndices(n)
			b = 3 + rand.Intn(3)
			k = 3 + rand.Intn(n-3)
			h = curve.Random()

			// Machines (players) participating in the RNG protocol
			ids = make([]mpcutil.ID, n)
			machines = make([]mpcutil.Machine, n)

			// Get BRNG outputs for all players for both RNGer and RZGer
			rngSharesByPlayer, rngCommitmentsByPlayer := rngutil.GetAllSharesAndCommitments(indices, b, k, h, false)
			rzgSharesByPlayer, rzgCommitmentsByPlayer := rngutil.GetAllSharesAndCommitments(indices, b, k, h, true)

			// Append machines to the network
			for i, index := range indices {
				id := mpcutil.ID(i)
				rkpgMachine := rkpgutil.NewRkpgMachine(
					id, index, indices, b, k, h,
					rngSharesByPlayer[index],
					rngCommitmentsByPlayer[index],
					rzgSharesByPlayer[index],
					rzgCommitmentsByPlayer[index],
				)
				machines[i] = &rkpgMachine
				ids[i] = id
			}

			nOffline := rand.Intn(n - k + 1)
			shuffleMsgs, isOffline = mpcutil.MessageShufflerDropper(ids, nOffline)
			network = mpcutil.NewNetwork(machines, shuffleMsgs)
			network.SetCaptureHist(true)
		})

		Specify("RKPG machines should reconstruct the same batch of public keys", func() {
			err := network.Run()
			Expect(err).ToNot(HaveOccurred())

			// ID of the first online machine
			i := 0
			for isOffline[machines[i].ID()] {
				i = i + 1
			}

			// Fetch the keypairs as constructed by this reference machine
			referencePublicKeys, _ := machines[i].(*rkpgutil.RkpgMachine).KeyPairs()

			// For every other machine
			for j := i + 1; j < len(machines); j++ {
				// Ignoring the offline machines
				if isOffline[machines[j].ID()] {
					continue
				}

				// Fetch its public keys
				publicKeys, _ := machines[j].(*rkpgutil.RkpgMachine).KeyPairs()

				// They should match the reference public keys meaning every
				// machine should have constructed the same batch of public keys
				Expect(len(publicKeys)).To(Equal(len(referencePublicKeys)))
				for l, publicKey := range publicKeys {
					Expect(publicKey.Eq(&referencePublicKeys[l])).To(BeTrue())
				}
			}
		})
	})
})
