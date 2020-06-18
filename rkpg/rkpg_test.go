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

		InStateDone := func(
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

			// Transition to WaitingRNG state
			for i, index := range indices {
				event := rkpgers[i].TransitionRNGShares(
					rngSharesByPlayer[index],
					rngCommitmentsByPlayer[index],
				)
				Expect(event).To(Equal(rkpg.RNGInputsAccepted))
				Expect(rkpgers[i].State()).To(Equal(rkpg.WaitingRNG))
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

			// Transition to WaitingRZG state
			for i, index := range indices {
				event := rkpgers[i].TransitionRZGShares(
					rzgSharesByPlayer[index],
					rzgCommitmentsByPlayer[index],
				)
				Expect(event).To(Equal(rkpg.RZGInputsAccepted))
				Expect(rkpgers[i].State()).To(Equal(rkpg.WaitingRZG))
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

		BeforeEach(func() {
			n, indices, index, b, k, h = Setup()
		})

		Context("State transitions", func() {
			Specify("Initialise RKPG state machine", func() {
				event, rkpger := rkpg.New(index, indices, uint32(b), uint32(k), h)

				Expect(event).To(Equal(rkpg.Initialised))
				Expect(rkpger.State()).To(Equal(rkpg.Init))
				Expect(rkpger.N()).To(Equal(n))
				Expect(rkpger.BatchSize()).To(Equal(uint32(b)))
				Expect(rkpger.Threshold()).To(Equal(uint32(k)))
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
				rkpgers := InStateDone(
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
