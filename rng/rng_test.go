package rng_test

import (
	"math/rand"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/renproject/secp256k1"
	"github.com/renproject/shamir"
	"github.com/renproject/shamir/shamirutil"

	"github.com/renproject/mpc/mpcutil"
	"github.com/renproject/mpc/rng/rngutil"
)

var _ = Describe("RNG", func() {
	rand.Seed(int64(time.Now().Nanosecond()))

	Describe("Network Simulation", func() {
		var n, b, k, nOffline int
		var indices []secp256k1.Fn
		var h secp256k1.Point
		var isZero bool
		var ids []mpcutil.ID
		var setsOfSharesByPlayer map[secp256k1.Fn][]shamir.VerifiableShares
		var setsOfCommitmentsByPlayer [][]shamir.Commitment
		var shuffleMsgs func([]mpcutil.Message)
		var isOffline map[mpcutil.ID]bool
		var machines []mpcutil.Machine

		CheckMachines := func(
			machines []mpcutil.Machine,
			isOffline map[mpcutil.ID]bool,
			b, k int,
			h secp256k1.Point,
		) {
			// ID of the first online machine
			i := 0
			for isOffline[machines[i].ID()] {
				i = i + 1
			}

			// Get the unbiased random numbers calculated by that RNG machine
			referenceRNShares := machines[i].(*rngutil.RngMachine).RandomNumbersShares()
			referenceCommitments := machines[i].(*rngutil.RngMachine).Commitments()

			for j := i + 1; j < len(machines); j++ {
				// Ignore if that machine is offline
				if isOffline[machines[j].ID()] {
					continue
				}

				rnShares := machines[j].(*rngutil.RngMachine).RandomNumbersShares()
				rnCommitments := machines[j].(*rngutil.RngMachine).Commitments()
				Expect(len(referenceRNShares)).To(Equal(len(rnShares)))

				// Every player has computed the same commitments
				for l, c := range rnCommitments {
					Expect(c.Eq(referenceCommitments[l])).To(BeTrue())
				}

				// Verify that each machine's share is valid with respect to
				// the reference commitments
				for l, vshare := range rnShares {
					Expect(shamir.IsValid(h, &rnCommitments[l], &vshare)).To(BeTrue())
				}
			}

			// For every batch in batch size, the shares that every player has
			// should be consistent
			for i := 0; i < b; i++ {
				shares := make(shamir.Shares, 0, len(machines))

				for j := 0; j < len(machines); j++ {
					if isOffline[machines[j].ID()] {
						continue
					}

					vshare := machines[j].(*rngutil.RngMachine).RandomNumbersShares()[i]
					shares = append(shares, vshare.Share)
				}

				Expect(shamirutil.SharesAreConsistent(shares, k-1)).ToNot(BeTrue())
				Expect(shamirutil.SharesAreConsistent(shares, k)).To(BeTrue())
			}
		}

		Setup := func() {
			// Randomise RNG network scenario
			n = 15 + rand.Intn(6)
			indices = shamirutil.SequentialIndices(n)
			b = 3 + rand.Intn(3)
			k = rngutil.Min(3+rand.Intn(n-3), 7)
			h = secp256k1.RandomPoint()
			isZero = false

			// Machines (players) participating in the RNG protocol
			ids = make([]mpcutil.ID, n)

			// Get BRNG outputs for all players
			setsOfSharesByPlayer, setsOfCommitmentsByPlayer =
				rngutil.BRNGOutputFullBatch(indices, b, k, k, h)

			// Append machine IDs and get offline machines
			for i := range indices {
				id := mpcutil.ID(i)
				ids[i] = id
			}
			nOffline = rand.Intn(n - k + 1)
			shuffleMsgs, isOffline = mpcutil.MessageShufflerDropper(ids, nOffline)
		}

		MakeMachines := func() {
			machines = make([]mpcutil.Machine, n)
			for i, index := range indices {
				rngMachine := rngutil.NewRngMachine(
					mpcutil.ID(i), index, indices, b, k, h, isZero,
					setsOfSharesByPlayer[index],
					setsOfCommitmentsByPlayer,
				)
				machines[i] = &rngMachine
			}
		}

		BeforeEach(func() {
			Setup()
		})

		Specify("RNG machines should reconstruct the consistent shares for random numbers", func() {
			MakeMachines()
			network := mpcutil.NewNetwork(machines, shuffleMsgs)
			network.SetCaptureHist(true)

			err := network.Run()
			Expect(err).ToNot(HaveOccurred())

			CheckMachines(machines, isOffline, b, k, h)
		})

		Specify("With not all RNG machines contributing their BRNG shares", func() {
			// Mark some machines as being idle specifically, at the most k+1
			// should not be idle so (n - nOffline) - k - 1 should be idle
			// because only (n - nOffline) machines are online
			idleCount := 0
			for j, index := range indices {
				if isOffline[mpcutil.ID(j)] {
					continue
				}
				if idleCount == rngutil.Max(0, (n-nOffline)-k-1) {
					break
				}

				setsOfSharesByPlayer[index] = []shamir.VerifiableShares{}
				idleCount++
			}

			MakeMachines()
			network := mpcutil.NewNetwork(machines, shuffleMsgs)
			network.SetCaptureHist(true)

			err := network.Run()
			Expect(err).ToNot(HaveOccurred())

			CheckMachines(machines, isOffline, b, k, h)
		})
	})
})
