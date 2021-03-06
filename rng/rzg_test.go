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

var _ = Describe("RZG", func() {
	rand.Seed(int64(time.Now().Nanosecond()))

	Describe("Network Simulation", func() {
		var ids []mpcutil.ID
		var machines []mpcutil.Machine
		var indices []secp256k1.Fn
		var network mpcutil.Network
		var shuffleMsgs func([]mpcutil.Message)
		var isOffline map[mpcutil.ID]bool
		var b, k int
		var h secp256k1.Point

		JustBeforeEach(func() {
			// Randomise RZG network scenario
			n := 5 + rand.Intn(6)
			indices = shamirutil.RandomIndices(n)
			b = 3 + rand.Intn(3)
			k = 3 + rand.Intn(n-3)
			h = secp256k1.RandomPoint()
			isZero := true

			// Machines (players) participating in the RZG protocol
			ids = make([]mpcutil.ID, n)
			machines = make([]mpcutil.Machine, n)

			// Get BRNG outputs for all players
			setsOfSharesByPlayer, setsOfCommitmentsByPlayer :=
				rngutil.BRNGOutputFullBatch(indices, b, k-1, k, h)

			// Append machines to the network
			for i, index := range indices {
				id := mpcutil.ID(i)
				rngMachine := rngutil.NewRngMachine(
					id, index, indices, b, k, h, isZero,
					setsOfSharesByPlayer[index],
					setsOfCommitmentsByPlayer,
				)
				machines[i] = &rngMachine
				ids[i] = id
			}

			nOffline := rand.Intn(n - k + 1)
			shuffleMsgs, isOffline = mpcutil.MessageShufflerDropper(ids, nOffline)
			network = mpcutil.NewNetwork(machines, shuffleMsgs)
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

				secret := shamir.Open(shares)
				Expect(secret.IsZero()).To(BeTrue())
			}
		})
	})
})
