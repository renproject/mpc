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
	rtu "github.com/renproject/mpc/rng/testutil"
	mtu "github.com/renproject/mpc/testutil"
)

var _ = Describe("Rzg", func() {
	rand.Seed(int64(time.Now().Nanosecond()))

	Describe("Network Simulation", func() {
		var ids []mtu.ID
		var machines []mtu.Machine
		var network mtu.Network
		var shuffleMsgs func([]mtu.Message)
		var isOffline map[mtu.ID]bool
		var b, k int

		JustBeforeEach(func() {
			// Randomise RNG network scenario
			n := 5 + rand.Intn(6)
			indices := stu.SequentialIndices(n)
			b = 3 + rand.Intn(3)
			k = 3 + rand.Intn(n-3)
			h := curve.Random()
			isZero := true

			// Machines (players) participating in the RNG protocol
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

			// Get the unbiased random numbers calculated by that RNG machine
			referenceRNShares := machines[i].(*rtu.RngMachine).RandomNumbersShares()

			for j := i + 1; j < len(machines); j++ {
				// Ignore if that machine is offline
				if isOffline[machines[j].ID()] {
					continue
				}

				rnShares := machines[j].(*rtu.RngMachine).RandomNumbersShares()
				Expect(len(referenceRNShares)).To(Equal(len(rnShares)))
			}

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
