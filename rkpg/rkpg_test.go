package rkpg_test

import (
	"math/rand"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

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
