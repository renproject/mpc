package brng_test

import (
	"math/rand"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	. "github.com/renproject/mpc/brng"
	. "github.com/renproject/mpc/mpcutil"

	"github.com/renproject/mpc/brng/brngutil"
	"github.com/renproject/secp256k1"
	"github.com/renproject/shamir"
	"github.com/renproject/shamir/shamirutil"
)

var _ = Describe("BRNG", func() {
	rand.Seed(int64(time.Now().Nanosecond()))

	RandomTestParameters := func() (int, uint32, uint32, int, []secp256k1.Fn, secp256k1.Fn, secp256k1.Point) {
		n := shamirutil.RandRange(5, 20)
		k := shamirutil.RandRange(1, (n/2)-1)
		b := shamirutil.RandRange(1, 5)
		t := shamirutil.RandRange(k, n)
		indices := shamirutil.RandomIndices(n)
		index := indices[rand.Intn(len(indices))]
		h := secp256k1.RandomPoint()
		return n, uint32(k), uint32(b), t, indices, index, h
	}

	ValidBatches := func(k, b uint32, t int, indices []secp256k1.Fn, index secp256k1.Fn, h secp256k1.Point) (
		[]shamir.VerifiableShares, [][]shamir.Commitment,
	) {
		n := len(indices)
		sharesBatch := make([]shamir.VerifiableShares, b)
		commitmentsBatch := make([][]shamir.Commitment, b)
		for i := range commitmentsBatch {
			sharesBatch[i] = make(shamir.VerifiableShares, t)
			commitmentsBatch[i] = make([]shamir.Commitment, t)
			for j := range commitmentsBatch[i] {
				commitmentsBatch[i][j] = shamir.NewCommitmentWithCapacity(int(k))
			}
		}

		shares := make(shamir.VerifiableShares, n)
		for i := 0; i < t; i++ {
			for j := uint32(0); j < b; j++ {
				shamir.VShareSecret(&shares, &commitmentsBatch[j][i], indices, h, secp256k1.RandomFn(), int(k))
				for _, share := range shares {
					if share.Share.IndexEq(&index) {
						sharesBatch[j][i] = share
					}
				}
			}
		}
		return sharesBatch, commitmentsBatch
	}

	Context("creating a new BRNGer and initial messages", func() {
		Specify("the shairings (initial messages) should be valid", func() {
			_, k, b, _, indices, index, h := RandomTestParameters()
			_, sharingBatch := New(b, k, indices, index, h)
			Expect(len(sharingBatch)).To(Equal(int(b)))
			for _, sharing := range sharingBatch {
				Expect(shamirutil.VsharesAreConsistent(sharing.Shares, int(k))).To(BeTrue())
				for _, share := range sharing.Shares {
					Expect(shamir.IsValid(h, &sharing.Commitment, &share)).To(BeTrue())
				}
			}
		})
	})

	Context("checking if consensus outputs are valid", func() {
		Specify("valid share and commitment batches", func() {
			_, k, b, t, indices, index, h := RandomTestParameters()
			sharesBatch, commitmentsBatch := ValidBatches(k, b, t, indices, index, h)
			brnger, _ := New(b, k, indices, index, h)
			err := brnger.IsValid(sharesBatch, commitmentsBatch, t)
			Expect(err).ToNot(HaveOccurred())
		})

		Context("error cases", func() {
			Specify("incorrect batch size", func() {
				_, k, b, t, indices, index, h := RandomTestParameters()
				sharesBatch, commitmentsBatch := ValidBatches(k, b, t, indices, index, h)
				brnger, _ := New(b, k, indices, index, h)

				// Incorrect batch size for shares
				err := brnger.IsValid(sharesBatch[1:], commitmentsBatch, t)
				Expect(err).To(Equal(ErrIncorrectSharesBatchSize))

				// Incorrect batch size for commitments
				err = brnger.IsValid(sharesBatch, commitmentsBatch[1:], t)
				Expect(err).To(Equal(ErrIncorrectCommitmentsBatchSize))
			})

			Specify("not enough contributions", func() {
				_, k, b, t, indices, index, h := RandomTestParameters()
				sharesBatch, commitmentsBatch := ValidBatches(k, b, t-1, indices, index, h)
				brnger, _ := New(b, k, indices, index, h)
				err := brnger.IsValid(sharesBatch, commitmentsBatch, t)
				Expect(err).To(Equal(ErrNotEnoughContributions))
			})

			Context("incorrect input dimensions", func() {
				Specify("commitment contributions length", func() {
					_, k, b, t, indices, index, h := RandomTestParameters()
					// This test only makes sense if b > 1.
					if b == 1 {
						b++
					}
					sharesBatch, commitmentsBatch := ValidBatches(k, b, t, indices, index, h)
					brnger, _ := New(b, k, indices, index, h)

					// We modify the slice at index 1 because if the index 0
					// element has the wrong length, it will return a different
					// error instead.
					commitmentsBatch[1] = commitmentsBatch[1][1:]
					err := brnger.IsValid(sharesBatch, commitmentsBatch, t)
					Expect(err).To(Equal(ErrInvalidCommitmentDimensions))
				})

				Specify("commitment threshold", func() {
					_, k, b, t, indices, index, h := RandomTestParameters()
					sharesBatch, commitmentsBatch := ValidBatches(k, b, t, indices, index, h)
					brnger, _ := New(b, k, indices, index, h)

					commitmentsBatch[0][0] = shamir.NewCommitmentWithCapacity(int(k) - 1)
					err := brnger.IsValid(sharesBatch, commitmentsBatch, t)
					Expect(err).To(Equal(ErrInvalidCommitmentDimensions))
				})

				Specify("share contributions length", func() {
					_, k, b, t, indices, index, h := RandomTestParameters()
					// This test only makes sense for some cases if b > 1.
					if b == 1 {
						b++
					}
					sharesBatch, commitmentsBatch := ValidBatches(k, b, t, indices, index, h)
					brnger, _ := New(b, k, indices, index, h)

					// We modify the slice at index 1 because if the index 0
					// element has the wrong length, it will return a different
					// error instead.
					sharesBatch[1] = sharesBatch[1][1:]
					err := brnger.IsValid(sharesBatch, commitmentsBatch, t)
					Expect(err).To(Equal(ErrInvalidShareDimensions))
				})
			})

			Specify("incorrect share index", func() {
				_, k, b, t, indices, index, h := RandomTestParameters()
				sharesBatch, commitmentsBatch := ValidBatches(k, b, t, indices, index, h)
				brnger, _ := New(b, k, indices, index, h)

				// Pick an index that is not the index of the BRNGer.
				badIndex := indices[rand.Intn(len(indices))]
				for badIndex.Eq(&index) {
					badIndex = indices[rand.Intn(len(indices))]
				}

				sharesBatch[0][0].Share.Index = badIndex
				err := brnger.IsValid(sharesBatch, commitmentsBatch, t)
				Expect(err).To(Equal(ErrIncorrectIndex))
			})

			Specify("invalid shares", func() {
				_, k, b, t, indices, index, h := RandomTestParameters()
				sharesBatch, commitmentsBatch := ValidBatches(k, b, t, indices, index, h)
				brnger, _ := New(b, k, indices, index, h)
				sharesBatch[0][0].Share.Value = secp256k1.RandomFn()
				err := brnger.IsValid(sharesBatch, commitmentsBatch, t)
				Expect(err).To(Equal(ErrInvalidShares))
			})
		})
	})

	Context("constructing output shares and commitments", func() {
		It("should return nil shares when the corresponding argument is nil", func() {
			_, k, b, t, indices, index, h := RandomTestParameters()
			_, commitmentsBatch := ValidBatches(k, b, t, indices, index, h)
			outputShares, _ := HandleConsensusOutput(nil, commitmentsBatch)
			Expect(outputShares).To(BeNil())
		})

		It("should return the summed output on valid inputs", func() {
			_, k, b, t, indices, index, h := RandomTestParameters()
			sharesBatch, commitmentsBatch := ValidBatches(k, b, t, indices, index, h)
			outputShares, outputCommitments := HandleConsensusOutput(sharesBatch, commitmentsBatch)

			summedShares := make(shamir.VerifiableShares, b)
			summedCommitments := make([]shamir.Commitment, b)
			for i := uint32(0); i < b; i++ {
				summedShares[i] = sharesBatch[i][0]
				summedCommitments[i] = commitmentsBatch[i][0]
				for j := 1; j < t; j++ {
					summedShares[i].Add(&summedShares[i], &sharesBatch[i][j])
					summedCommitments[i].Add(summedCommitments[i], commitmentsBatch[i][j])
				}
			}

			for i := uint32(0); i < b; i++ {
				Expect(outputShares[i].Eq(&summedShares[i])).To(BeTrue())
				Expect(outputCommitments[i].Eq(summedCommitments[i])).To(BeTrue())
			}
		})
	})

	Context("panics", func() {
		Context("when creating a new BRNGer", func() {
			Specify("batch size less than 1", func() {
				_, k, _, _, indices, index, h := RandomTestParameters()
				Expect(func() { New(0, k, indices, index, h) }).To(Panic())
			})

			Specify("k less than 1", func() {
				_, _, b, _, indices, index, h := RandomTestParameters()
				Expect(func() { New(b, 0, indices, index, h) }).To(Panic())
			})

			Specify("insecure pedersen parameter", func() {
				_, k, b, _, indices, index, _ := RandomTestParameters()
				h := secp256k1.NewPointInfinity()
				Expect(func() { New(b, k, indices, index, h) }).To(Panic())
			})
		})

		Context("when checking validity", func() {
			Specify("required contributions less than 1", func() {
				_, k, b, t, indices, index, h := RandomTestParameters()
				sharesBatch, commitmentsBatch := ValidBatches(k, b, t, indices, index, h)
				brnger, _ := New(b, k, indices, index, h)
				Expect(func() { brnger.IsValid(sharesBatch, commitmentsBatch, 0) }).To(Panic())
			})
		})
	})

	Context("network test", func() {
		Specify("BRNG should function correctly in a network with offline machines", func() {
			n, k, b, _, indices, _, h := RandomTestParameters()

			playerIDs := make([]ID, len(indices))
			for i := range playerIDs {
				playerIDs[i] = ID(i + 1)
			}
			consID := ID(len(indices) + 1)
			shuffleMsgs, isOffline := MessageShufflerDropper(playerIDs, rand.Intn(int(k)))

			machines := make([]Machine, 0, len(indices)+1)
			honestIndices := make([]secp256k1.Fn, 0, n-len(isOffline))
			for i, id := range playerIDs {
				machine := brngutil.NewMachine(
					brngutil.BrngTypePlayer, id, consID, playerIDs, indices, nil, indices[i], h, int(k), int(b),
				)
				machines = append(machines, &machine)
				if !isOffline[id] {
					honestIndices = append(honestIndices, indices[i])
				}
			}
			cmachine := brngutil.NewMachine(
				brngutil.BrngTypeConsensus,
				consID,
				consID,
				playerIDs,
				indices,
				honestIndices,
				secp256k1.Fn{},
				h,
				int(k),
				int(b),
			)
			machines = append(machines, &cmachine)

			network := NewNetwork(machines, shuffleMsgs)
			network.SetCaptureHist(true)

			err := network.Run()
			Expect(err).ToNot(HaveOccurred())

			// Check that for each batch, every player has the same output
			// commitment.
			for j := uint32(0); j < b; j++ {
				// Get a reference commitment from one of the online machines.
				var i int
				for i = 0; isOffline[machines[i].ID()]; i++ {
				}
				machine := machines[i].(*brngutil.BrngMachine)
				comm := machine.Commitments()[j]

				for i := 0; i < len(machines)-1; i++ {
					if isOffline[playerIDs[i]] {
						continue
					}

					machine := machines[i].(*brngutil.BrngMachine)
					Expect(machine.Commitments()[j].Eq(comm)).To(BeTrue())
				}
			}

			// Check that for each batch, the output shares of the online
			// players form a consistent and valid sharing.
			for j := uint32(0); j < b; j++ {
				shares := make(shamir.VerifiableShares, 0, n-len(isOffline))
				for i := 0; i < len(machines)-1; i++ {
					if isOffline[playerIDs[i]] {
						continue
					}

					pmachine := machines[i].(*brngutil.BrngMachine)
					machineShares := pmachine.Shares()
					machineCommitments := pmachine.Commitments()

					Expect(shamir.IsValid(h, &machineCommitments[j], &machineShares[j])).To(BeTrue())

					shares = append(shares, machineShares[j])
				}

				Expect(shamirutil.VsharesAreConsistent(shares, int(k))).To(BeTrue())
			}
		})
	})
})
