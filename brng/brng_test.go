package brng_test

import (
	"math/rand"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	. "github.com/renproject/mpc/brng"
	. "github.com/renproject/mpc/mpcutil"

	"github.com/renproject/mpc/brng/brngutil"
	"github.com/renproject/mpc/brng/table"
	"github.com/renproject/secp256k1"
	"github.com/renproject/shamir"
	"github.com/renproject/shamir/shamirutil"
)

// The main properties that we want to test for the BRNGer state machine are
//
//	1. The state transition logic is as described in the documentation.
//	2. When the random shares are created, they are valid and consistent
//	(including the commitment), have the correct reconstruction threshold and
//	the correct batch size.
//	3. When processing a valid slice of shares from the consensus algorithm,
//	the BRNGer should output the correct summed shares and commitments.
//	4. When processing an invalid slice of shares from the consensus algorithm,
//	the BRNGer should correctly identify the incorrect shares.
//	5. In a network of n nodes, if all nodes are honest then the outputs shares
//	should constitute a valid sharing of a random number, and correspond
//	correctly the output commitments. In the presence of dishonest nodes, any
//	node that sends an incorrect share/commitment should be identified.
var _ = Describe("BRNG", func() {
	rand.Seed(int64(time.Now().Nanosecond()))

	// Pedersem paramter.
	h := secp256k1.RandomPoint()

	n := 20
	k := 7

	var (
		brnger  BRNGer
		row     table.Row
		indices []secp256k1.Fn
		b, t    int
		to      secp256k1.Fn
	)

	Setup := func() (BRNGer, table.Row, int, int, secp256k1.Fn, []secp256k1.Fn) {
		b := 5
		t := k - 1
		indices := shamirutil.RandomIndices(n)
		to := indices[0]
		brnger, row := New(uint32(b), uint32(k), indices, h)

		return brnger, row, t, b, to, indices
	}

	TransitionToOk := func(
		brnger *BRNGer,
		to secp256k1.Fn,
		indices []secp256k1.Fn,
		k, b int,
	) {
		slice := brngutil.RandomValidSlice(to, indices, h, k, b, k)
		_, _, _ = brnger.HandleSlice(slice)
	}

	TransitionToError := func(
		brnger *BRNGer,
		to secp256k1.Fn,
		indices []secp256k1.Fn,
		k, t, b int,
	) {
		slice, _ := brngutil.RandomInvalidSlice(to, indices, h, n, k, b, k)
		_, _, _ = brnger.HandleSlice(slice)
	}

	BeforeEach(func() {
		brnger, row, t, b, to, indices = Setup()
	})

	Context("State transitions (1)", func() {
		Context("Waiting state", func() {
			Specify("Valid Slice -> Ok", func() {
				validSlice := brngutil.RandomValidSlice(to, indices, h, k, b, k)
				_, _, _ = brnger.HandleSlice(validSlice)
			})

			Context("Invalid Slice -> Error", func() {
				Specify("Slice with wrong batch size", func() {
					invalidSlice := brngutil.RandomValidSlice(to, indices, h, k, rand.Intn(b-1)+1, k-1)
					Expect(func() { brnger.HandleSlice(invalidSlice) }).To(Panic())
				})

				Specify("Slice with invalid form", func() {
					invalidSlice := make([]table.Col, b)

					// The slice will have an invalid form if any of the
					// columns have a different length than the others.
					invalidSlice[0] = make([]table.Element, k)
					Expect(func() { brnger.HandleSlice(invalidSlice) }).To(Panic())
				})

				Specify("Slice with faults", func() {
					invalidSlice, _ := brngutil.RandomInvalidSlice(to, indices, h, k, k, b, k-1)
					_, _, _ = brnger.HandleSlice(invalidSlice)
				})
			})
		})

		Context("Ok state", func() {
			JustBeforeEach(func() {
				TransitionToOk(&brnger, to, indices, k, b)
			})

			Specify("Slice -> Do nothing", func() {
				validSlice := brngutil.RandomValidSlice(to, indices, h, k, b, k)
				_, _, _ = brnger.HandleSlice(validSlice)
			})
		})

		Context("Error state", func() {
			JustBeforeEach(func() {
				TransitionToError(&brnger, to, indices, k, t, b)
			})

			Specify("Slice -> Do nothing", func() {
				validSlice := brngutil.RandomValidSlice(to, indices, h, k, b, k)
				_, _, _ = brnger.HandleSlice(validSlice)
			})
		})
	})

	Context("Share creation (2)", func() {
		// On receiving a start message in the Init state, the state machine
		// should return a valid Row.
		Specify("the returned row should be valid", func() {
			Expect(brngutil.RowIsValid(row, k, indices, h)).To(BeTrue())
		})

		Specify("the reconstruction threshold is correct", func() {
			Expect(brngutil.RowIsValid(row, k-1, indices, h)).To(BeFalse())
			Expect(brngutil.RowIsValid(row, k, indices, h)).To(BeTrue())
		})

		Specify("the returned row should have the correct batch size", func() {
			Expect(row.BatchSize()).To(Equal(b))
		})
	})

	Context("Valid slice processing (3)", func() {
		// On receiving a valid slice in the Waiting state, the state machine
		// should return the correct shares and commitment that correspond to
		// the slice.
		It("should correctly process a valid slice", func() {
			expectedShares := make(shamir.VerifiableShares, b)
			expectedCommitments := make([]shamir.Commitment, b)
			validSlice := brngutil.RandomValidSlice(to, indices, h, k, b, k)

			for i, col := range validSlice {
				expectedShares[i], expectedCommitments[i] = col.Sum()
			}

			shares, commitments, _ := brnger.HandleSlice(validSlice)

			Expect(len(shares)).To(Equal(b))
			Expect(len(commitments)).To(Equal(b))

			for i, share := range shares {
				Expect(share.Eq(&expectedShares[i])).To(BeTrue())
			}

			for i, commitment := range commitments {
				Expect(commitment.Eq(expectedCommitments[i])).To(BeTrue())
			}
		})
	})

	Context("Invalid slice processing (4)", func() {
		// On receiving an invalid slice in the Waiting state, the state
		// machine should return a list of faults that correctly identifies the
		// invalid shares. The commitment should still be returned.
		It("should correctly identify faulty elements", func() {
			invalidSlice, expectedFaults := brngutil.RandomInvalidSlice(to, indices, h, k, k, b, k-1)

			shares, commitments, faults := brnger.HandleSlice(invalidSlice)

			Expect(len(shares)).To(Equal(0))
			Expect(len(commitments)).To(Equal(b))
			Expect(len(faults)).To(Equal(len(expectedFaults)))
			for i, expectedFault := range expectedFaults {
				Expect(faults[i]).To(Equal(expectedFault))
			}
		})
	})

	Context("Network (5)", func() {
		Specify("BRNG should function correctly in a network with offline machines", func() {
			n = 20
			k = 7
			b = 5
			t = k - 1

			indices = shamirutil.SequentialIndices(n)

			playerIDs := make([]ID, len(indices))
			for i := range playerIDs {
				playerIDs[i] = ID(i + 1)
			}
			consID := ID(len(indices) + 1)
			shuffleMsgs, isOffline := MessageShufflerDropper(playerIDs, rand.Intn(k))

			machines := make([]Machine, 0, len(indices)+1)
			honestIndices := make([]secp256k1.Fn, 0, len(isOffline))
			for i, id := range playerIDs {
				machine := brngutil.NewMachine(brngutil.BrngTypePlayer, id, consID, playerIDs, indices, nil, h, k, b)
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
				h,
				k,
				b,
			)
			machines = append(machines, &cmachine)

			network := NewNetwork(machines, shuffleMsgs)
			network.SetCaptureHist(true)

			err := network.Run()
			Expect(err).ToNot(HaveOccurred())

			// Check that for each batch, every player has the same output
			// commitment.
			for j := 0; j < b; j++ {
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
			for j := 0; j < b; j++ {
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

				Expect(shamirutil.VsharesAreConsistent(shares, k)).To(BeTrue())
			}
		})
	})
})
