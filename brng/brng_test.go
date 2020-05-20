package brng_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	. "github.com/renproject/mpc/brng"
	"github.com/renproject/mpc/brng/testutil"
	"github.com/renproject/secp256k1-go"
	"github.com/renproject/shamir"

	btu "github.com/renproject/mpc/brng/testutil"
	"github.com/renproject/shamir/curve"
	stu "github.com/renproject/shamir/testutil"
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

	// Pedersem paramter.
	h := curve.Random()

	n := 20
	k := 7

	var (
		brnger  BRNGer
		indices []secp256k1.Secp256k1N
		b, t    int
		to      secp256k1.Secp256k1N
	)

	Setup := func() (BRNGer, int, int, secp256k1.Secp256k1N, []secp256k1.Secp256k1N) {
		b := 5
		t := k - 1
		indices := stu.RandomIndices(n)
		to := indices[0]
		brnger := New(indices, h)

		return brnger, t, b, to, indices
	}

	TransitionToWaiting := func(brnger *BRNGer, k, b int) Row {
		return brnger.TransitionStart(k, b)
	}

	TransitionToOk := func(
		brnger *BRNGer,
		to secp256k1.Secp256k1N,
		indices []secp256k1.Secp256k1N,
		k, b int,
	) {
		_ = TransitionToWaiting(brnger, k, b)
		slice := btu.RandomValidSlice(to, indices, h, k, b, k)
		_, _, _ = brnger.TransitionSlice(slice)
	}

	TransitionToError := func(
		brnger *BRNGer,
		to secp256k1.Secp256k1N,
		indices []secp256k1.Secp256k1N,
		k, t, b int,
	) {
		_ = TransitionToWaiting(brnger, k, b)
		badIndices := testutil.RandomBadIndices(t, len(indices), b)
		slice, _ := testutil.RandomInvalidSlice(to, indices, badIndices, h, n, k, b, k)
		_, _, _ = brnger.TransitionSlice(slice)
	}

	JustBeforeEach(func() {
		brnger, t, b, to, indices = Setup()
	})

	Context("State transitions (1)", func() {
		// Given that the BRNGer is in a particular state, it should transition
		// to the appropriate state or continue being in the same state
		// depending on the message supplied to it
		Context("Init state", func() {
			Specify("Start -> Waiting", func() {
				Expect(brnger.BatchSize()).To(Equal(0))

				brnger.TransitionStart(k, b)

				Expect(brnger.State()).To(Equal(Waiting))
				Expect(brnger.BatchSize()).To(Equal(b))
			})

			Specify("Slice -> Do nothing", func() {
				validSlice := btu.RandomValidSlice(to, indices, h, k, b, k)

				brnger.TransitionSlice(validSlice)

				Expect(brnger.State()).To(Equal(Init))
			})

			Specify("Reset -> Init", func() {
				brnger.Reset()

				Expect(brnger.State()).To(Equal(Init))
			})
		})

		Context("Waiting state", func() {
			JustBeforeEach(func() {
				TransitionToWaiting(&brnger, k, b)
			})

			Specify("Start -> Do nothing", func() {
				brnger.TransitionStart(k, b)

				Expect(brnger.State()).To(Equal(Waiting))
				Expect(brnger.BatchSize()).To(Equal(b))
			})

			Specify("Valid Slice -> Ok", func() {
				validSlice := btu.RandomValidSlice(to, indices, h, k, b, k)
				brnger.TransitionSlice(validSlice)

				Expect(brnger.State()).To(Equal(Ok))
			})

			Specify("Invalid Slice -> Error", func() {
				badIndices := btu.RandomBadIndices(t, n, b)
				invalidSlice, _ := btu.RandomInvalidSlice(to, indices, badIndices, h, k, k, b, k-1)
				brnger.TransitionSlice(invalidSlice)

				Expect(brnger.State()).To(Equal(Error))
			})

			Specify("Reset -> Init", func() {
				brnger.Reset()

				Expect(brnger.State()).To(Equal(Init))
			})
		})

		Context("Ok state", func() {
			JustBeforeEach(func() {
				TransitionToOk(&brnger, to, indices, k, b)
			})

			Specify("Start -> Do nothing", func() {
				brnger.TransitionStart(k, b)

				Expect(brnger.State()).To(Equal(Ok))
			})

			Specify("Slice -> Do nothing", func() {
				validSlice := btu.RandomValidSlice(to, indices, h, k, b, k)
				brnger.TransitionSlice(validSlice)

				Expect(brnger.State()).To(Equal(Ok))
			})

			Specify("Reset -> Init", func() {
				brnger.Reset()

				Expect(brnger.State()).To(Equal(Init))
			})
		})

		Context("Error state", func() {
			JustBeforeEach(func() {
				TransitionToError(&brnger, to, indices, k, t, b)
			})

			Specify("Start -> Do nothing", func() {
				brnger.TransitionStart(k, b)

				Expect(brnger.State()).To(Equal(Error))
			})

			Specify("Slice -> Do nothing", func() {
				validSlice := btu.RandomValidSlice(to, indices, h, k, b, k)
				brnger.TransitionSlice(validSlice)

				Expect(brnger.State()).To(Equal(Error))
			})

			Specify("Reset -> Init", func() {
				brnger.Reset()

				Expect(brnger.State()).To(Equal(Init))
			})
		})
	})

	Context("Share creation (2)", func() {
		// On receiving a start message in the Init state, the state machine
		// should return a valid Row.
		Specify("the returned row should be valid", func() {
			row := brnger.TransitionStart(k, b)

			Expect(btu.RowIsValid(row, k, indices, h)).To(BeTrue())
		})

		Specify("the reconstruction threshold is correct", func() {
			row := brnger.TransitionStart(k, b)

			Expect(btu.RowIsValid(row, k-1, indices, h)).To(BeFalse())
			Expect(btu.RowIsValid(row, k, indices, h)).To(BeTrue())
		})

		Specify("the returned row should have the correct batch size", func() {
			row := brnger.TransitionStart(k, b)

			Expect(row.BatchSize()).To(Equal(b))
			Expect(brnger.BatchSize()).To(Equal(b))
		})
	})

	Context("Valid slice processing (3)", func() {
		// On receiving a valid slice in the Waiting state, the state machine
		// should return the correct shares and commitment that correspond to
		// the slice.
		It("should correctly process a valid slice", func() {
			brnger.TransitionStart(k, b)

			expectedShares := make(shamir.VerifiableShares, b)
			expectedCommitments := make([]shamir.Commitment, b)
			validSlice := btu.RandomValidSlice(to, indices, h, k, b, k)

			for i, col := range validSlice {
				expectedShares[i], expectedCommitments[i] = col.Sum()
			}

			shares, commitments, _ := brnger.TransitionSlice(validSlice)

			Expect(len(shares)).To(Equal(b))
			Expect(len(commitments)).To(Equal(b))

			for i, share := range shares {
				Expect(share.Eq(&expectedShares[i])).To(BeTrue())
			}

			for i, commitment := range commitments {
				Expect(commitment.Eq(&expectedCommitments[i])).To(BeTrue())
			}
		})
	})

	Context("Invalid slice processing (4)", func() {
		// On receiving an invalid slice in the Waiting state, the state
		// machine should return a list of faults that correctly identifies the
		// invalid shares.
		It("should correctly identify faulty elements", func() {
			brnger.TransitionStart(k, b)

			badIndices := btu.RandomBadIndices(t, n, b)
			invalidSlice, expectedFaults := btu.RandomInvalidSlice(to, indices, badIndices, h, k, k, b, k-1)

			shares, commitments, faults := brnger.TransitionSlice(invalidSlice)

			Expect(len(shares)).To(Equal(0))
			Expect(len(commitments)).To(Equal(0))
			Expect(len(faults)).To(Equal(len(expectedFaults)))
			for i, expectedFault := range expectedFaults {
				Expect(faults[i]).To(Equal(expectedFault))
			}
		})
	})

	Context("Network (5)", func() {
	})
})
