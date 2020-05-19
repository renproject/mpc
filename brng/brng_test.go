package brng_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	. "github.com/renproject/mpc/brng"
	"github.com/renproject/mpc/brng/testutil"
	"github.com/renproject/secp256k1-go"

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
		to := secp256k1.OneSecp256k1N()
		indices := stu.RandomIndices(n)
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
		slice := testutil.RandomValidSlice(to, indices, h, b)
		_, _ = brnger.TransitionSlice(slice)
	}

	TransitionToError := func(
		brnger *BRNGer,
		to secp256k1.Secp256k1N,
		indices []secp256k1.Secp256k1N,
		k, t, b int,
	) {
		_ = TransitionToWaiting(brnger, k, b)
		badIndices := testutil.RandomBadIndices(t, len(indices), b)
		slice := testutil.RandomInvalidSlice(to, indices, badIndices, h, b)
		_, _ = brnger.TransitionSlice(slice)
	}

	JustBeforeEach(func() {
		brnger, t, b, to, indices = Setup()
	})

	Context("State transitions (1)", func() {
		Context("Init state", func() {
			Specify("Start -> Waiting", func() {
			})

			Specify("Slice -> Do nothing", func() {
			})

			Specify("Reset -> Init", func() {
			})
		})

		Context("Waiting state", func() {
			Specify("Start -> Do nothing", func() {
				TransitionToWaiting(&brnger, k, b)

				Expect(brnger.State()).To(Equal(Waiting))
			})

			Specify("Valid Slice -> Ok", func() {
			})

			Specify("Invalid Slice -> Error", func() {
			})

			Specify("Reset -> Init", func() {
			})
		})

		Context("Ok state", func() {
			Specify("Start -> Do nothing", func() {
				TransitionToOk(&brnger, to, indices, k, b)

				Expect(brnger.State()).To(Equal(Ok))
			})

			Specify("Slice -> Do nothing", func() {
			})

			Specify("Reset -> Init", func() {
			})
		})

		Context("Error state", func() {
			Specify("Start -> Do nothing", func() {
				TransitionToError(&brnger, to, indices, k, t, b)

				Expect(brnger.State()).To(Equal(Error))
			})

			Specify("Slice -> Do nothing", func() {
			})

			Specify("Reset -> Init", func() {
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

		Specify("", func() {
		})

		Specify("", func() {
		})
	})

	Context("Valid slice processing (3)", func() {
		// On receiving a valid slice in the Waiting state, the state machine
		// should return the correct shares and commitment that correspond to
		// the slice.
	})

	Context("Invalid slice processing (4)", func() {
		// On receiving an invalid slice in the Waiting state, the state
		// machine should return a list of faults that correctly identifies the
		// invalid shares.
	})

	Context("Network (5)", func() {
	})
})
