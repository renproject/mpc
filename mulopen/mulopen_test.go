package mulopen_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	. "github.com/renproject/mpc/mulopen"

	"github.com/renproject/mpc/mpcutil"
	"github.com/renproject/mpc/mulopen/mulopenutil"
	"github.com/renproject/mpc/rkpg/rkpgutil"
	"github.com/renproject/secp256k1"
	"github.com/renproject/shamir/shamirutil"
)

var _ = Describe("MulOpener", func() {
	Context("panics", func() {
		Specify("batch size too small", func() {
			// FIXME
			Expect(func() { New(nil, nil, nil, nil, nil, nil, nil, secp256k1.Point{}) }).To(Panic())
		})
	})

	Context("network", func() {
		n := 20
		k := 6
		b := 5

		Specify("all honest nodes should reconstruct the product of the secrets", func() {
			indices := shamirutil.RandomIndices(n)
			h := secp256k1.RandomPoint()
			machines := make([]mpcutil.Machine, n)

			aShares, aCommitments, aSecrets := rkpgutil.RNGOutputBatch(indices, k, b, h)
			bShares, bCommitments, bSecrets := rkpgutil.RNGOutputBatch(indices, k, b, h)
			rzgShares, rzgCommitments := rkpgutil.RZGOutputBatch(indices, 2*k-1, b, h)

			ids := make([]mpcutil.ID, n)
			for i := range ids {
				ids[i] = mpcutil.ID(i + 1)
			}

			for i, id := range ids {
				machine := mulopenutil.NewMachine(
					aShares[i], bShares[i], rzgShares[i],
					aCommitments, bCommitments, rzgCommitments,
					ids, id, indices, h,
				)
				machines[i] = &machine
			}

			shuffleMsgs, _ := mpcutil.MessageShufflerDropper(ids, 0)
			network := mpcutil.NewNetwork(machines, shuffleMsgs)
			network.SetCaptureHist(true)
			err := network.Run()
			Expect(err).ToNot(HaveOccurred())

			for i := 0; i < b; i++ {
				var product secp256k1.Fn
				product.Mul(&aSecrets[i], &bSecrets[i])

				for _, machine := range machines {
					output := machine.(*mulopenutil.Machine).Output[i]
					Expect(output.Eq(&product)).To(BeTrue())
				}
			}
		})
	})
})
