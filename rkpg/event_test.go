package rkpg_test

import (
	"fmt"
	"math/rand"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	. "github.com/renproject/mpc/rkpg"
)

var _ = Describe("Event", func() {
	rand.Seed(int64(time.Now().Nanosecond()))

	Context("String", func() {
		Specify("the Stringer interface should be properly implemented", func() {
			var expected string
			for i := 0; i < 256; i++ {
				switch i {
				case 0:
					expected = "WrongBatchSize"
				case 1:
					expected = "InvalidIndex"
				case 2:
					expected = "DuplicateIndex"
				case 3:
					expected = "InconsistentShares"
				case 4:
					expected = "ShareAdded"
				case 5:
					expected = "TooManyErrors"
				case 6:
					expected = "Reconstructed"
				default:
					expected = fmt.Sprintf("Unknown(%v)", uint8(i))
				}

				Expect(TransitionEvent(i).String()).To(Equal(expected))
			}
		})
	})
})
