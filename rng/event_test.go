package rng_test

import (
	"fmt"
	"math/rand"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/renproject/mpc/rng"
)

var _ = Describe("State", func() {
	rand.Seed(int64(time.Now().Nanosecond()))

	Context("String", func() {
		Specify("the Stringer interface should be properly implemented", func() {
			var expected string
			for i := 0; i < 256; i++ {
				switch i {
				case 0:
					expected = "Initialised"
				case 1:
					expected = "SharesIgnored"
				case 2:
					expected = "CommitmentsConstructed"
				case 3:
					expected = "SharesConstructed"
				case 4:
					expected = "OpeningsIgnored"
				case 5:
					expected = "OpeningsAdded"
				case 6:
					expected = "RNGsReconstructed"
				case 7:
					expected = "Reset"
				default:
					expected = fmt.Sprintf("Unknown(%v)", uint8(i))
				}

				Expect(rng.TransitionEvent(i).String()).To(Equal(expected))
			}
		})
	})
})
