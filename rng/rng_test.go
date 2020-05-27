package rng_test

import (
	"math/rand"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	stu "github.com/renproject/shamir/testutil"

	"github.com/renproject/mpc/rng"
)

var _ = Describe("Rng", func() {
	rand.Seed(int64(time.Now().Nanosecond()))

	Context("State Transitions and properties", func() {
		Specify("Init state", func() {
			n := 5
			indices := make([]rng.Fn, n)
			for i, index := range stu.SequentialIndices(n) {
				indices[i] = rng.Fn(index)
			}
			index := indices[0]
			b, k := uint32(4), uint32(3)
			event, rnger := rng.New(index, indices, b, k)

			Expect(event).To(Equal(rng.Initialised))
			Expect(rnger.N()).To(Equal(n))
			Expect(rnger.BatchSize()).To(Equal(b))
			Expect(rnger.Threshold()).To(Equal(k))
			Expect(rnger.HasConstructedShares()).ToNot(BeTrue())
		})
	})
})
