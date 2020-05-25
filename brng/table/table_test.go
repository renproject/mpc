package table_test

import (
	"math/rand"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/renproject/secp256k1-go"
	"github.com/renproject/shamir/curve"
	stu "github.com/renproject/shamir/testutil"

	. "github.com/renproject/mpc/brng/table"
	ttu "github.com/renproject/mpc/brng/table/testutil"
)

const (
	LoopTests = 50
)

var _ = Describe("Table", func() {
	Context("Row", func() {
		Specify("MakeRow correctly allocates memory for a new row", func() {
			for t := 0; t < LoopTests; t++ {
				n := 10 + rand.Intn(40)
				k := 2 + rand.Intn(n-2)
				b := 5 + rand.Intn(45)

				row := MakeRow(n, k, b)

				Expect(len(row)).To(Equal(b))
				Expect(row.BatchSize()).To(Equal(b))
				Expect(row.N()).To(Equal(n))
			}
		})
	})

	Context("Column", func() {
		Specify("", func() {
			for t := 0; t < LoopTests; t++ {
				n := 10 + rand.Intn(40)
				h := curve.Random()
				to := secp256k1.RandomSecp256k1N()
				indices := stu.RandomIndices(n)

				col, expectedSumShares, expectedSumCommitments := ttu.RandomValidCol(to, indices, h)

				sumShares, sumCommitments := col.Sum()

				Expect(sumShares).To(Equal(expectedSumShares))
				Expect(sumCommitments).To(Equal(expectedSumCommitments))
			}
		})
	})
})
