package table_test

import (
	"bytes"
	"math/rand"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/renproject/secp256k1-go"
	"github.com/renproject/shamir/curve"
	stu "github.com/renproject/shamir/testutil"

	. "github.com/renproject/mpc/brng/table"
	ttu "github.com/renproject/mpc/brng/table/testutil"
	btu "github.com/renproject/mpc/brng/testutil"
)

const (
	LoopTests = 50
)

var _ = Describe("Table", func() {
	Context("Sharing", func() {
		It("Marshals and Unmarshals correctly", func() {
			for t := 0; t < LoopTests; t++ {
				n := 10 + rand.Intn(40)
				k := 2 + rand.Intn(n-2)
				h := curve.Random()
				indices := stu.RandomIndices(n)

				sharing := btu.RandomValidSharing(indices, k, h)

				buf := bytes.NewBuffer([]byte{})
				m, err := sharing.Marshal(buf, sharing.SizeHint())
				Expect(err).ToNot(HaveOccurred())
				Expect(m).To(Equal(0))

				var unmarshalledSharing Sharing
				m, err = unmarshalledSharing.Unmarshal(buf, sharing.SizeHint())
				Expect(err).ToNot(HaveOccurred())
				Expect(m).To(Equal(0))

				Expect(unmarshalledSharing).To(Equal(sharing))
			}
		})
	})

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

		Context("Marshalling and Unmarshalling", func() {
			It("Marshals and Unmarshals correctly", func() {
				for t := 0; t < LoopTests; t++ {
					n := 10 + rand.Intn(40)
					k := 2 + rand.Intn(n-2)
					b := 5 + rand.Intn(45)
					h := curve.Random()
					indices := stu.RandomIndices(n)

					row := btu.RandomValidRow(indices, k, b, h)

					buf := bytes.NewBuffer([]byte{})
					m, err := row.Marshal(buf, row.SizeHint())
					Expect(err).ToNot(HaveOccurred())
					Expect(m).To(Equal(0))

					var unmarshalledRow Row
					m, err = unmarshalledRow.Unmarshal(buf, row.SizeHint())
					Expect(err).ToNot(HaveOccurred())
					Expect(m).To(Equal(0))

					Expect(unmarshalledRow).To(Equal(row))
				}
			})
		})
	})

	Context("Column", func() {
		Specify("Sum correctly adds shares and commitments", func() {
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

		Context("Marshalling and Unmarshalling", func() {
			It("Marshals and Unmarshals correctly", func() {
				for t := 0; t < LoopTests; t++ {
					n := 10 + rand.Intn(40)
					h := curve.Random()
					to := secp256k1.RandomSecp256k1N()
					indices := stu.RandomIndices(n)

					col, _, _ := ttu.RandomValidCol(to, indices, h)

					buf := bytes.NewBuffer([]byte{})
					m, err := col.Marshal(buf, col.SizeHint())
					Expect(err).ToNot(HaveOccurred())
					Expect(m).To(Equal(0))

					var unmarshalledCol Col
					m, err = unmarshalledCol.Unmarshal(buf, col.SizeHint())
					Expect(err).ToNot(HaveOccurred())
					Expect(m).To(Equal(0))

					Expect(unmarshalledCol).To(Equal(col))
				}
			})
		})
	})
})
