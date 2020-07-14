package table_test

import (
	"bytes"
	"math/rand"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/renproject/secp256k1"
	"github.com/renproject/shamir"
	"github.com/renproject/shamir/shamirutil"

	"github.com/renproject/mpc/brng/brngutil"
	. "github.com/renproject/mpc/brng/table"
	"github.com/renproject/mpc/brng/table/tableutil"
)

const (
	LoopTests = 10
)

var _ = Describe("Table", func() {
	rand.Seed(int64(time.Now().Nanosecond()))

	Context("Sharing", func() {
		It("Marshals and Unmarshals correctly", func() {
			for t := 0; t < LoopTests; t++ {
				n := 10 + rand.Intn(40)
				k := 2 + rand.Intn(n-2)
				h := secp256k1.RandomPoint()
				indices := shamirutil.RandomIndices(n)

				sharing := brngutil.RandomValidSharing(indices, k, h)

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

	Context("Element", func() {
		It("Marshals and Unmarshals correctly", func() {
			for t := 0; t < LoopTests; t++ {
				to := secp256k1.RandomSecp256k1N()
				from := secp256k1.RandomSecp256k1N()
				h := secp256k1.RandomPoint()

				element, _, _ := tableutil.RandomValidElement(to, from, h)

				buf := bytes.NewBuffer([]byte{})
				m, err := element.Marshal(buf, element.SizeHint())
				Expect(err).ToNot(HaveOccurred())
				Expect(m).To(Equal(0))

				var unmarshalledElement Element
				m, err = unmarshalledElement.Unmarshal(buf, element.SizeHint())
				Expect(err).ToNot(HaveOccurred())
				Expect(m).To(Equal(0))

				Expect(unmarshalledElement).To(Equal(element))
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
					n := 5 + rand.Intn(40)
					k := 2 + rand.Intn(n-2)
					b := 5 + rand.Intn(45)
					h := secp256k1.RandomPoint()
					indices := shamirutil.RandomIndices(n)

					row := brngutil.RandomValidRow(indices, k, b, h)

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
				h := secp256k1.RandomPoint()
				to := secp256k1.RandomSecp256k1N()
				indices := shamirutil.RandomIndices(n)

				col, expectedSumShares, expectedSumCommitments := tableutil.RandomValidCol(to, indices, h)

				sumShares, sumCommitments := col.Sum()

				Expect(sumShares).To(Equal(expectedSumShares))
				Expect(sumCommitments).To(Equal(expectedSumCommitments))
			}
		})

		Context("Marshalling and Unmarshalling", func() {
			It("Marshals and Unmarshals correctly", func() {
				for t := 0; t < LoopTests; t++ {
					n := 5 + rand.Intn(40)
					h := secp256k1.RandomPoint()
					to := secp256k1.RandomSecp256k1N()
					indices := shamirutil.RandomIndices(n)

					col, _, _ := tableutil.RandomValidCol(to, indices, h)

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

	Context("Slice", func() {
		Context("HasValidForm", func() {
			It("correctly notices invalid form (batch size = 0)", func() {
				slice := Slice{}

				Expect(slice.HasValidForm()).To(Equal(false))
			})

			It("correctly notices invalid form (mismatching col lengths)", func() {
				for t := 0; t < LoopTests; t++ {
					n := 10 + rand.Intn(40)
					h := secp256k1.RandomPoint()
					indices := shamirutil.SequentialIndices(n)

					slice := make(Slice, n)
					for i := range slice {
						// NOTE: its improbable that all r's will be the same
						r := 1 + rand.Intn(n-1)
						col, _, _ := tableutil.RandomValidCol(indices[i], indices[:r], h)
						slice[i] = col
					}

					Expect(slice.BatchSize()).To(Equal(n))
					Expect(slice.HasValidForm()).ToNot(BeTrue())
				}
			})

			It("correctly notices a valid form", func() {
				for t := 0; t < LoopTests; t++ {
					n := 5 + rand.Intn(40)
					k := 2 + rand.Intn(n-2)
					b := 5 + rand.Intn(35)
					t := 1 + rand.Intn(k-1)
					h := secp256k1.RandomPoint()
					indices := shamirutil.RandomIndices(n)
					to_id := rand.Intn(n)
					to := indices[to_id]

					slice := brngutil.RandomValidSlice(to, indices, h, k, b, t)

					Expect(slice.HasValidForm()).To(BeTrue())
				}
			})
		})

		Context("Marshalling and Unmarshalling", func() {
			It("Marshals and Unmarshals correctly", func() {
				for t := 0; t < LoopTests; t++ {
					n := 5 + rand.Intn(40)
					k := 2 + rand.Intn(n-2)
					b := 5 + rand.Intn(35)
					t := 1 + rand.Intn(k-1)
					h := secp256k1.RandomPoint()
					indices := shamirutil.RandomIndices(n)
					to_id := rand.Intn(n)
					to := indices[to_id]

					slice := brngutil.RandomValidSlice(to, indices, h, k, b, t)

					buf := bytes.NewBuffer([]byte{})
					m, err := slice.Marshal(buf, slice.SizeHint())
					Expect(err).ToNot(HaveOccurred())
					Expect(m).To(Equal(0))

					var unmarshalledSlice Slice
					m, err = unmarshalledSlice.Unmarshal(buf, slice.SizeHint())
					Expect(err).ToNot(HaveOccurred())
					Expect(m).To(Equal(0))

					Expect(unmarshalledSlice).To(Equal(slice))
				}
			})
		})

		It("correctly identifies faults in an invalid slice", func() {
			n := 5 + rand.Intn(40)
			k := 2 + rand.Intn(n-2)
			b := 5 + rand.Intn(35)
			t := 1 + rand.Intn(k-1)
			h := secp256k1.RandomPoint()
			indices := shamirutil.RandomIndices(n)
			to_id := rand.Intn(n)
			to := indices[to_id]

			invalidSlice, expectedFaults := brngutil.RandomInvalidSlice(to, indices, h, n, k, b, t)

			vssChecker := shamir.NewVSSChecker(h)
			faults := invalidSlice.Faults(&vssChecker)

			Expect(faults).To(Equal(expectedFaults))
		})
	})

	Context("Table", func() {
		Context("Marshalling and Unmarshalling", func() {
			It("Marshals and Unmarshals correctly", func() {
				for t := 0; t < LoopTests; t++ {
					n := 5 + rand.Intn(40)
					k := 2 + rand.Intn(n-2)
					b := 5 + rand.Intn(35)
					t := 1 + rand.Intn(k-1)
					h := secp256k1.RandomPoint()
					indices := shamirutil.RandomIndices(n)

					table := brngutil.RandomValidTable(indices, h, k, b, t)

					buf := bytes.NewBuffer([]byte{})
					m, err := table.Marshal(buf, table.SizeHint())
					Expect(err).ToNot(HaveOccurred())
					Expect(m).To(Equal(0))

					var unmarshalledTable Table
					m, err = unmarshalledTable.Unmarshal(buf, table.SizeHint())
					Expect(err).ToNot(HaveOccurred())
					Expect(m).To(Equal(0))

					Expect(unmarshalledTable).To(Equal(table))
				}
			})
		})

		Context("HasValidDimensions", func() {
			It("correctly notices invalid table (height = 0)", func() {
				table := Table{}

				Expect(table.HasValidDimensions()).ToNot(BeTrue())
			})

			It("correctly notices invalid table (contains row of batch size = 0)", func() {
				n := 5 + rand.Intn(40)
				k := 2 + rand.Intn(n-2)
				b := 5 + rand.Intn(45)
				h := secp256k1.RandomPoint()
				indices := shamirutil.RandomIndices(n)

				validRow := brngutil.RandomValidRow(indices, k, b, h)

				table := Table{Row{}, validRow}

				Expect(table.HasValidDimensions()).ToNot(BeTrue())
			})

			It("correctly notices an invalid table (all rows not the same size)", func() {
				n := 5 + rand.Intn(40)
				k := 2 + rand.Intn(n-2)
				b := 5 + rand.Intn(45)
				h := secp256k1.RandomPoint()
				indices := shamirutil.RandomIndices(n)

				validRow1 := brngutil.RandomValidRow(indices, k, b, h)
				validRow2 := brngutil.RandomValidRow(indices, k, b+1, h)

				table := Table{validRow1, validRow2}

				Expect(table.HasValidDimensions()).ToNot(BeTrue())
			})

			It("correctly notices an invalid table (all rows not the same length)", func() {
				n := 5 + rand.Intn(40)
				k := 2 + rand.Intn(n-2)
				b := 5 + rand.Intn(45)
				h := secp256k1.RandomPoint()
				indices1 := shamirutil.RandomIndices(n)
				indices2 := shamirutil.RandomIndices(n + 1)

				validRow1 := brngutil.RandomValidRow(indices1, k, b, h)
				validRow2 := brngutil.RandomValidRow(indices2, k, b, h)

				table := Table{validRow1, validRow2}

				Expect(table.HasValidDimensions()).ToNot(BeTrue())
			})

			It("correctly notices a valid table", func() {
				n := 5 + rand.Intn(40)
				k := 2 + rand.Intn(n-2)
				b := 5 + rand.Intn(35)
				t := 1 + rand.Intn(k-1)
				h := secp256k1.RandomPoint()
				indices := shamirutil.RandomIndices(n)

				table := brngutil.RandomValidTable(indices, h, k, b, t)

				Expect(table.HasValidDimensions()).To(BeTrue())
			})
		})

		It("correctly takes slice at provided index", func() {
			for t := 0; t < LoopTests; t++ {
				n := 5 + rand.Intn(25)
				k := 2 + rand.Intn(n-2)
				b := 5 + rand.Intn(15)
				h := secp256k1.RandomPoint()
				indices := shamirutil.SequentialIndices(n)

				table := brngutil.RandomValidTable(indices, h, k, b, n)

				for i := 1; i <= n; i++ {
					at := secp256k1.NewSecp256k1N(uint64(i))
					slice := table.TakeSlice(at, indices)

					for j, col := range slice {
						Expect(len(col)).To(Equal(n))

						for _, element := range col {
							from := element.From()
							fromUint := from.Uint64()
							sharingInTable := table[fromUint-1][j]
							share, err := sharingInTable.ShareWithIndex(at)

							Expect(err).To(BeNil())
							Expect(element.Share()).To(Equal(share))
						}
					}
				}
			}
		})
	})
})
