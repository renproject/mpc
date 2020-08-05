package mulopen_test

import (
	"math/rand"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	. "github.com/renproject/mpc/mulopen"
	"github.com/renproject/shamir"

	"github.com/renproject/mpc/mpcutil"
	"github.com/renproject/mpc/mulopen/mulopenutil"
	"github.com/renproject/mpc/mulopen/mulzkp"
	"github.com/renproject/mpc/rkpg/rkpgutil"
	"github.com/renproject/secp256k1"
	"github.com/renproject/shamir/shamirutil"
)

var _ = Describe("MulOpener", func() {
	RandomTestParams := func() (int, int, int, []secp256k1.Fn, secp256k1.Point) {
		n := shamirutil.RandRange(9, 20)
		k := shamirutil.RandRange(2, n/3-1)
		b := shamirutil.RandRange(1, 5)
		indices := shamirutil.RandomIndices(n)
		h := secp256k1.RandomPoint()
		return n, k, b, indices, h
	}

	// TODO: This should probably be a function inside the shamir package.
	PolyEvalPoint := func(commitment shamir.Commitment, index secp256k1.Fn) secp256k1.Point {
		var acc secp256k1.Point
		acc = commitment[len(commitment)-1]
		for l := len(commitment) - 2; l >= 0; l-- {
			acc.Scale(&acc, &index)
			acc.Add(&acc, &commitment[l])
		}
		return acc
	}

	// TODO: This should probably be a function inside the shamir package.
	PedersenCommit := func(value, decommitment *secp256k1.Fn, h *secp256k1.Point) secp256k1.Point {
		var commitment, hPow secp256k1.Point
		commitment.BaseExp(value)
		hPow.Scale(h, decommitment)
		commitment.Add(&commitment, &hPow)
		return commitment
	}

	MessageBatchFromPlayer := func(
		b int, h secp256k1.Point, index secp256k1.Fn,
		aShareBatch, bShareBatch, rzgShareBatch shamir.VerifiableShares,
		aCommitmentBatch, bCommitmentBatch []shamir.Commitment,
	) []Message {
		var product secp256k1.Fn
		messageBatch := make([]Message, b)
		for i := 0; i < b; i++ {
			product.Mul(&aShareBatch[i].Share.Value, &bShareBatch[i].Share.Value)
			tau := secp256k1.RandomFn()
			aShareCommitment := PolyEvalPoint(aCommitmentBatch[i], index)
			bShareCommitment := PolyEvalPoint(bCommitmentBatch[i], index)
			productShareCommitment := PedersenCommit(&product, &tau, &h)
			proof := mulzkp.CreateProof(&h, &aShareCommitment, &bShareCommitment, &productShareCommitment,
				aShareBatch[i].Share.Value, bShareBatch[i].Share.Value,
				aShareBatch[i].Decommitment, bShareBatch[i].Decommitment, tau,
			)
			share := shamir.VerifiableShare{
				Share: shamir.Share{
					Index: index,
					Value: product,
				},
				Decommitment: tau,
			}
			share.Add(&share, &rzgShareBatch[i])
			messageBatch[i] = Message{
				VShare:     share,
				Commitment: productShareCommitment,
				Proof:      proof,
			}
		}
		return messageBatch
	}

	Context("creating a new mulopener", func() {
		Specify("the returned messages should be valid", func() {
			n, k, b, indices, h := RandomTestParams()
			playerInd := rand.Intn(n)
			index := indices[playerInd]
			aShares, aCommitments, _ := rkpgutil.RNGOutputBatch(indices, k, b, h)
			bShares, bCommitments, _ := rkpgutil.RNGOutputBatch(indices, k, b, h)
			rzgShares, rzgCommitments := rkpgutil.RZGOutputBatch(indices, 2*k-1, b, h)

			_, messages := New(
				aShares[playerInd], bShares[playerInd], rzgShares[playerInd],
				aCommitments, bCommitments, rzgCommitments,
				indices, h,
			)

			for i, message := range messages {
				// The ZKP should be valid.
				aShareCommitment := PolyEvalPoint(aCommitments[i], index)
				bShareCommitment := PolyEvalPoint(bCommitments[i], index)
				Expect(mulzkp.Verify(
					&h, &aShareCommitment, &bShareCommitment, &message.Commitment, &message.Proof,
				)).To(BeTrue())

				// The share should be valid with respect to the associated
				// commitment.
				var shareCommitment secp256k1.Point
				rzgShareCommitment := PolyEvalPoint(rzgCommitments[i], index)
				shareCommitment.Add(&message.Commitment, &rzgShareCommitment)
				com := PedersenCommit(&message.VShare.Share.Value, &message.VShare.Decommitment, &h)
				Expect(shareCommitment.Eq(&com)).To(BeTrue())
			}
		})
	})

	Context("handling messages", func() {
		Context("valid messages", func() {
			Specify("there should be no error and the return value should be nil unless it can reconstruct",
				func() {
					n, k, b, indices, h := RandomTestParams()
					playerInd := rand.Intn(n)
					index := indices[playerInd]
					aShares, aCommitments, aSecrets := rkpgutil.RNGOutputBatch(indices, k, b, h)
					bShares, bCommitments, bSecrets := rkpgutil.RNGOutputBatch(indices, k, b, h)
					rzgShares, rzgCommitments := rkpgutil.RZGOutputBatch(indices, 2*k-1, b, h)

					mulopener, _ := New(
						aShares[playerInd], bShares[playerInd], rzgShares[playerInd],
						aCommitments, bCommitments, rzgCommitments,
						indices, h,
					)

					// The number of messages received starts at 1 because a
					// mulopener handles its own message on creation.
					count := 1
					for i, ind := range indices {
						if ind.Eq(&index) {
							continue
						}
						messageBatch := MessageBatchFromPlayer(
							b, h, ind,
							aShares[i], bShares[i], rzgShares[i],
							aCommitments, bCommitments,
						)

						output, err := mulopener.HandleShareBatch(messageBatch)
						count++
						Expect(err).To(BeNil())
						if count == 2*k-1 {
							var product secp256k1.Fn
							for i, secret := range output {
								product.Mul(&aSecrets[i], &bSecrets[i])
								Expect(secret.Eq(&product)).To(BeTrue())
							}
						} else {
							Expect(output).To(BeNil())
						}
					}
				})
		})

		Context("invalid messages", func() {
			TestErrorCase := func(
				err error, minB int,
				modifyMessages func([]Message, secp256k1.Fn,
				) []Message) {
				n, k, b, indices, h := RandomTestParams()
				if b < minB {
					b = minB
				}
				playerInd := rand.Intn(n)
				index := indices[playerInd]
				aShares, aCommitments, _ := rkpgutil.RNGOutputBatch(indices, k, b, h)
				bShares, bCommitments, _ := rkpgutil.RNGOutputBatch(indices, k, b, h)
				rzgShares, rzgCommitments := rkpgutil.RZGOutputBatch(indices, 2*k-1, b, h)

				mulopener, _ := New(
					aShares[playerInd], bShares[playerInd], rzgShares[playerInd],
					aCommitments, bCommitments, rzgCommitments,
					indices, h,
				)

				otherPlayerInd := rand.Intn(n)
				for otherPlayerInd == playerInd {
					otherPlayerInd = rand.Intn(n)
				}
				otherIndex := indices[otherPlayerInd]
				messageBatch := MessageBatchFromPlayer(
					b, h, otherIndex,
					aShares[otherPlayerInd], bShares[otherPlayerInd], rzgShares[otherPlayerInd],
					aCommitments, bCommitments,
				)

				output, err := mulopener.HandleShareBatch(modifyMessages(messageBatch, index))
				Expect(output).To(BeNil())
				Expect(err).To(Equal(err))
			}

			Specify("incorrect batch size", func() {
				TestErrorCase(ErrIncorrectBatchSize, 1,
					func(messageBatch []Message, _ secp256k1.Fn) []Message {
						return messageBatch[1:]
					})
			})

			Specify("invalid index", func() {
				TestErrorCase(ErrInvalidIndex, 1,
					func(messageBatch []Message, _ secp256k1.Fn) []Message {
						messageBatch[0].VShare.Share.Index = secp256k1.RandomFn()
						return messageBatch
					})
			})

			Specify("inconsistent shares", func() {
				TestErrorCase(ErrInconsistentShares, 2,
					func(messageBatch []Message, _ secp256k1.Fn) []Message {
						messageBatch[1].VShare.Share.Index = secp256k1.RandomFn()
						return messageBatch
					})
			})

			Specify("duplicate index", func() {
				TestErrorCase(ErrDuplicateIndex, 1,
					func(messageBatch []Message, index secp256k1.Fn) []Message {
						for i := range messageBatch {
							messageBatch[i].VShare.Share.Index = index
						}
						return messageBatch
					})
			})

			Specify("invalid zkp", func() {
				TestErrorCase(ErrInvalidZKP, 1,
					func(messageBatch []Message, _ secp256k1.Fn) []Message {
						messageBatch[0].Commitment = secp256k1.RandomPoint()
						return messageBatch
					})
			})

			Specify("invalid share", func() {
				TestErrorCase(ErrInvalidShares, 1,
					func(messageBatch []Message, _ secp256k1.Fn) []Message {
						messageBatch[0].VShare.Share.Value = secp256k1.RandomFn()
						return messageBatch
					})
			})
		})
	})

	Context("panics", func() {
		Specify("batch size too small", func() {
			n, k, b, indices, h := RandomTestParams()
			playerInd := rand.Intn(n)
			aShares, aCommitments, _ := rkpgutil.RNGOutputBatch(indices, k, b, h)
			bShares, bCommitments, _ := rkpgutil.RNGOutputBatch(indices, k, b, h)
			rzgShares, rzgCommitments := rkpgutil.RZGOutputBatch(indices, 2*k-1, b, h)

			Expect(func() {
				New(
					aShares[playerInd][:0], bShares[playerInd], rzgShares[playerInd],
					aCommitments, bCommitments, rzgCommitments,
					indices, h,
				)
			}).To(Panic())
			Expect(func() {
				New(
					aShares[playerInd], bShares[playerInd][:0], rzgShares[playerInd],
					aCommitments, bCommitments, rzgCommitments,
					indices, h,
				)
			}).To(Panic())
			Expect(func() {
				New(
					aShares[playerInd], bShares[playerInd], rzgShares[playerInd][:0],
					aCommitments, bCommitments, rzgCommitments,
					indices, h,
				)
			}).To(Panic())
			Expect(func() {
				New(
					aShares[playerInd], bShares[playerInd], rzgShares[playerInd],
					aCommitments[:0], bCommitments, rzgCommitments,
					indices, h,
				)
			}).To(Panic())
			Expect(func() {
				New(
					aShares[playerInd], bShares[playerInd], rzgShares[playerInd],
					aCommitments, bCommitments[:0], rzgCommitments,
					indices, h,
				)
			}).To(Panic())
			Expect(func() {
				New(
					aShares[playerInd], bShares[playerInd], rzgShares[playerInd],
					aCommitments, bCommitments, rzgCommitments[:0],
					indices, h,
				)
			}).To(Panic())
		})

		Specify("k too small", func() {
			n, k, b, indices, h := RandomTestParams()
			playerInd := rand.Intn(n)
			aShares, aCommitments, _ := rkpgutil.RNGOutputBatch(indices, k, b, h)
			bShares, bCommitments, _ := rkpgutil.RNGOutputBatch(indices, k, b, h)
			rzgShares, rzgCommitments := rkpgutil.RZGOutputBatch(indices, 2*k-1, b, h)

			aCommitments[0] = shamir.Commitment{secp256k1.Point{}}
			Expect(func() {
				New(
					aShares[playerInd], bShares[playerInd], rzgShares[playerInd],
					aCommitments, bCommitments, rzgCommitments,
					indices, h,
				)
			}).To(Panic())
		})

		Specify("inconsistent k", func() {
			n, k, b, indices, h := RandomTestParams()
			playerInd := rand.Intn(n)
			aShares, aCommitments, _ := rkpgutil.RNGOutputBatch(indices, k, b, h)
			bShares, bCommitments, _ := rkpgutil.RNGOutputBatch(indices, k+1, b, h)
			rzgShares, rzgCommitments := rkpgutil.RZGOutputBatch(indices, 2*k-1, b, h)

			Expect(func() {
				New(
					aShares[playerInd], bShares[playerInd], rzgShares[playerInd],
					aCommitments, bCommitments, rzgCommitments,
					indices, h,
				)
			}).To(Panic())
		})

		Specify("incorrect rzg k", func() {
			n, k, b, indices, h := RandomTestParams()
			playerInd := rand.Intn(n)
			aShares, aCommitments, _ := rkpgutil.RNGOutputBatch(indices, k, b, h)
			bShares, bCommitments, _ := rkpgutil.RNGOutputBatch(indices, k, b, h)
			rzgShares, rzgCommitments := rkpgutil.RZGOutputBatch(indices, 2*k-2, b, h)

			Expect(func() {
				New(
					aShares[playerInd], bShares[playerInd], rzgShares[playerInd],
					aCommitments, bCommitments, rzgCommitments,
					indices, h,
				)
			}).To(Panic())
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
