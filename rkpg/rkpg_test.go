package rkpg_test

import (
	"fmt"
	"math/rand"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/renproject/mpc/mpcutil"
	. "github.com/renproject/mpc/rkpg"
	"github.com/renproject/mpc/rkpg/rkpgutil"
	"github.com/renproject/shamir"

	"github.com/renproject/secp256k1"
	"github.com/renproject/shamir/shamirutil"
)

var _ = Describe("RKPG", func() {
	rand.Seed(int64(time.Now().Nanosecond()))
	trials := 10

	RandomTestParams := func() (int, int, int, int, secp256k1.Point, []secp256k1.Fn, Params, State) {
		k := shamirutil.RandRange(4, 15)
		n := 3 * k
		t := k - 2
		b := shamirutil.RandRange(2, 10)
		h := secp256k1.RandomPoint()
		indices := shamirutil.RandomIndices(n)
		params := CreateParams(k, b, h, indices)
		state := NewState(n, b)
		return n, k, t, b, h, indices, params, state
	}

	RXGOutputs := func(k, b int, indices []secp256k1.Fn, h secp256k1.Point) (
		[]shamir.VerifiableShares,
		[]shamir.VerifiableShares,
		[]shamir.Commitment,
		[]secp256k1.Fn,
	) {
		rngShares, rngComs, secrets := rkpgutil.RNGOutputBatch(indices, k, b, h)
		rzgShares, _ := rkpgutil.RZGOutputBatch(indices, k, b, h)
		return rngShares, rzgShares, rngComs, secrets
	}

	Context("state transitions", func() {
		CreateInvalidShares := func(
			n, t, b int,
			params *Params,
			rngShares, rzgShares []shamir.VerifiableShares,
		) []shamir.Shares {
			var err error
			shares := make([]shamir.Shares, n)
			for i := range shares {
				shares[i], err = InitialMessages(params, rngShares[i], rzgShares[i])
				Expect(err).ToNot(HaveOccurred())
			}

			badBuf := rand.Intn(b)
			for i := 0; i < t; i++ {
				shares[i][badBuf] = shamir.NewShare(shares[i][badBuf].Index(), secp256k1.NewFnFromU16(0))
			}

			return shares
		}

		CheckAgainstInvalidShares := func(
			n, k int,
			state *State,
			params *Params,
			shares []shamir.Shares,
			coms []shamir.Commitment,
		) {
			threshold := n - k + 1
			errThreshold := n - 2
			for i := 0; i < threshold-1; i++ {
				res, e := HandleShareBatch(state, params, coms, shares[i])
				Expect(e).To(Equal(ShareAdded))
				Expect(res).To(BeNil())
			}
			for i := threshold - 1; i < errThreshold-1; i++ {
				res, e := HandleShareBatch(state, params, coms, shares[i])
				Expect(e).To(Equal(TooManyErrors))
				Expect(res).To(BeNil())
			}
			res, e := HandleShareBatch(state, params, coms, shares[errThreshold-1])
			Expect(res).ToNot(BeNil())
			Expect(e).To(Equal(Reconstructed))
		}

		Specify("shares with invalid batch size", func() {
			for i := 0; i < trials; i++ {
				_, _, _, b, _, _, params, state := RandomTestParams()
				shares := make(shamir.Shares, b)

				res, e := HandleShareBatch(&state, &params, []shamir.Commitment{}, shares[:b-1])
				Expect(res).To(BeNil())
				Expect(e).To(Equal(WrongBatchSize))
			}
		})

		Specify("shares with invalid index", func() {
			for i := 0; i < trials; i++ {
				_, _, _, b, _, _, params, state := RandomTestParams()
				shares := make(shamir.Shares, b)

				// As it is an uninitialised slice, all of the shares in
				// `shares` should have index zero, which should not be in the
				// set `indices` with overwhelming probability.
				res, e := HandleShareBatch(&state, &params, []shamir.Commitment{}, shares)
				Expect(res).To(BeNil())
				Expect(e).To(Equal(InvalidIndex))
			}
		})

		Specify("shares with duplicate indices", func() {
			for i := 0; i < trials; i++ {
				_, _, _, b, _, indices, params, state := RandomTestParams()
				shares := make(shamir.Shares, b)

				for i := range shares {
					shares[i] = shamir.NewShare(indices[0], secp256k1.Fn{})
				}

				_, _ = HandleShareBatch(&state, &params, []shamir.Commitment{}, shares)
				res, e := HandleShareBatch(&state, &params, []shamir.Commitment{}, shares)
				Expect(res).To(BeNil())
				Expect(e).To(Equal(DuplicateIndex))
			}
		})

		Specify("shares with inconsistent indices", func() {
			for i := 0; i < trials; i++ {
				_, _, _, b, _, indices, params, state := RandomTestParams()
				shares := make(shamir.Shares, b)

				shares[0] = shamir.NewShare(indices[0], secp256k1.Fn{})
				for i := 1; i < len(shares); i++ {
					shares[i] = shamir.NewShare(indices[1], secp256k1.Fn{})
				}

				res, e := HandleShareBatch(&state, &params, []shamir.Commitment{}, shares)
				Expect(res).To(BeNil())
				Expect(e).To(Equal(InconsistentShares))
			}
		})

		Specify("valid shares", func() {
			for i := 0; i < 1; i++ {
				n, k, _, b, h, indices, params, state := RandomTestParams()
				rngShares, rzgShares, rngComs, secrets := RXGOutputs(k, b, indices, h)

				var err error
				shares := make([]shamir.Shares, n)
				for i := range shares {
					shares[i], err = InitialMessages(&params, rngShares[i], rzgShares[i])
					Expect(err).ToNot(HaveOccurred())
				}

				threshold := n - k + 1
				for i := 0; i < threshold-1; i++ {
					res, e := HandleShareBatch(&state, &params, rngComs, shares[i])
					Expect(e).To(Equal(ShareAdded))
					Expect(res).To(BeNil())
				}
				pubkeys, e := HandleShareBatch(&state, &params, rngComs, shares[threshold-1])
				Expect(e).To(Equal(Reconstructed))
				for i := range pubkeys {
					var expected secp256k1.Point
					expected.BaseExpUnsafe(&secrets[i])
					Expect(expected.Eq(&pubkeys[i])).To(BeTrue())
				}
			}
		})

		Specify("invalid shares", func() {
			for i := 0; i < trials; i++ {
				n, k, t, b, h, indices, params, state := RandomTestParams()
				rngShares, rzgShares, rngComs, _ := RXGOutputs(k, b, indices, h)

				shares := CreateInvalidShares(n, t, b, &params, rngShares, rzgShares)
				CheckAgainstInvalidShares(n, k, &state, &params, shares, rngComs)
			}
		})

		Specify("the state object can be reused", func() {
			for i := 0; i < trials; i++ {
				n, k, t, b, h, indices, params, state := RandomTestParams()
				rngShares, rzgShares, rngComs, _ := RXGOutputs(k, b, indices, h)

				shares := CreateInvalidShares(n, t, b, &params, rngShares, rzgShares)
				CheckAgainstInvalidShares(n, k, &state, &params, shares, rngComs)

				state.Clear()
				CheckAgainstInvalidShares(n, k, &state, &params, shares, rngComs)
			}
		})
	})

	Context("initial messages", func() {
		Specify("shares with the wrong batch size", func() {
			for i := 0; i < trials; i++ {
				_, _, _, b, _, _, params, _ := RandomTestParams()
				rngShares := make(shamir.VerifiableShares, b)
				rzgShares := make(shamir.VerifiableShares, b)

				_, err := InitialMessages(&params, rngShares[:b-1], rzgShares)
				Expect(err).To(HaveOccurred())
				_, err = InitialMessages(&params, rngShares, rzgShares[:b-1])
				Expect(err).To(HaveOccurred())
				_, err = InitialMessages(&params, rngShares[:b-1], rzgShares[:b-1])
				Expect(err).To(HaveOccurred())
			}
		})

		Specify("inconsistent share indices", func() {
			for i := 0; i < trials; i++ {
				_, _, _, b, _, _, params, _ := RandomTestParams()
				rngShares := make(shamir.VerifiableShares, b)
				rzgShares := make(shamir.VerifiableShares, b)

				rngShares[0] = shamir.NewVerifiableShare(
					shamir.NewShare(secp256k1.RandomFn(), secp256k1.Fn{}),
					secp256k1.Fn{},
				)
				_, err := InitialMessages(&params, rngShares, rzgShares)
				Expect(err).To(HaveOccurred())
			}
		})

		Specify("shares with invalid indices", func() {
			for i := 0; i < trials; i++ {
				_, _, _, b, _, _, params, _ := RandomTestParams()
				rngShares := make(shamir.VerifiableShares, b)
				rzgShares := make(shamir.VerifiableShares, b)

				_, err := InitialMessages(&params, rngShares, rzgShares)
				Expect(err).To(HaveOccurred())
			}
		})
	})

	Context("network simulation", func() {
		tys := []rkpgutil.MachineType{
			rkpgutil.Offline,
			rkpgutil.Malicious,
			rkpgutil.MaliciousZero,
		}

		for _, ty := range tys {
			Context(fmt.Sprintf("dishonest machine type %v", ty), func() {
				Specify("players should end up with the same correct public key", func() {
					n, k, t, b, h, indices, params, _ := RandomTestParams()
					rngShares, rzgShares, rngComs, secrets := RXGOutputs(k, b, indices, h)
					ids := make([]mpcutil.ID, n)
					for i := range ids {
						ids[i] = mpcutil.ID(i + 1)
					}
					dishonestIDs := make(map[mpcutil.ID]struct{}, t)
					{
						tmp := make([]mpcutil.ID, n)
						copy(tmp, ids)
						rand.Shuffle(len(tmp), func(i, j int) {
							tmp[i], tmp[j] = tmp[j], tmp[i]
						})
						for _, id := range tmp[:t] {
							dishonestIDs[id] = struct{}{}
						}
					}
					machineType := make(map[mpcutil.ID]rkpgutil.MachineType, n)
					for _, id := range ids {
						if _, ok := dishonestIDs[id]; ok {
							machineType[id] = ty
						} else {
							machineType[id] = rkpgutil.Honest
						}
					}

					machines := make([]mpcutil.Machine, n)
					for i, id := range ids {
						state := NewState(n, b)
						var machine mpcutil.Machine
						switch machineType[id] {
						case rkpgutil.Offline:
							m := mpcutil.OfflineMachine(ids[i])
							machine = &m
						case rkpgutil.Malicious:
							m := rkpgutil.NewMaliciousMachine(ids[i], ids, int32(b), indices, false)
							machine = &m
						case rkpgutil.MaliciousZero:
							m := rkpgutil.NewMaliciousMachine(ids[i], ids, int32(b), indices, true)
							machine = &m
						case rkpgutil.Honest:
							m := rkpgutil.NewHonestMachine(
								ids[i],
								ids,
								params,
								state,
								rngComs,
								rngShares[i],
								rzgShares[i],
							)
							machine = &m
						}
						machines[i] = machine
					}
					shuffleMsgs, _ := mpcutil.MessageShufflerDropper(ids, 0)
					network := mpcutil.NewNetwork(machines, shuffleMsgs)
					network.SetCaptureHist(true)
					err := network.Run()
					Expect(err).ToNot(HaveOccurred())

					// All players should have the same public keys.
					var refPoints []secp256k1.Point
					for i := range machines {
						if machineType[machines[i].ID()] == rkpgutil.Honest {
							refPoints = machines[i].(*rkpgutil.HonestMachine).Points
							break
						}
					}
					for i := range machines {
						if machineType[machines[i].ID()] != rkpgutil.Honest {
							continue
						}
						points := machines[i].(*rkpgutil.HonestMachine).Points
						for j := range refPoints {
							Expect(refPoints[j].Eq(&points[j])).To(BeTrue())
						}
					}

					// The public keys should correspond to the private keys.
					for i := range refPoints {
						var expected secp256k1.Point
						expected.BaseExpUnsafe(&secrets[i])
						Expect(expected.Eq(&refPoints[i])).To(BeTrue())
					}
				})
			})
		}
	})
})
