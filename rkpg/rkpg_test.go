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

	RandomTestParams := func() (int, int, int, int, secp256k1.Point, []secp256k1.Fn) {
		k := shamirutil.RandRange(4, 15)
		n := 3 * k
		t := k - 2
		b := shamirutil.RandRange(2, 10)
		h := secp256k1.RandomPoint()
		indices := shamirutil.RandomIndices(n)
		return n, k, t, b, h, indices
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

	RKPGShare := func(rngShare, rzgShare shamir.VerifiableShare) shamir.Share {
		var share shamir.Share
		ind := rzgShare.Share.Index
		dRnShare := shamir.NewShare(ind, rngShare.Decommitment)
		share.Add(&dRnShare, &rzgShare.Share)
		return share
	}

	Context("state transitions", func() {
		Specify("shares with invalid batch size", func() {
			for i := 0; i < trials; i++ {
				_, k, _, b, h, indices := RandomTestParams()
				rngShares, rzgShares, rngComs, _ := RXGOutputs(k, b, indices, h)
				rkpger, _ := New(indices, h, rngShares[1], rzgShares[1], rngComs)

				res, err := rkpger.HandleShareBatch(make(shamir.Shares, b-1))
				Expect(res).To(BeNil())
				Expect(err).To(Equal(ErrWrongBatchSize))
			}
		})

		Specify("shares with invalid index", func() {
			for i := 0; i < trials; i++ {
				_, k, _, b, h, indices := RandomTestParams()
				rngShares, rzgShares, rngComs, _ := RXGOutputs(k, b, indices, h)
				rkpger, _ := New(indices, h, rngShares[1], rzgShares[1], rngComs)

				// As it is an uninitialised slice, all of the shares in
				// `shares` should have index zero, which should not be in the
				// set `indices` with overwhelming probability.
				res, err := rkpger.HandleShareBatch(make(shamir.Shares, b))
				Expect(res).To(BeNil())
				Expect(err).To(Equal(ErrInvalidIndex))
			}
		})

		Specify("shares with duplicate indices", func() {
			for i := 0; i < trials; i++ {
				_, k, _, b, h, indices := RandomTestParams()
				rngShares, rzgShares, rngComs, _ := RXGOutputs(k, b, indices, h)
				rkpger, shares := New(indices, h, rngShares[0], rzgShares[0], rngComs)

				// The RKPGer has already handled its own shares, so this
				// should trigger a duplciate index error.
				res, err := rkpger.HandleShareBatch(shares)
				Expect(res).To(BeNil())
				Expect(err).To(Equal(ErrDuplicateIndex))
			}
		})

		Specify("shares with inconsistent indices", func() {
			for i := 0; i < trials; i++ {
				_, k, _, b, h, indices := RandomTestParams()
				rngShares, rzgShares, rngComs, _ := RXGOutputs(k, b, indices, h)
				rkpger, _ := New(indices, h, rngShares[0], rzgShares[0], rngComs)

				shares := make(shamir.Shares, b)
				shares[0] = shamir.NewShare(indices[1], secp256k1.Fn{})
				for j := 1; j < len(shares); j++ {
					shares[j] = shamir.NewShare(indices[2], secp256k1.Fn{})
				}

				res, err := rkpger.HandleShareBatch(shares)
				Expect(res).To(BeNil())
				Expect(err).To(Equal(ErrInconsistentShares))
			}
		})

		Specify("valid shares", func() {
			for i := 0; i < 1; i++ {
				n, k, _, b, h, indices := RandomTestParams()
				rngShares, rzgShares, rngComs, secrets := RXGOutputs(k, b, indices, h)
				rkpger, _ := New(indices, h, rngShares[0], rzgShares[0], rngComs)

				var err error
				shares := make([]shamir.Shares, n-1)
				for j := range shares {
					_, shares[j] = New(indices, h, rngShares[j+1], rzgShares[j+1], rngComs)
				}

				threshold := n - k + 1
				for j := 0; j < threshold-2; j++ {
					res, err := rkpger.HandleShareBatch(shares[j])
					Expect(err).ToNot(HaveOccurred())
					Expect(res).To(BeNil())
				}
				pubkeys, err := rkpger.HandleShareBatch(shares[threshold-1])
				Expect(err).ToNot(HaveOccurred())
				for j := range pubkeys {
					var expected secp256k1.Point
					expected.BaseExpUnsafe(&secrets[j])
					Expect(expected.Eq(&pubkeys[j])).To(BeTrue())
				}
			}
		})

		Specify("invalid shares", func() {
			for i := 0; i < trials; i++ {
				n, k, t, b, h, indices := RandomTestParams()
				rngShares, rzgShares, rngComs, _ := RXGOutputs(k, b, indices, h)
				rkpger, _ := New(indices, h, rngShares[0], rzgShares[0], rngComs)

				// Create invalid shares.
				shares := make([]shamir.Shares, n-1)
				for i := range shares {
					shares[i] = make(shamir.Shares, b)
					for j := range shares[i] {
						shares[i][j] = RKPGShare(rngShares[i+1][j], rzgShares[i+1][j])
					}
				}
				badBuf := rand.Intn(b)
				for i := 0; i < t; i++ {
					shares[i][badBuf] = shamir.NewShare(shares[i][badBuf].Index, secp256k1.NewFnFromU16(0))
				}

				threshold := n - k + 1
				errThreshold := n - 2
				for i := 0; i < threshold-2; i++ {
					res, err := rkpger.HandleShareBatch(shares[i])
					Expect(err).ToNot(HaveOccurred())
					Expect(res).To(BeNil())
				}
				for i := threshold - 2; i < errThreshold-2; i++ {
					res, err := rkpger.HandleShareBatch(shares[i])
					Expect(err).To(Equal(ErrTooManyErrors))
					Expect(res).To(BeNil())
				}
				res, err := rkpger.HandleShareBatch(shares[errThreshold-1])
				Expect(res).ToNot(BeNil())
				Expect(err).ToNot(HaveOccurred())
			}
		})
	})

	Context("initial messages", func() {
		Specify("shares with the wrong batch size", func() {
			for i := 0; i < trials; i++ {
				_, _, _, b, h, indices := RandomTestParams()
				rngShares := make(shamir.VerifiableShares, b)
				rzgShares := make(shamir.VerifiableShares, b)
				rngComs := make([]shamir.Commitment, b)

				Expect(func() { New(indices, h, rngShares[:b-1], rzgShares, rngComs) }).To(Panic())
				Expect(func() { New(indices, h, rngShares, rzgShares[:b-1], rngComs) }).To(Panic())
				Expect(func() { New(indices, h, rngShares, rzgShares, rngComs[:b-1]) }).To(Panic())
			}
		})

		Specify("inconsistent share indices", func() {
			for i := 0; i < trials; i++ {
				_, _, _, b, h, indices := RandomTestParams()
				rngShares := make(shamir.VerifiableShares, b)
				rzgShares := make(shamir.VerifiableShares, b)
				rngComs := make([]shamir.Commitment, b)

				rngShares[0] = shamir.NewVerifiableShare(
					shamir.NewShare(secp256k1.RandomFn(), secp256k1.Fn{}),
					secp256k1.Fn{},
				)
				Expect(func() { New(indices, h, rngShares, rzgShares, rngComs) }).To(Panic())
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
					n, k, t, b, h, indices := RandomTestParams()
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
								indices,
								h,
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
