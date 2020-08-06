package inv_test

import (
	"math/rand"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	. "github.com/renproject/mpc/inv"

	"github.com/renproject/mpc/inv/invutil"
	"github.com/renproject/mpc/mpcutil"
	"github.com/renproject/mpc/rkpg/rkpgutil"
	"github.com/renproject/secp256k1"
	"github.com/renproject/shamir"
	"github.com/renproject/shamir/shamirutil"
)

var _ = Describe("inverter", func() {
	// FIXME
	Specify("FIXME", func() {
		Expect(func() { New(nil, nil, nil, nil, nil, nil, nil, secp256k1.Point{}) }).To(Panic())
	})

	Context("network", func() {
		n := 15
		k := 4
		b := 3
		t := k - 1

		tys := []invutil.MachineType{
			invutil.Offline,
			invutil.Malicious,
		}
		for _, ty := range tys {
			ty := ty

			Specify("all honest nodes should reconstruct the product of the secrets", func() {
				indices := shamirutil.RandomIndices(n)
				h := secp256k1.RandomPoint()
				machines := make([]mpcutil.Machine, n)

				aShares, aCommitments, aSecrets := rkpgutil.RNGOutputBatch(indices, k, b, h)
				rShares, rCommitments, _ := rkpgutil.RNGOutputBatch(indices, k, b, h)
				rzgShares, rzgCommitments := rkpgutil.RZGOutputBatch(indices, 2*k-1, b, h)

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
				machineType := make(map[mpcutil.ID]invutil.MachineType, n)
				for _, id := range ids {
					if _, ok := dishonestIDs[id]; ok {
						machineType[id] = ty
					} else {
						machineType[id] = invutil.Honest
					}
				}

				honestMachines := make([]*invutil.Machine, 0, n-t)
				for i, id := range ids {
					var machine mpcutil.Machine
					switch machineType[id] {
					case invutil.Offline:
						m := mpcutil.OfflineMachine(ids[i])
						machine = &m
					case invutil.Malicious:
						m := invutil.NewMaliciousMachine(
							aShares[i], rShares[i], rzgShares[i],
							aCommitments, rCommitments, rzgCommitments,
							ids, id, indices, h,
						)
						machine = &m
					case invutil.Honest:
						m := invutil.NewMachine(
							aShares[i], rShares[i], rzgShares[i],
							aCommitments, rCommitments, rzgCommitments,
							ids, id, indices, h,
						)
						honestMachines = append(honestMachines, &m)
						machine = &m
					default:
						panic("unexpected machine type")
					}
					machines[i] = machine
				}

				shuffleMsgs, _ := mpcutil.MessageShufflerDropper(ids, 0)
				network := mpcutil.NewNetwork(machines, shuffleMsgs)
				network.SetCaptureHist(true)
				err := network.Run()
				Expect(err).ToNot(HaveOccurred())

				for i := 0; i < b; i++ {
					var inv secp256k1.Fn
					inv.Inverse(&aSecrets[i])

					// Each player should hold a valid share of the inverse of the
					// input.
					shares := make(shamir.Shares, 0, n)
					vshares := make(shamir.VerifiableShares, 0, n)
					for _, machine := range honestMachines {
						output := machine.OutputShares[i]
						vshares = append(vshares, output)
						shares = append(shares, output.Share)
					}
					commitment := honestMachines[0].OutputCommitments[i]
					for _, machine := range honestMachines {
						Expect(machine.OutputCommitments[i].Eq(commitment)).To(BeTrue())
					}

					Expect(shamirutil.VsharesAreConsistent(vshares, k-1)).To(BeFalse())
					Expect(shamirutil.VsharesAreConsistent(vshares, k)).To(BeTrue())
					for _, vshare := range vshares {
						Expect(shamir.IsValid(h, &commitment, &vshare)).To(BeTrue())
					}

					secret := shamir.Open(shares)
					Expect(secret.Eq(&inv)).To(BeTrue())
				}
			})
		}
	})
})
