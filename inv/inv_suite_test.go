package inv_test

import (
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func TestInv(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Inv Suite")
}
