package zkp_test

import (
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func TestMulZkp(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Zkp Suite")
}
