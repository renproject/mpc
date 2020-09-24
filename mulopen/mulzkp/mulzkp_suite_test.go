package mulzkp_test

import (
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func TestMulZkp(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "MulZkp Suite")
}
