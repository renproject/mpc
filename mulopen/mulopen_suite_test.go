package mulopen_test

import (
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func TestMulopen(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Mulopen Suite")
}
