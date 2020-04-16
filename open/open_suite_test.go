package open_test

import (
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func TestOpen(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Open Suite")
}
