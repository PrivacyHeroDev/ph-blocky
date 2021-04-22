package server

import (
	"testing"

	"github.com/privacyherodev/ph-blocky/log"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func TestDNSServer(t *testing.T) {
	log.NewLogger("Warn", "text")
	RegisterFailHandler(Fail)
	RunSpecs(t, "Server Suite")
}
