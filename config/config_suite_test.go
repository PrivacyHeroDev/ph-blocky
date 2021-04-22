package config

import (
	"github.com/privacyherodev/ph-blocky/log"
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func TestConfig(t *testing.T) {
	log.NewLogger("Warn", "Text")
	RegisterFailHandler(Fail)
	RunSpecs(t, "Config Suite")
}
