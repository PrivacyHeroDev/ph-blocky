package cmd

import (
	"fmt"
	"github.com/privacyherodev/ph-blocky/config"
	"github.com/privacyherodev/ph-blocky/log"
	"os"

	"github.com/spf13/cobra"
)

//nolint:gochecknoglobals
var (
	version    = "undefined"
	buildTime  = "undefined"
	configPath string
	cfg        config.Config
	apiHost    string
	apiPort    uint16
)

//nolint:gochecknoglobals
var rootCmd = &cobra.Command{
	Use:   "blocky",
	Short: "blocky is a DNS proxy ",
	Long: `A fast and configurable DNS Proxy
and ad-blocker for local network.
		   
Complete documentation is available at https://github.com/0xERR0R/blocky`,
	Run: func(cmd *cobra.Command, args []string) {
		serveCmd.Run(cmd, args)
	},
}

func apiURL(path string) string {
	return fmt.Sprintf("http://%s:%d%s", apiHost, apiPort, path)
}

//nolint:gochecknoinits
func init() {
	cobra.OnInitialize(initConfig)

	rootCmd.PersistentFlags().StringVarP(&configPath, "config", "c", "./config.yml", "path to config file")
	rootCmd.PersistentFlags().StringVar(&apiHost, "apiHost", "localhost", "host of blocky (API)")
	rootCmd.PersistentFlags().Uint16Var(&apiPort, "apiPort", 0, "port of blocky (API)")
}

func initConfig() {
	cfg = config.NewConfig(configPath)
	log.NewLogger(cfg.LogLevel, cfg.LogFormat)

	if apiPort == 0 {
		apiPort = cfg.HTTPPort
	}
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
