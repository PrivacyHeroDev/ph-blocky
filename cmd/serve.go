package cmd

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/privacyherodev/ph-blocky/config"
	"github.com/privacyherodev/ph-blocky/server"

	"github.com/privacyherodev/ph-blocky/log"

	"github.com/spf13/cobra"
)

//nolint:gochecknoinits
func init() {
	rootCmd.AddCommand(serveCmd)
}

//nolint:gochecknoglobals
var (
	serveCmd = &cobra.Command{
		Use:   "serve",
		Args:  cobra.NoArgs,
		Short: "start blocky DNS server (default command)",
		Run:   startServer,
	}
	done chan bool
)

func startServer(_ *cobra.Command, _ []string) {
	printBanner()

	configureHTTPClient(&cfg)

	signals := make(chan os.Signal)
	done = make(chan bool)

	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)

	srv, err := server.NewServer(&cfg)
	if err != nil {
		log.Logger.Fatal("cant start server: ", err)
	}

	srv.Start()

	go func() {
		<-signals
		log.Logger.Infof("Terminating...")
		srv.Stop()
		done <- true
	}()

	<-done
}

func configureHTTPClient(cfg *config.Config) {
	if cfg.BootstrapDNS != (config.Upstream{}) {
		if cfg.BootstrapDNS.Net == "tcp" || cfg.BootstrapDNS.Net == "udp" {
			dns := net.JoinHostPort(cfg.BootstrapDNS.Host, fmt.Sprint(cfg.BootstrapDNS.Port))
			log.Logger.Debugf("using %s as bootstrap dns server", dns)

			r := &net.Resolver{
				PreferGo: true,
				Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
					d := net.Dialer{
						Timeout: time.Millisecond * time.Duration(2000),
					}
					return d.DialContext(ctx, cfg.BootstrapDNS.Net, dns)
				}}

			http.DefaultTransport = &http.Transport{
				Dial: (&net.Dialer{
					Timeout:  5 * time.Second,
					Resolver: r,
				}).Dial,
				TLSHandshakeTimeout: 5 * time.Second,
			}
		} else {
			log.Logger.Fatal("bootstrap dns net should be tcp+udp")
		}
	}
}

func printBanner() {
	log.Logger.Info("_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/")
	log.Logger.Info("_/                                                              _/")
	log.Logger.Info("_/                                                              _/")
	log.Logger.Info("_/       _/        _/                      _/                   _/")
	log.Logger.Info("_/      _/_/_/    _/    _/_/      _/_/_/  _/  _/    _/    _/    _/")
	log.Logger.Info("_/     _/    _/  _/  _/    _/  _/        _/_/      _/    _/     _/")
	log.Logger.Info("_/    _/    _/  _/  _/    _/  _/        _/  _/    _/    _/      _/")
	log.Logger.Info("_/   _/_/_/    _/    _/_/      _/_/_/  _/    _/    _/_/_/       _/")
	log.Logger.Info("_/                                                    _/        _/")
	log.Logger.Info("_/                                               _/_/           _/")
	log.Logger.Info("_/                                                              _/")
	log.Logger.Info("_/                                                              _/")
	log.Logger.Infof("_/  Version: %-18s Build time: %-18s  _/", version, buildTime)
	log.Logger.Info("_/                                                              _/")
	log.Logger.Info("_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/")
}
