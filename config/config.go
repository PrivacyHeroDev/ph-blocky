package config

import (
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"reflect"
	"regexp"
	"strconv"
	"strings"

	"github.com/privacyherodev/ph-blocky/log"

	"gopkg.in/yaml.v2"
)

const validUpstream = `(?P<Net>[^\s:]*):/?/?(?P<Host>(?:\[[^\]]+\])|[^\s/:]+):?(?P<Port>[^\s/:]*)?(?P<Path>/[^\s]*)?`

// nolint:gochecknoglobals
var netDefaultPort = map[string]uint16{
	"udp":     53,
	"tcp":     53,
	"tcp-tls": 853,
	"https":   443,
}

// Upstream is the definition of external DNS server
type Upstream struct {
	Net  string
	Host string
	Port uint16
	Path string
}

func (u *Upstream) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var s string
	if err := unmarshal(&s); err != nil {
		return err
	}

	upstream, err := ParseUpstream(s)
	if err != nil {
		return err
	}

	*u = upstream

	return nil
}

// ParseUpstream creates new Upstream from passed string in format net:host[:port][/path]
func ParseUpstream(upstream string) (result Upstream, err error) {
	if strings.TrimSpace(upstream) == "" {
		return Upstream{}, nil
	}

	r := regexp.MustCompile(validUpstream)

	match := r.FindStringSubmatch(upstream)

	if len(match) == 0 {
		err = fmt.Errorf("wrong configuration, couldn't parse input '%s', please enter net:host[:port][/path]", upstream)
		return
	}

	n := match[1]
	if _, ok := netDefaultPort[n]; !ok {
		err = fmt.Errorf("wrong configuration, couldn't parse net '%s', please user one of %s",
			n, reflect.ValueOf(netDefaultPort).MapKeys())
		return
	}

	host := match[2]
	if len(host) == 0 {
		err = errors.New("wrong configuration, host wasn't specified")
		return
	}

	portPart := match[3]

	path := match[4]

	var port uint16

	if len(portPart) > 0 {
		var p int
		p, err = strconv.Atoi(strings.TrimSpace(portPart))

		if err != nil {
			err = fmt.Errorf("can't convert port to number %v", err)
			return
		}

		if p < 1 || p > 65535 {
			err = fmt.Errorf("invalid port %d", p)
			return
		}

		port = uint16(p)
	} else {
		port = netDefaultPort[n]
	}

	return Upstream{Net: n, Host: host, Port: port, Path: path}, nil
}

const (
	cfgDefaultPort           = 53
	cfgDefaultPrometheusPath = "/metrics"
)

// main configuration
type Config struct {
	Upstream     UpstreamConfig            `yaml:"upstream"`
	CustomDNS    CustomDNSConfig           `yaml:"customDNS"`
	Conditional  ConditionalUpstreamConfig `yaml:"conditional"`
	Blocking     BlockingConfig            `yaml:"blocking"`
	ClientLookup ClientLookupConfig        `yaml:"clientLookup"`
	Caching      CachingConfig             `yaml:"caching"`
	QueryLog     QueryLogConfig            `yaml:"queryLog"`
	Prometheus   PrometheusConfig          `yaml:"prometheus"`
	LogFormat    string                    `yaml:"logFormat"`
	LogLevel     string                    `yaml:"logLevel"`
	Port         uint16                    `yaml:"port"`
	HTTPPort     uint16                    `yaml:"httpPort"`
	HTTPSPort    uint16                    `yaml:"httpsPort"`
	CertFile     string                    `yaml:"httpsCertFile"`
	KeyFile      string                    `yaml:"httpsKeyFile"`
	BootstrapDNS Upstream                  `yaml:"bootstrapDns"`
	Cname        CnameConfig               `yaml:"cname"`
}

type Groups struct {
	Domains []string `yaml:"domains"`
	Cname   string   `yaml:"cname"`
}
type CnameConfig struct {
	Groups            map[string]Groups   `yaml:"groups"`
	ClientGroupsBlock map[string][]string `yaml:"clientGroupsBlock"`
}

// PrometheusConfig contains the config values for prometheus
type PrometheusConfig struct {
	Enable bool   `yaml:"enable"`
	Path   string `yaml:"path"`
}

type UpstreamConfig struct {
	ExternalResolvers []Upstream `yaml:"externalResolvers"`
}

type CustomDNSConfig struct {
	Mapping map[string]net.IP `yaml:"mapping"`
}

type ConditionalUpstreamConfig struct {
	Mapping map[string]Upstream `yaml:"mapping"`
}

type BlockingConfig struct {
	BlackLists        map[string][]string `yaml:"blackLists"`
	WhiteLists        map[string][]string `yaml:"whiteLists"`
	ClientGroupsBlock map[string][]string `yaml:"clientGroupsBlock"`
	Global            map[string]bool     `yaml:"global"`
	BlockType         string              `yaml:"blockType"`
	RefreshPeriod     int                 `yaml:"refreshPeriod"`
}

type ClientLookupConfig struct {
	ClientnameIPMapping map[string][]net.IP `yaml:"clients"`
	Upstream            Upstream            `yaml:"upstream"`
	SingleNameOrder     []uint              `yaml:"singleNameOrder"`
}

type CachingConfig struct {
	MinCachingTime int `yaml:"minTime"`
	MaxCachingTime int `yaml:"maxTime"`
}

type QueryLogConfig struct {
	Dir              string `yaml:"dir"`
	PerClient        bool   `yaml:"perClient"`
	LogRetentionDays uint64 `yaml:"logRetentionDays"`
}

func NewConfig(path string) Config {
	cfg := Config{}
	setDefaultValues(&cfg)

	data, err := ioutil.ReadFile(path)

	if err != nil {
		log.Logger.Fatal("Can't read config file: ", err)
	}

	err = yaml.UnmarshalStrict(data, &cfg)
	if err != nil {
		log.Logger.Fatal("wrong file structure: ", err)
	}
	if cfg.LogFormat != log.CfgLogFormatText && cfg.LogFormat != log.CfgLogFormatJSON {
		log.Logger.Fatal("LogFormat should be 'text' or 'json'")
	}

	return cfg
}

func setDefaultValues(cfg *Config) {
	cfg.Port = cfgDefaultPort
	cfg.LogLevel = "info"
	cfg.LogFormat = log.CfgLogFormatText
	cfg.Prometheus.Path = cfgDefaultPrometheusPath
}
