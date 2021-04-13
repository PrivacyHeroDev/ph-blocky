package resolver

import (
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
	"github.com/stgnet/blocky/util"
)

func callExternal(msg *dns.Msg, upstreamURL string) (*dns.Msg, time.Duration, error) {

	dnsClient := &dnsUpstreamClient{
		client: &dns.Client{
			Net:     "udp",
			Timeout: defaultTimeout,
			UDPSize: 4096,
		},
	}
	return dnsClient.callExternal(msg, upstreamURL)

}

func resolvePrivate(request *Request, port int) (*dns.Msg, error) {
	logger := withPrefix(request.Log, "private_resolver")
	host := "10.255.0.1"
	url := net.JoinHostPort(host, strconv.Itoa(port))

	var rtt time.Duration
	var resp *dns.Msg
	var err error
	if resp, rtt, err = callExternal(request.Req, url); err == nil {
		logger.WithFields(logrus.Fields{
			"answer":           util.AnswerToString(resp.Answer),
			"return_code":      dns.RcodeToString[resp.Rcode],
			"upstream":         url,
			"response_time_ms": rtt.Milliseconds(),
		}).Debugf("received response from private dns")

		return resp, nil
	}

	return nil, fmt.Errorf("could not resolve using private dns %w", err)
}

func contains(domain string, cache []string) bool {
	idx := sort.SearchStrings(cache, domain)
	if idx < len(cache) {
		return cache[idx] == strings.ToLower(domain)
	}

	return false
}

func (r *BlockingResolver) getPort(groupsToCheck []string) int {
	toggles := map[string]bool{"adblock": false, "malware": false, "adult": false}
	uniqueGroups := buildGroupsMap(groupsToCheck)
	for k, v := range r.cfg.Global {
		toggles[k] = v
	}

	logger("private_resolver").Debugf("global: %v, toggles: %v, groupsToCheck: %v ***!", r.cfg.Global, toggles, uniqueGroups)
	// Global State	| Device State	| Result for Device
	// -----------------------------------------------
	// OFF (False)	| ON (True)		| OFF |
	// OFF (False)	| OFF (False)	| OFF |
	// ON (True)	| ON (True)		| ON  |
	// ON (True)	| OFF (False)	| OFF |

	for k, v := range toggles {
		v2, _ := uniqueGroups[k]

		if v && v2 {
			toggles[k] = true
			continue
		}
		toggles[k] = false
		continue

	}

	logger("private_resolver").Debugf("final toggles %v", toggles)
	// calculate result
	values := map[string]int{"adblock": 1, "malware": 2, "adult": 4}
	port := 1024
	for k, v := range toggles {
		if v {
			if i, ok := values[k]; ok {
				port += i
			}
		}
	}
	if port > 1031 {
		logger("private_resolver").Error("port returned a value greater than the maximum of 1031. Setting to 1024", port)
		port = 1024
	}

	return port

}
func buildGroupsMap(slice []string) map[string]bool {
	m := map[string]bool{}
	for _, entry := range slice {
		m[entry] = true
	}

	return m
}

func getMacFromEDNS0(request *Request) (string, error) {

	opt := request.Req.IsEdns0()

	if opt != nil {
		if len(opt.Option) == 0 {
			return "", errors.New("opt.option of len 0")
		}
		for _, v := range opt.Option {
			switch m := v.(type) {
			case *dns.EDNS0_LOCAL:
				return net.HardwareAddr(m.Data).String(), nil
			}
		}

		return "", errors.New("no EDNS0_LOCAL found")

	}

	return "", errors.New("opt nil")
}

func getEdnsData(request *Request, cfg map[string][]string, groups *[]string) {
	mac, err := getMacFromEDNS0(request)
	if err != nil {
		logger("groups_to_check").Error(err)
	}

	if len(mac) > 0 {
		groupsByName, found := cfg[mac]
		if found {
			*groups = append(*groups, groupsByName...)
		}
	}

	logger("groups_to_check").Debugf("macstr: %s, groups: %v", mac, groups)
}
