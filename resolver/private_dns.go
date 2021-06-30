package resolver

import (
	"errors"
	"net"
	"sort"
	"strings"

	"github.com/miekg/dns"
)

func contains(domain string, cache []string) bool {
	idx := sort.SearchStrings(cache, domain)
	if idx < len(cache) {
		return strings.EqualFold(cache[idx], domain)
	}

	return false
}

func buildGroupsMap(slice []string) map[string]bool {
	m := map[string]bool{}
	for _, entry := range slice {
		m[entry] = true
	}

	return m
}

func getMacFromEDNS0(msg *dns.Msg) (string, error) {

	opt := msg.IsEdns0()

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
	mac, err := getMacFromEDNS0(request.Req)
	if err != nil {
		// logging is too verbose
		// logger("groups_to_check").Error(err)
	}

	if len(mac) > 0 {
		groupsByName, found := cfg[mac]
		if found {
			*groups = append(*groups, groupsByName...)
		}
	}

	logger("groups_to_check").Debugf("macstr: %s, groups: %v", mac, groups)
}
