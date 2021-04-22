package resolver

import (
	"net"
	"testing"
	"time"

	"github.com/go-chi/chi"
	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
	"github.com/stgnet/blocky/config"
	"github.com/stgnet/blocky/helpertest"
	"github.com/stretchr/testify/assert"
)

// Global State	| Device State	| Result for Device
// -----------------------------------------------
// OFF (False)	| ON (True)		| OFF |
// OFF (False)	| OFF (False)	| OFF |
// ON (True)	| ON (True)		| ON  |
// ON (True)	| OFF (False)	| OFF |
func TestBlockingResolver_getPort(t *testing.T) {
	defaultGroupFile := helpertest.TempFile(
		`blocked3.com
123.145.123.145
2001:db8:85a3:08d3::370:7344
badcnamedomain.com`)
	tests := []struct {
		name          string
		blockingCfg   config.BlockingConfig
		groupsToCheck []string
		req           *Request
		want          []string
	}{
		{
			name: "client malware true and global adblock true",
			blockingCfg: config.BlockingConfig{
				BlackLists: map[string][]string{
					"adblock": {defaultGroupFile.Name()},
				},
				ClientGroupsBlock: map[string][]string{
					"48:52:4a": {"malware"},
				},
				Global: map[string]bool{"adblock": true},
			},
			req:  newRequestWithClientAndEDNS0("blocked3.com.", dns.TypeA, "1.2.1.2", []byte{72, 82, 74}, "unknown"),
			want: nil,
		},
		{
			name: "global and client adblock true",
			blockingCfg: config.BlockingConfig{
				BlackLists: map[string][]string{
					"adblock": {defaultGroupFile.Name()},
				},
				ClientGroupsBlock: map[string][]string{
					"48:52:4a": {"adblock"},
				},
				Global: map[string]bool{"adblock": true},
			},
			req:  newRequestWithClientAndEDNS0("example.com.", dns.TypeA, "1.2.1.2", []byte{72, 82, 74}, "unknown"),
			want: []string{"adblock"},
		},
		{
			name: "global and client adblock adult true",
			blockingCfg: config.BlockingConfig{
				BlackLists: map[string][]string{
					"adblock": {defaultGroupFile.Name()},
					"adult":   {defaultGroupFile.Name()},
				},
				ClientGroupsBlock: map[string][]string{
					"48:52:4a": {"adult"},
				},
				Global: map[string]bool{"adblock": true, "adult": true},
			},
			req:  newRequestWithClientAndEDNS0("example.com.", dns.TypeA, "1.2.1.2", []byte{72, 82, 74}, "unknown"),
			want: []string{"adult"},
		},
		{
			name: "global and client adblock true, adult client",
			blockingCfg: config.BlockingConfig{
				BlackLists: map[string][]string{
					"adblock": {defaultGroupFile.Name()},
					"adult":   {defaultGroupFile.Name()},
				},
				ClientGroupsBlock: map[string][]string{
					"48:52:4a": {"adblock", "adult"},
				},
				Global: map[string]bool{"adblock": true, "adult": true},
			},
			req:  newRequestWithClientAndEDNS0("example.com.", dns.TypeA, "1.2.1.2", []byte{72, 82, 74}, "unknown"),
			want: []string{"adblock", "adult"},
		},
		{
			name: "global adblock false, client true. Client adult",
			blockingCfg: config.BlockingConfig{
				BlackLists: map[string][]string{
					"adblock": {defaultGroupFile.Name()},
				},
				ClientGroupsBlock: map[string][]string{
					"48:52:4a": {"adblock", "adult"},
				},
				Global: map[string]bool{"adblock": false},
			},
			req:  newRequestWithClientAndEDNS0("example.com.", dns.TypeA, "1.2.1.2", []byte{72, 82, 74}, "unknown"),
			want: nil,
		},
		{
			name: "all enabled",
			blockingCfg: config.BlockingConfig{
				BlackLists: map[string][]string{
					"adblock": {defaultGroupFile.Name()},
				},
				ClientGroupsBlock: map[string][]string{
					"48:52:4a": {"adblock", "adult", "malware"},
				},
				Global: map[string]bool{"adblock": true, "adult": true, "malware": true},
			},
			req:  newRequestWithClientAndEDNS0("example.com.", dns.TypeA, "1.2.1.2", []byte{72, 82, 74}, "unknown"),
			want: []string{"adblock", "adult", "malware"},
		},
		{
			name: "no client, global adblock true",
			blockingCfg: config.BlockingConfig{
				BlackLists: map[string][]string{
					"adblock": {defaultGroupFile.Name()},
				},
				ClientGroupsBlock: map[string][]string{
					"48:52:4a": {},
				},
				Global: map[string]bool{"adblock": true},
			},
			req:  newRequestWithClientAndEDNS0("example.com.", dns.TypeA, "1.2.1.2", []byte{72, 82, 74}, "unknown"),
			want: []string{},
		},
		{
			name: "everything on",
			blockingCfg: config.BlockingConfig{
				BlackLists: map[string][]string{
					"adblock": {defaultGroupFile.Name()},
				},
				ClientGroupsBlock: map[string][]string{
					"48:52:4a": {"adblock", "adult", "malware"},
				},
				Global: map[string]bool{"adblock": true, "adult": true, "malware": true},
			},
			req:  newRequestWithClientAndEDNS0("example.com.", dns.TypeA, "1.2.1.2", []byte{72, 82, 74}, "unknown"),
			want: []string{"adblock", "adult", "malware"},
		},
		{
			name: "global malware off",
			blockingCfg: config.BlockingConfig{
				BlackLists: map[string][]string{
					"adblock": {defaultGroupFile.Name()},
				},
				ClientGroupsBlock: map[string][]string{
					"48:52:4a": {"adblock", "adult", "malware"},
				},
				Global: map[string]bool{"adblock": true, "adult": true, "malware": false},
			},
			req:  newRequestWithClientAndEDNS0("example.com.", dns.TypeA, "1.2.1.2", []byte{72, 82, 74}, "unknown"),
			want: []string{"adblock", "adult"},
		},
		{
			name: "global malware off, missing client",
			blockingCfg: config.BlockingConfig{
				BlackLists: map[string][]string{
					"adblock": {defaultGroupFile.Name()},
				},
				ClientGroupsBlock: map[string][]string{
					"48:52:4a": {"adblock", "adult"},
				},
				Global: map[string]bool{"adblock": true, "adult": true, "malware": false},
			},
			req:  newRequestWithClientAndEDNS0("example.com.", dns.TypeA, "1.2.1.2", []byte{72, 82, 74}, "unknown"),
			want: []string{"adblock", "adult"},
		},
		{
			name: "multiple client to check",
			blockingCfg: config.BlockingConfig{
				BlackLists: map[string][]string{
					"adblock": {defaultGroupFile.Name()},
				},
				ClientGroupsBlock: map[string][]string{
					"48:52:4a": {"adblock", "adult"},
					"48:52:43": {"adult"},
				},
				Global: map[string]bool{"adblock": true, "adult": true, "malware": false},
			},
			req:  newRequestWithClientAndEDNS0("example.com.", dns.TypeA, "1.2.1.2", []byte{72, 82, 74}, "unknown"),
			want: []string{"adblock", "adult"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := NewBlockingResolver(chi.NewRouter(), tt.blockingCfg).(*BlockingResolver)
			if got := r.groupsToCheckForClient(tt.req); !assert.ElementsMatch(t, got, tt.want) {
				t.Errorf("BlockingResolver.groupsToCheckForClient() = %v, want %v", got, tt.want)
			}
		})
	}
}
func newRequestWithClientAndEDNS0(question string, rType uint16, ip string, mac []byte, clientNames ...string) *Request {
	return &Request{
		ClientIP:    net.ParseIP(ip),
		ClientNames: clientNames,
		Req:         newMsgWithEDNS0(question, rType, mac),
		Log:         logrus.NewEntry(logrus.New()),
		RequestTS:   time.Time{},
	}
}

func newMsgWithEDNS0(question string, mType uint16, mac []byte) *dns.Msg {
	msg := new(dns.Msg)
	msg.SetQuestion(question, mType)
	o := new(dns.OPT)
	o.Hdr.Name = "."
	o.Hdr.Rrtype = dns.TypeOPT
	e := new(dns.EDNS0_LOCAL)
	e.Code = dns.EDNS0LOCALSTART
	e.Data = mac
	o.Option = append(o.Option, e)
	msg.Extra = append(msg.Extra, o)

	return msg
}
