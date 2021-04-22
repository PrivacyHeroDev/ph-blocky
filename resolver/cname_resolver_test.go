package resolver

import (
	"testing"

	"github.com/miekg/dns"
	"github.com/privacyherodev/ph-blocky/config"
	. "github.com/privacyherodev/ph-blocky/helpertest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

var (
	sut  ChainedResolver
	m    *resolverMock
	err  error
	resp *Response
)

func TestCnameResolver_Resolve(t *testing.T) {
	sut = NewCnameResolver(config.CnameConfig{
		Groups: map[string]config.Groups{
			"youtube": {
				Domains: []string{"youtube.com", "other.youtube.com"},
				Cname:   "restrict.youtube.com.",
			},
		},
		ClientGroupsBlock: map[string][]string{
			"1.2.1.2": {"youtube"},
		},
	})
	m = &resolverMock{}
	m.On("Resolve", mock.Anything).Return(&Response{Res: new(dns.Msg)}, nil)
	sut.Next(m)

	// Client in block, querying restricted domain. Respond with domain restriction
	resp, err = sut.Resolve(newRequestWithClient("other.youtube.com.", dns.TypeA, "1.2.1.2", "unknown"))
	assert.Nil(t, err)
	b := BeDNSRecord("other.youtube.com.", dns.TypeA, 3600, "restrict.youtube.com.")
	ok, err := b.Match(resp.Res.Answer)
	assert.Nil(t, err)
	assert.True(t, ok)
	assert.Equal(t, CUSTOMDNS, resp.RType)

	// Client in block, querying alternate restricted domain. Respond with domain restriction
	resp, err = sut.Resolve(newRequestWithClient("youtube.com.", dns.TypeA, "1.2.1.2", "unknown"))
	assert.Nil(t, err)
	b = BeDNSRecord("youtube.com.", dns.TypeA, 3600, "restrict.youtube.com.")
	ok, err = b.Match(resp.Res.Answer)
	assert.Nil(t, err)
	assert.True(t, ok)
	assert.Equal(t, CUSTOMDNS, resp.RType)

	// Client in block. Querying restricted domain. Respond without restriction
	resp, err = sut.Resolve(newRequestWithClient("starcraft.com.", dns.TypeA, "1.2.1.2", "unknown"))
	assert.Nil(t, err)
	assert.Nil(t, resp.Res.Answer)
	// was delegated to the next resolver

	// Client not in block. Querying restricted domain. Respond without restriction
	resp, err = sut.Resolve(newRequestWithClient("youtube.com.", dns.TypeA, "1.2.1.3", "unknown"))
	assert.Nil(t, err)
	assert.Nil(t, resp.Res.Answer)
	// was delegated to the next resolver

}
