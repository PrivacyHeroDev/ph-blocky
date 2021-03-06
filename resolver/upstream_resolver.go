package resolver

import (
	"bytes"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/privacyherodev/ph-blocky/config"
	"github.com/privacyherodev/ph-blocky/util"

	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

const (
	defaultTimeout = 2 * time.Second
	dnsContentType = "application/dns-message"
)

// UpstreamResolver sends request to external DNS server
type UpstreamResolver struct {
	NextResolver
	upstreamURL    string
	upstreamClient upstreamClient
}

type upstreamClient interface {
	callExternal(msg *dns.Msg, upstreamURL string) (response *dns.Msg, rtt time.Duration, err error)
}

type dnsUpstreamClient struct {
	client *dns.Client
}

type httpUpstreamClient struct {
	client *http.Client
}

func createUpstreamClient(cfg config.Upstream) (client upstreamClient, upstreamURL string) {
	if cfg.Net == "https" {
		return &httpUpstreamClient{
			client: &http.Client{
				Timeout: defaultTimeout,
			},
		}, fmt.Sprintf("%s://%s:%d%s", cfg.Net, cfg.Host, cfg.Port, cfg.Path)
	}

	return &dnsUpstreamClient{
		client: &dns.Client{
			Net:     cfg.Net,
			Timeout: defaultTimeout,
			UDPSize: 4096,
		},
	}, net.JoinHostPort(cfg.Host, strconv.Itoa(int(cfg.Port)))
}

func (r *httpUpstreamClient) callExternal(msg *dns.Msg,
	upstreamURL string) (*dns.Msg, time.Duration, error) {
	start := time.Now()

	rawDNSMessage, err := msg.Pack()

	if err != nil {
		return nil, 0, fmt.Errorf("can't pack message: %v", err)
	}

	httpResponse, err := r.client.Post(upstreamURL, dnsContentType, bytes.NewReader(rawDNSMessage))

	if err != nil {
		return nil, 0, fmt.Errorf("can't perform https request: %v", err)
	}
	defer httpResponse.Body.Close()

	if httpResponse.StatusCode != http.StatusOK {
		return nil, 0, fmt.Errorf("http return code should be %d, but received %d", http.StatusOK, httpResponse.StatusCode)
	}

	contentType := httpResponse.Header.Get("content-type")
	if contentType != dnsContentType {
		return nil, 0, fmt.Errorf("http return content type should be '%s', but was '%s'",
			dnsContentType, contentType)
	}

	body, err := ioutil.ReadAll(httpResponse.Body)
	if err != nil {
		return nil, 0, errors.New("can't read response body")
	}

	response := dns.Msg{}
	err = response.Unpack(body)

	if err != nil {
		return nil, 0, errors.New("can't unpack message")
	}

	return &response, time.Since(start), nil
}

func (r *dnsUpstreamClient) callExternal(msg *dns.Msg, upstreamURL string) (response *dns.Msg, rtt time.Duration, err error) {
	return r.client.Exchange(msg, upstreamURL)
}

func NewUpstreamResolver(upstream config.Upstream) Resolver {
	upstreamClient, upstreamURL := createUpstreamClient(upstream)

	return &UpstreamResolver{
		upstreamClient: upstreamClient,
		upstreamURL:    upstreamURL}
}

func (r *UpstreamResolver) Configuration() (result []string) {
	return
}

func (r UpstreamResolver) String() string {
	return fmt.Sprintf("upstream '%s'", r.upstreamURL)
}

func (r *UpstreamResolver) Resolve(request *Request) (response *Response, err error) {
	logger := withPrefix(request.Log, "upstream_resolver")

	attempt := 1

	var rtt time.Duration

	var resp *dns.Msg

	for attempt <= 3 {
		if resp, rtt, err = r.upstreamClient.callExternal(request.Req, r.upstreamURL); err == nil {
			logger.WithFields(logrus.Fields{
				"answer":           util.AnswerToString(resp.Answer),
				"return_code":      dns.RcodeToString[resp.Rcode],
				"upstream":         r.upstreamURL,
				"response_time_ms": rtt.Milliseconds(),
			}).Debugf("received response from upstream")

			return &Response{Res: resp, Reason: fmt.Sprintf("RESOLVED (%s)", r.upstreamURL)}, err
		}

		if errNet, ok := err.(net.Error); ok && (errNet.Timeout() || errNet.Temporary()) {
			logger.WithField("attempt", attempt).Debugf("Temporary network error / Timeout occurred, retrying...")
			attempt++
		} else {
			return nil, err
		}
	}

	return
}
