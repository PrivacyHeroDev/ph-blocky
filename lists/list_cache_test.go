package lists

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-chi/chi"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/privacyherodev/ph-blocky/config"
	. "github.com/privacyherodev/ph-blocky/helpertest"
	"github.com/privacyherodev/ph-blocky/metrics"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

var _ = Describe("ListCache", func() {
	var (
		emptyFile, file1, file2, file3 *os.File
		server1, server2, server3      *httptest.Server
	)

	BeforeEach(func() {
		emptyFile = TempFile("#empty file\n\n")
		server1 = TestServer("blocked1.com\nblocked1a.com\n192.168.178.55")
		server2 = TestServer("blocked2.com")
		server3 = TestServer("blocked3.com\nblocked1a.com")

		file1 = TempFile("blocked1.com\nblocked1a.com")
		file2 = TempFile("blocked2.com")
		file3 = TempFile("blocked3.com\nblocked1a.com")
		timeout = 30 * time.Second

	})
	AfterEach(func() {
		_ = os.Remove(emptyFile.Name())
		_ = os.Remove(file1.Name())
		_ = os.Remove(file2.Name())
		_ = os.Remove(file3.Name())
		server1.Close()
		server2.Close()
		server3.Close()
	})

	Describe("List cache and matching", func() {
		When("List is empty", func() {
			It("should not match anything", func() {
				lists := map[string][]string{
					"gr1": {emptyFile.Name()},
				}
				sut := NewListCache(BLACKLIST, lists, 0)

				found, group := sut.Match("google.com", []string{"gr1"})
				Expect(found).Should(BeFalse())
				Expect(group).Should(BeEmpty())
			})
		})
		When("If timeout occurs", func() {
			var attempt uint64 = 1
			It("Should perform a retry", func() {
				// should produce a timeout on first attempt
				s := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
					a := atomic.LoadUint64(&attempt)
					if a == 1 {
						time.Sleep(200 * time.Millisecond)
					} else {
						_, err := rw.Write([]byte("blocked1.com"))
						Expect(err).Should(Succeed())
					}
					atomic.AddUint64(&attempt, 1)
				}))
				defer s.Close()
				lists := map[string][]string{
					"gr1": {s.URL},
				}

				timeout = 100 * time.Millisecond
				sut := NewListCache(BLACKLIST, lists, 0)
				time.Sleep(time.Second)
				found, group := sut.Match("blocked1.com", []string{"gr1"})
				Expect(found).Should(BeTrue())
				Expect(group).Should(Equal("gr1"))
			})
		})
		When("a temporary error occurs on download", func() {
			var attempt uint64 = 1
			It("should not delete existing elements from group cache", func() {
				// should produce a timeout on second attempt
				s := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
					a := atomic.LoadUint64(&attempt)
					if a != 1 {
						time.Sleep(200 * time.Millisecond)
					} else {
						_, err := rw.Write([]byte("blocked1.com"))
						Expect(err).Should(Succeed())
					}
					atomic.AddUint64(&attempt, 1)
				}))
				defer s.Close()
				lists := map[string][]string{
					"gr1": {s.URL, emptyFile.Name()},
				}

				timeout = 100 * time.Millisecond
				sut := NewListCache(BLACKLIST, lists, 0)
				time.Sleep(time.Second)
				By("Lists loaded without timeout", func() {
					found, group := sut.Match("blocked1.com", []string{"gr1"})
					Expect(found).Should(BeTrue())
					Expect(group).Should(Equal("gr1"))
				})

				sut.refresh()

				By("List couldn't be loaded due to timeout", func() {
					found, group := sut.Match("blocked1.com", []string{"gr1"})
					Expect(found).Should(BeTrue())
					Expect(group).Should(Equal("gr1"))
				})
			})
		})
		When("error occurs on download", func() {
			var attempt uint64 = 1
			It("should delete existing elements from group cache", func() {
				// should produce a 404 error on second attempt
				s := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
					a := atomic.LoadUint64(&attempt)
					if a != 1 {
						rw.WriteHeader(http.StatusNotFound)
					} else {
						_, err := rw.Write([]byte("blocked1.com"))
						Expect(err).Should(Succeed())
					}
					atomic.AddUint64(&attempt, 1)
				}))
				defer s.Close()
				lists := map[string][]string{
					"gr1": {s.URL},
				}

				sut := NewListCache(BLACKLIST, lists, 0)
				time.Sleep(time.Second)
				By("Lists loaded without error", func() {
					found, group := sut.Match("blocked1.com", []string{"gr1"})
					Expect(found).Should(BeTrue())
					Expect(group).Should(Equal("gr1"))
				})

				sut.refresh()
				time.Sleep(time.Second)

				By("List couldn't be loaded due to 404 error", func() {
					found, _ := sut.Match("blocked1.com", []string{"gr1"})
					Expect(found).Should(BeFalse())
				})
			})
		})
		When("Configuration has 3 external urls", func() {
			It("should download the list and match against", func() {
				lists := map[string][]string{
					"gr1": {server1.URL, server2.URL},
					"gr2": {server3.URL},
				}

				sut := NewListCache(BLACKLIST, lists, 0)

				found, group := sut.Match("blocked1.com", []string{"gr1", "gr2"})
				Expect(found).Should(BeTrue())
				Expect(group).Should(Equal("gr1"))

				found, group = sut.Match("blocked1a.com", []string{"gr1", "gr2"})
				Expect(found).Should(BeTrue())
				Expect(group).Should(Equal("gr1"))

				found, group = sut.Match("blocked1a.com", []string{"gr2"})
				Expect(found).Should(BeTrue())
				Expect(group).Should(Equal("gr2"))
			})
			It("should not match if no groups are passed", func() {
				lists := map[string][]string{
					"gr1":          {server1.URL, server2.URL},
					"gr2":          {server3.URL},
					"withDeadLink": {"http://wrong.host.name"},
				}

				sut := NewListCache(BLACKLIST, lists, 0)

				found, group := sut.Match("blocked1.com", []string{})
				Expect(found).Should(BeFalse())
				Expect(group).Should(BeEmpty())
			})
		})
		When("metrics are enabled", func() {
			It("should count elements in downloaded lists", func() {
				metrics.Start(chi.NewRouter(), config.PrometheusConfig{Enable: true, Path: "/metrics"})
				lists := map[string][]string{
					"gr1": {server1.URL},
				}

				sut := NewListCache(BLACKLIST, lists, 0)

				found, group := sut.Match("blocked1.com", []string{})
				Expect(found).Should(BeFalse())
				Expect(group).Should(BeEmpty())
				Expect(testutil.ToFloat64(sut.counter)).Should(Equal(float64(3)))
			})
		})
		When("multiple groups are passed", func() {
			It("should match", func() {
				lists := map[string][]string{
					"gr1": {file1.Name(), file2.Name()},
					"gr2": {"file://" + file3.Name()},
				}

				sut := NewListCache(BLACKLIST, lists, 0)

				found, group := sut.Match("blocked1.com", []string{"gr1", "gr2"})
				Expect(found).Should(BeTrue())
				Expect(group).Should(Equal("gr1"))

				found, group = sut.Match("blocked1a.com", []string{"gr1", "gr2"})
				Expect(found).Should(BeTrue())
				Expect(group).Should(Equal("gr1"))

				found, group = sut.Match("blocked1a.com", []string{"gr2"})
				Expect(found).Should(BeTrue())
				Expect(group).Should(Equal("gr2"))
			})
		})
	})
	Describe("Configuration", func() {
		When("refresh is enabled", func() {
			It("should print list configuration", func() {
				lists := map[string][]string{
					"gr1": {server1.URL, server2.URL},
				}

				sut := NewListCache(BLACKLIST, lists, 0)

				c := sut.Configuration()
				Expect(c).Should(HaveLen(8))
			})
		})
		When("refresh is disabled", func() {
			It("should print 'refresh disabled'", func() {
				lists := map[string][]string{
					"gr1": {"file1", "file2"},
				}

				sut := NewListCache(BLACKLIST, lists, -1)

				c := sut.Configuration()
				Expect(c).Should(ContainElement("refresh: disabled"))
			})
		})
	})
})

func quick(c *gin.Context) {
	key := "black"
	e := fmt.Sprintf("%s", key)
	c.Header("Etag", e)
	c.Header("Cache-Control", "max-age=2592000") // 30 days
	c.Status(http.StatusOK)
}

func TestListCache_refresh(t *testing.T) {
	gin.SetMode(gin.TestMode)
	// api.GetRouterQuicgin.SetMode(gin.TestMode)
	r := gin.Default()
	r.GET("/quick", quick)

	// c, _ := gin.CreateTestContext(w)
	// ?mac=a1&sv=123

	// Perform the request
	go r.Run(":8181")

	type fields struct {
		groupCaches   map[string]map[string][]string
		lock          sync.RWMutex
		groupToLinks  map[string][]string
		refreshPeriod time.Duration
		counter       *prometheus.GaugeVec
	}
	tests := []struct {
		name   string
		fields fields
	}{
		{
			name: "test1",
			fields: fields{
				groupToLinks: map[string][]string{
					"testGroup": {"http://localhost:8181/quick"},
				},
				groupCaches: map[string]map[string][]string{},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := &ListCache{
				groupCaches:   tt.fields.groupCaches,
				lock:          tt.fields.lock,
				groupToLinks:  tt.fields.groupToLinks,
				refreshPeriod: tt.fields.refreshPeriod,
				counter:       tt.fields.counter,
			}
			b.refresh()
		})
	}
}
