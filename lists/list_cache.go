package lists

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/privacyherodev/ph-blocky/log"
	"github.com/privacyherodev/ph-blocky/metrics"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/sirupsen/logrus"
)

const (
	defaultRefreshPeriod = 4 * time.Hour
)

// nolint:gochecknoglobals
var (
	timeout = 30 * time.Second
	etags   = map[string]Etag{}
)

type ListCacheType int

const (
	BLACKLIST ListCacheType = iota
	WHITELIST
)

func (l ListCacheType) String() string {
	names := [...]string{
		"blacklist",
		"whitelist"}

	return names[l]
}

type Matcher interface {
	// matches passed domain name against cached list entries
	Match(domain string, groupsToCheck []string) (found bool, group string)

	// returns current configuration and stats
	Configuration() []string
}

type ListCache struct {
	groupCaches map[string][]string
	lock        sync.RWMutex

	groupToLinks  map[string][]string
	refreshPeriod time.Duration

	counter *prometheus.GaugeVec
}
type Etag struct {
	Key  string
	Date string
	Body io.ReadCloser
}

func (b *ListCache) Configuration() (result []string) {
	if b.refreshPeriod > 0 {
		result = append(result, fmt.Sprintf("refresh period: %d minutes", b.refreshPeriod/time.Minute))
	} else {
		result = append(result, "refresh: disabled")
	}

	result = append(result, "group links:")
	for group, links := range b.groupToLinks {
		result = append(result, fmt.Sprintf("  %s:", group))
		for _, link := range links {
			result = append(result, fmt.Sprintf("   - %s", link))
		}
	}

	result = append(result, "group caches:")

	var total int

	for group, cache := range b.groupCaches {
		result = append(result, fmt.Sprintf("  %s: %d entries", group, len(cache)))
		total += len(cache)
	}

	result = append(result, fmt.Sprintf("  TOTAL: %d entries", total))

	return
}

func NewListCache(t ListCacheType, groupToLinks map[string][]string, refreshPeriod int) *ListCache {
	groupCaches := make(map[string][]string)

	p := time.Duration(refreshPeriod) * time.Minute
	if refreshPeriod == 0 {
		p = defaultRefreshPeriod
	}

	var counter *prometheus.GaugeVec

	if metrics.IsEnabled() {
		counter = prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: fmt.Sprintf("blocky_%s_cache", t),
				Help: "Number of entries in cache",
			}, []string{"group"},
		)

		metrics.RegisterMetric(counter)
	}

	b := &ListCache{
		groupToLinks:  groupToLinks,
		groupCaches:   groupCaches,
		refreshPeriod: p,
		counter:       counter,
	}
	b.refresh()

	go periodicUpdate(b)

	return b
}

// triggers periodical refresh (and download) of list entries
func periodicUpdate(cache *ListCache) {
	if cache.refreshPeriod > 0 {
		ticker := time.NewTicker(cache.refreshPeriod)
		defer ticker.Stop()

		for {
			<-ticker.C
			cache.refresh()
		}
	}
}

func logger() *logrus.Entry {
	return log.Logger.WithField("prefix", "list_cache")
}

// downloads and reads files with domain names and creates cache for them
func createCacheForGroup(links []string) []string {
	cache := make([]string, 0)

	keys := make(map[string]bool)

	var wg sync.WaitGroup

	c := make(chan []string, len(links))

	for _, link := range links {
		wg.Add(1)

		go processFile(link, c, &wg)
	}

	wg.Wait()

Loop:
	for {
		select {
		case res := <-c:
			if res == nil {
				return nil
			}
			for _, entry := range res {
				if _, value := keys[entry]; !value {
					keys[entry] = true
					cache = append(cache, entry)
				}
			}
		default:
			close(c)
			break Loop
		}
	}

	sort.Strings(cache)

	return cache
}

func (b *ListCache) Match(domain string, groupsToCheck []string) (found bool, group string) {
	b.lock.RLock()
	defer b.lock.RUnlock()

	for _, g := range groupsToCheck {
		if contains(domain, b.groupCaches[g]) {
			return true, g
		}
	}

	return false, ""
}

func contains(domain string, cache []string) bool {
	idx := sort.SearchStrings(cache, domain)
	if idx < len(cache) {
		return cache[idx] == strings.ToLower(domain)
	}

	return false
}

func (b *ListCache) refresh() {
	for group, links := range b.groupToLinks {
		cacheForGroup := createCacheForGroup(links)

		if cacheForGroup != nil {
			b.lock.Lock()
			b.groupCaches[group] = cacheForGroup
			b.lock.Unlock()
		} else {
			logger().Warn("Populating of group cache failed, leaving items from last successful download in cache")
		}

		if metrics.IsEnabled() {
			b.counter.WithLabelValues(group).Set(float64(len(b.groupCaches[group])))
		}

		logger().WithFields(logrus.Fields{
			"group":       group,
			"total_count": len(b.groupCaches[group]),
		}).Info("group import finished")
	}
}

func downloadFile(link string) (io.ReadCloser, error) {
	client := http.Client{
		Timeout: timeout,
	}

	var resp *http.Response

	var err error

	logger().WithField("link", link).Info("starting download")

	attempt := 1

	for attempt <= 3 {
		//nolint:bodyclose
		req, _ := buildRequest(link)
		if resp, err = client.Do(req); err == nil {
			if resp.StatusCode == http.StatusNotModified {
				return etags[link].Body, nil
			}
			if resp.StatusCode == http.StatusOK {
				updateEtagCache(link, resp)
				return resp.Body, nil
			}

			resp.Body.Close()

			return nil, fmt.Errorf("couldn't download url, got status code %d", resp.StatusCode)
		}

		if errNet, ok := err.(net.Error); ok && (errNet.Timeout() || errNet.Temporary()) {
			logger().WithField("link", link).WithField("attempt",
				attempt).Warnf("Temporary network error / Timeout occurred, retrying... %s", errNet)
			time.Sleep(time.Second)
			attempt++
		} else {
			return nil, err
		}
	}

	return nil, err
}

// Update the internal Etags cache.
func updateEtagCache(url string, resp *http.Response) (io.ReadCloser, error) {
	// body, err := ioutil.ReadAll(resp.Body)
	// if err != nil {
	// 	return nil, err
	// }

	// If etags headers are missing, ignore.
	key := resp.Header.Get("ETag")
	date := resp.Header.Get("Date")
	if key == "" || date == "" {
		return resp.Body, nil
	}
	etags[url] = Etag{key, date, resp.Body}
	return resp.Body, nil
}

// Build an HTTP request, including Etags data.
func buildRequest(url string) (*http.Request, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	if _, present := etags[url]; present {
		req.Header.Add("If-None-Match", etags[url].Key)
		req.Header.Add("If-Modified-Since", etags[url].Date)
	}
	return req, err
}

func readFile(file string) (io.ReadCloser, error) {
	logger().WithField("file", file).Info("starting processing of file")
	file = strings.TrimPrefix(file, "file://")

	return os.Open(file)
}

// downloads file (or reads local file) and writes file content as string array in the channel
func processFile(link string, ch chan<- []string, wg *sync.WaitGroup) {
	defer wg.Done()

	result := make([]string, 0)

	var r io.ReadCloser

	var err error

	if strings.HasPrefix(link, "http") {
		r, err = downloadFile(link)
	} else {
		r, err = readFile(link)
	}

	if err != nil {
		logger().Warn("error reading "+link+": ", err)

		if errNet, ok := err.(net.Error); ok && (errNet.Timeout() || errNet.Temporary()) {
			// put nil to indicate the temporary error
			ch <- nil
			return
		}
		ch <- []string{}

		return
	}
	defer r.Close()

	var count int

	scanner := bufio.NewScanner(r)

	for scanner.Scan() {
		line := scanner.Text()
		// skip comments
		if !strings.HasPrefix(line, "#") {
			result = append(result, processLine(line))

			count++
		}
	}

	if err := scanner.Err(); err != nil {
		logger().Warn("can't parse file: ", err)
	} else {
		logger().WithFields(logrus.Fields{
			"source": link,
			"count":  count,
		}).Info("file imported")
	}
	ch <- result
}

// return only first column (see hosts format)
func processLine(line string) string {
	parts := strings.Fields(line)
	if len(parts) > 0 {
		host := parts[len(parts)-1]

		ip := net.ParseIP(host)
		if ip != nil {
			return ip.String()
		}

		return strings.ToLower(host)
	}

	return ""
}
