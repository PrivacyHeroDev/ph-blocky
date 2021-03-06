package util

import (
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/privacyherodev/ph-blocky/log"

	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

// AnswerToString creates a user-friendly representation of an answer
func AnswerToString(answer []dns.RR) string {
	answers := make([]string, len(answer))

	for i, record := range answer {
		switch v := record.(type) {
		case *dns.A:
			answers[i] = fmt.Sprintf("A (%s)", v.A)
		case *dns.AAAA:
			answers[i] = fmt.Sprintf("AAAA (%s)", v.AAAA)
		case *dns.CNAME:
			answers[i] = fmt.Sprintf("CNAME (%s)", v.Target)
		case *dns.PTR:
			answers[i] = fmt.Sprintf("PTR (%s)", v.Ptr)
		default:
			answers[i] = fmt.Sprint(record.String())
		}
	}

	return strings.Join(answers, ", ")
}

// QuestionToString creates a user-friendly representation of a question
func QuestionToString(questions []dns.Question) string {
	result := make([]string, len(questions))
	for i, question := range questions {
		result[i] = fmt.Sprintf("%s (%s)", dns.TypeToString[question.Qtype], question.Name)
	}

	return strings.Join(result, ", ")
}

// CreateAnswerFromQuestion creates new answer from a question
func CreateAnswerFromQuestion(question dns.Question, ip net.IP, remainingTTL uint32) (dns.RR, error) {
	h := dns.RR_Header{Name: question.Name, Rrtype: question.Qtype, Class: dns.ClassINET, Ttl: remainingTTL}

	switch question.Qtype {
	case dns.TypeA:
		a := new(dns.A)
		a.A = ip
		a.Hdr = h

		return a, nil
	case dns.TypeAAAA:
		a := new(dns.AAAA)
		a.AAAA = ip
		a.Hdr = h

		return a, nil
	}

	log.Logger.Errorf("Using fallback for unsupported query type %s", dns.TypeToString[question.Qtype])

	return dns.NewRR(fmt.Sprintf("%s %d %s %s %s",
		question.Name, remainingTTL, "IN", dns.TypeToString[question.Qtype], ip))
}

// ExtractDomain returns domain string from the question
func ExtractDomain(question dns.Question) string {
	return ExtractDomainOnly(question.Name)
}

// ExtractDomainOnly extracts domain from the DNS query
func ExtractDomainOnly(in string) string {
	return strings.TrimSuffix(strings.ToLower(in), ".")
}

// NewMsgWithQuestion creates new DNS message with question
func NewMsgWithQuestion(question string, mType uint16) *dns.Msg {
	msg := new(dns.Msg)
	msg.SetQuestion(question, mType)

	return msg
}

// NewMsgWithAnswer creates new DNS message with answer
func NewMsgWithAnswer(domain string, ttl uint, dnsType uint16, address string) (*dns.Msg, error) {
	rr, err := dns.NewRR(fmt.Sprintf("%s\t%d\tIN\t%s\t%s", domain, ttl, dns.TypeToString[dnsType], address))
	if err != nil {
		return nil, err
	}

	msg := new(dns.Msg)
	msg.Answer = []dns.RR{rr}

	return msg, nil
}

type kv struct {
	key   string
	value int
}

// IterateValueSorted iterates over maps value in a sorted order and applies the passed function
func IterateValueSorted(in map[string]int, fn func(string, int)) {
	ss := make([]kv, 0)

	for k, v := range in {
		ss = append(ss, kv{k, v})
	}

	sort.Slice(ss, func(i, j int) bool {
		return ss[i].value > ss[j].value || (ss[i].value == ss[j].value && ss[i].key > ss[j].key)
	})

	for _, kv := range ss {
		fn(kv.key, kv.value)
	}
}

// LogOnError logs the message only if error is not nil
func LogOnError(message string, err error) {
	if err != nil {
		log.Logger.Error(message, err)
	}
}

// LogOnErrorWithEntry logs the message only if error is not nil
func LogOnErrorWithEntry(logEntry *logrus.Entry, message string, err error) {
	if err != nil {
		logEntry.Error(message, err)
	}
}

// FatalOnError logs the message only if error is not nil and exits the program execution
func FatalOnError(message string, err error) {
	if err != nil {
		log.Logger.Fatal(message, err)
	}
}

// Chunks splits the string in multiple chunks
func Chunks(s string, chunkSize int) []string {
	if chunkSize >= len(s) {
		return []string{s}
	}

	var chunks []string

	chunk := make([]rune, chunkSize)
	ln := 0

	for _, r := range s {
		chunk[ln] = r
		ln++

		if ln == chunkSize {
			chunks = append(chunks, string(chunk))
			ln = 0
		}
	}

	if ln > 0 {
		chunks = append(chunks, string(chunk[:ln]))
	}

	return chunks
}
