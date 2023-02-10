package recursor

import (
	"context"
	"github.com/stretchr/testify/assert"
	"strconv"
	"strings"
	"testing"

	"github.com/coredns/coredns/plugin/pkg/dnstest"
	"github.com/coredns/coredns/plugin/test"

	"github.com/miekg/dns"
)

const verbose = 0

func TestRecursor_should_work_with_default_system_resolver(t *testing.T) {
	rcu, _ := createRecursor(recursorCfg{
		Verbose: verbose,
		Zone:    "svc",
		Aliases: map[string]aliasCfg{
			"test1": {
				Ips:   []string{"127.0.0.1"},
				Hosts: []string{"localhost"},
			},
			"test2": {
				Ips: []string{"10.0.0.1", "10.0.0.2"},
			},
			"test3": {
				Hosts: []string{"localhost"},
			},
			"test4": {
				Hosts: []string{"localhost"},
				Ips:   []string{"10.0.0.1", "10.0.0.2"},
			},
			"test5": {
				Hosts: []string{"127.0.0.1"},
				Ips:   []string{"127.0.0.1", "127.0.0.1"},
			},
		},
	})
	testQuestion(t, rcu, []uint16{dns.TypeA}, "test1.svc", []string{"127.0.0.1"}, 0, false)
	testQuestion(t, rcu, []uint16{dns.TypeA}, "test2.svc", []string{"10.0.0.1", "10.0.0.2"}, 0, false)
	testQuestion(t, rcu, []uint16{dns.TypeA}, "test3.svc", []string{"127.0.0.1"}, 0, false)
	testQuestion(t, rcu, []uint16{dns.TypeA}, "test4.svc", []string{"127.0.0.1", "10.0.0.1", "10.0.0.2"}, 0, false)
	testQuestion(t, rcu, []uint16{dns.TypeA}, "test5.svc", []string{"127.0.0.1"}, 0, false)
}

func TestRecursor_should_work_with_custom_resolver(t *testing.T) {
	rcu, _ := createRecursor(recursorCfg{
		Verbose: verbose,
		Zone:    "svc",
		Resolvers: map[string]resolverCfg{
			"my_resolver": {
				Urls:      []string{"udp://8.8.8.8:53"},
				TimeoutMs: 15,
			},
		},
		Aliases: map[string]aliasCfg{
			"test": {
				Hosts:        []string{"example.org"},
				Ttl:          3,
				ResolverName: "my_resolver",
			},
		},
	})

	testQuestion(t, rcu, []uint16{dns.TypeA}, "test.svc", []string{"93.184.216.34"}, 3, false)
	testQuestion(t, rcu, []uint16{dns.TypeAAAA}, "test.svc", []string{"2606:2800:220:1:248:1893:25c8:1946"}, 3, false)
	testQuestion(t, rcu, []uint16{dns.TypeANY}, "test.svc", []string{"93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946"}, 3, false)
	testQuestion(t, rcu, []uint16{dns.TypeA, dns.TypeAAAA}, "test.svc", []string{"93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946"}, 3, false)
	testQuestion(t, rcu, []uint16{dns.TypeCNAME}, "test.svc", []string{}, 3, true)
}

func TestRecursor_should_work_as_repeater(t *testing.T) {
	rcu, _ := createRecursor(recursorCfg{
		Verbose: verbose,
		Zone:    "wikipedia.org",
		Resolvers: map[string]resolverCfg{
			"default": {
				Urls:      []string{"udp://8.8.8.8:53"},
				TimeoutMs: 15,
			},
		},
		Aliases: map[string]aliasCfg{
			"www": {
				Hosts: []string{"www.wikipedia.org"},
				Ttl:   10,
			},
			"*": {
				Hosts: []string{"www.wikipedia.org"},
				Ttl:   20,
			},
		},
	})

	testQuestion(t, rcu, []uint16{dns.TypeA}, "www.wikipedia.org", []string{"91.198.174.192"}, 10, false)
	testQuestion(t, rcu, []uint16{dns.TypeA}, "pl.wikipedia.org", []string{"91.198.174.192"}, 20, false)
	testQuestion(t, rcu, []uint16{dns.TypeA}, "domain-that-doesnt-exist.wikipedia.org", []string{}, 0, true)
	testQuestion(t, rcu, []uint16{dns.TypeA}, "domain.that.doesnt.exist.wikipedia.org", []string{}, 0, true)
}

func testQuestion(t *testing.T, rr recursor, qTypes []uint16, question string, expectedIps []string, expectedTtl int, expectedError bool) {
	rec, code, err := askQuestion(question, qTypes, rr)
	if err != nil {
		if expectedError {
			return
		} else {
			t.Errorf("unexpected error %v", err)
		}
	}
	log.Debugf("code: %d, err: %v, answer: %s", code, err, rec.Msg.Answer)
	response := ","
	for _, value := range rec.Msg.Answer {
		if strings.Index(value.String(), dns.CanonicalName(question)+"\t"+strconv.Itoa(expectedTtl)) != 0 {
			t.Errorf("failed to find '%s' in responce '%s'", question, value)
		}
		response = response + value.String() + ","
	}
	assert.Equal(t, len(expectedIps), len(rec.Msg.Answer), "expected ips len != answer len")
	for _, ip := range expectedIps {
		if !strings.Contains(response, "A\t"+ip+",") {
			t.Errorf("%s - failed to find '%s' in responce %s", question, ip, response)
			return
		}
	}

}

func askQuestion(question string, qTypes []uint16, rr recursor) (*dnstest.Recorder, int, error) {
	ctx := context.TODO()
	msg := new(dns.Msg)
	msg.Question = []dns.Question{}
	for _, qType := range qTypes {
		msg.Question = append(msg.Question, dns.Question{Name: question, Qtype: qType, Qclass: dns.ClassINET})
	}
	rec := dnstest.NewRecorder(&test.ResponseWriter{})
	code, err := rr.ServeDNS(ctx, rec, msg)
	return rec, code, err
}
