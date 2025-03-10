package recursor

import (
	"context"
	"github.com/stretchr/testify/assert"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/coredns/coredns/plugin/pkg/dnstest"
	"github.com/coredns/coredns/plugin/test"

	"github.com/miekg/dns"
)

const verbose = 0

func TestRecursor_should_work_with_default_system_resolver(t *testing.T) {
	rcu, _ := createRecursor("svc", recursorCfg{
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
				Hosts:      []string{"localhost"},
				Ips:        []string{"10.0.0.1", "10.0.0.2"},
				ShuffleIps: true,
			},
			"test5": {
				Hosts: []string{"127.0.0.1"},
				Ips:   []string{"127.0.0.1", "127.0.0.1"},
			},
		},
	})
	testQuestion(t, rcu, []uint16{dns.TypeA}, "test1.svc", []string{"127.0.0.1"}, 0, false, "t1")
	testQuestion(t, rcu, []uint16{dns.TypeA}, "test2.svc", []string{"10.0.0.1", "10.0.0.2"}, 0, false, "t2")
	testQuestion(t, rcu, []uint16{dns.TypeA}, "test3.svc", []string{"127.0.0.1"}, 0, false, "t3")
	testQuestion(t, rcu, []uint16{dns.TypeA}, "test4.svc", []string{"127.0.0.1", "10.0.0.1", "10.0.0.2"}, 0, false, "t4")
	testQuestion(t, rcu, []uint16{dns.TypeA}, "test5.svc", []string{"127.0.0.1"}, 0, false, "t5")
}

func TestRecursor_should_work_with_custom_resolver(t *testing.T) {
	rcu, _ := createRecursor("svc", recursorCfg{
		Verbose: verbose,
		Resolvers: map[string]resolverCfg{
			"my_resolver": {
				Urls:      []string{"udp://8.8.8.8:53"},
				TimeoutMs: 15,
			},
		},
		Aliases: map[string]aliasCfg{
			"test": {
				Hosts:        []string{"one.one.one.one"},
				Ttl:          3,
				ResolverName: "my_resolver",
			},
		},
	})

	testQuestion(t, rcu, []uint16{dns.TypeA}, "test.svc", []string{"1.0.0.1", "1.1.1.1"}, 3, false, "t1")
	testQuestion(t, rcu, []uint16{dns.TypeAAAA}, "test.svc", []string{"2606:4700:4700::1001", "2606:4700:4700::1111"}, 3, false, "t2")
	testQuestion(t, rcu, []uint16{dns.TypeANY}, "test.svc", []string{"1.0.0.1", "1.1.1.1", "2606:4700:4700::1001", "2606:4700:4700::1111"}, 3, false, "t3")
	testQuestion(t, rcu, []uint16{dns.TypeA, dns.TypeAAAA}, "test.svc", []string{"1.0.0.1", "1.1.1.1", "2606:4700:4700::1001", "2606:4700:4700::1111"}, 3, false, "t4")
	testQuestion(t, rcu, []uint16{dns.TypeCNAME}, "test.svc", []string{}, 3, true, "t5")
}

func TestRecursor_should_work_as_repeater(t *testing.T) {
	rcu, _ := createRecursor("one.one.one", recursorCfg{
		Verbose: verbose,
		Resolvers: map[string]resolverCfg{
			"default": {
				Urls:      []string{"udp://8.8.8.8:53"},
				TimeoutMs: 15,
			},
		},
		Aliases: map[string]aliasCfg{
			"x": {
				Hosts: []string{"one.one.one.one"},
				Ttl:   10,
			},
			"*": {
				Ttl: 20,
			},
		},
	})

	testQuestion(t, rcu, []uint16{dns.TypeA}, "x.one.one.one", []string{"1.0.0.1", "1.1.1.1"}, 10, false, "t1")
	testQuestion(t, rcu, []uint16{dns.TypeA}, "one.one.one.one", []string{"1.0.0.1", "1.1.1.1"}, 20, false, "t2")
	testQuestion(t, rcu, []uint16{dns.TypeA}, "y.one.one.one", []string{}, 0, true, "t3")
	testQuestion(t, rcu, []uint16{dns.TypeA}, "z.y.one.one.one", []string{}, 0, true, "t4")
}

func TestRecursor_should_work_as_repeater_and_ips(t *testing.T) {
	rcu, _ := createRecursor("one.one.one", recursorCfg{
		Verbose: verbose,
		Resolvers: map[string]resolverCfg{
			"default": {
				Urls:      []string{"udp://8.8.8.8:53"},
				TimeoutMs: 15,
			},
		},
		Aliases: map[string]aliasCfg{
			"x": {
				Hosts: []string{"one.one.one.one"},
				Ttl:   10,
			},
			"*": {
				Ips:   []string{"2.2.2.2"},
				Hosts: []string{"*"},
				Ttl:   20,
			},
		},
	})

	testQuestion(t, rcu, []uint16{dns.TypeA}, "x.one.one.one", []string{"1.0.0.1", "1.1.1.1"}, 10, false, "t1")
	testQuestion(t, rcu, []uint16{dns.TypeA}, "one.one.one.one", []string{"2.2.2.2", "1.0.0.1", "1.1.1.1"}, 20, false, "t2")
	testQuestion(t, rcu, []uint16{dns.TypeA}, "y.one.one.one", []string{"2.2.2.2"}, 0, true, "t3")
	testQuestion(t, rcu, []uint16{dns.TypeA}, "z.y.one.one.one", []string{"2.2.2.2"}, 0, true, "t4")
}

func TestRecursor_should_not_work_as_repeater_with_ips(t *testing.T) {
	rcu, _ := createRecursor("one.one.one", recursorCfg{
		Verbose: verbose,
		Resolvers: map[string]resolverCfg{
			"default": {
				Urls:      []string{"udp://8.8.8.8:53"},
				TimeoutMs: 15,
			},
		},
		Aliases: map[string]aliasCfg{
			"x": {
				Ips: []string{"2.2.2.2"},
				Ttl: 10,
			},
			"*": {
				Ips: []string{"2.2.2.2"},
				Ttl: 20,
			},
		},
	})

	testQuestion(t, rcu, []uint16{dns.TypeA}, "x.one.one.one", []string{"2.2.2.2"}, 10, false, "t1")
	testQuestion(t, rcu, []uint16{dns.TypeA}, "one.one.one.one", []string{"2.2.2.2"}, 20, false, "t2")
}

func TestRecursor_should_shuffle_ips(t *testing.T) {
	rcu, _ := createRecursor("svc", recursorCfg{
		Verbose: verbose,
		Aliases: map[string]aliasCfg{
			"shuffle": {
				Ips:        []string{"10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5"},
				ShuffleIps: true,
			},
		},
	})

	ips1 := getIpsOrder(t, rcu, "shuffle.svc")
	ips2 := getIpsOrder(t, rcu, "shuffle.svc")
	i := 0
	for reflect.DeepEqual(ips1, ips2) && i < 5 {
		ips2 = getIpsOrder(t, rcu, "shuffle.svc")
		i++
	}
	assert.NotEqual(t, ips1, ips2, "IP Addresses have to be in different order in different queries")
}

func TestRecursor_should_shuffle_host_ips(t *testing.T) {
	rcu, _ := createRecursor("svc", recursorCfg{
		Verbose: verbose,
		Aliases: map[string]aliasCfg{
			"shuffle": {
				Hosts:      []string{"one.one.one.one"},
				ShuffleIps: true,
			},
		},
	})

	ips1 := getIpsOrder(t, rcu, "shuffle.svc")
	ips2 := getIpsOrder(t, rcu, "shuffle.svc")
	i := 0
	for reflect.DeepEqual(ips1, ips2) && i < 5 {
		ips2 = getIpsOrder(t, rcu, "shuffle.svc")
		i++
	}
	assert.NotEqual(t, ips1, ips2, "Host IP Addresses have to be in different order in different queries")
}

func getIpsOrder(t *testing.T, rr recursor, question string) []string {
	rec, _, err := askQuestion(question, []uint16{dns.TypeA}, rr)
	assert.NoError(t, err)
	var ips []string
	for _, answer := range rec.Msg.Answer {
		ips = append(ips, strings.Split(answer.String(), "\t")[4])
	}
	return ips
}

func testQuestion(t *testing.T, rr recursor, qTypes []uint16, question string, expectedIps []string, expectedTtl int, expectedError bool, description string) {
	rec, code, err := askQuestion(question, qTypes, rr)
	if err != nil {
		if expectedError {
			return
		} else {
			t.Errorf("(%s) unexpected error %v", description, err)
		}
	}
	log.Debugf("code: %d, err: %v, answer: %s", code, err, rec.Msg.Answer)
	response := ","
	for _, value := range rec.Msg.Answer {
		if strings.Index(value.String(), dns.CanonicalName(question)+"\t"+strconv.Itoa(expectedTtl)) != 0 {
			t.Errorf("(%s) failed to find '%s' in responce '%s'", description, question, value)
		}
		response = response + value.String() + ","
	}
	assert.Equal(t, len(expectedIps), len(rec.Msg.Answer), "("+description+") expected ips len != answer len")
	for _, ip := range expectedIps {
		if !strings.Contains(response, "A\t"+ip+",") {
			t.Errorf("(%s) %s - failed to find '%s' in responce %s", description, question, ip, response)
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
