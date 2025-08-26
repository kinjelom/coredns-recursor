package recursor

import (
	"context"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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

func TestRecursor_should_shuffle_ips_via_ips_transform(t *testing.T) {
	rcu, _ := createRecursor("svc", recursorCfg{
		Verbose: verbose,
		Aliases: map[string]aliasCfg{
			"shuffle": {
				Ips:          []string{"10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5"},
				IpsTransform: []string{"shuffle"},
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

func TestRecursor_should_shuffle_host_ips_via_ips_transform(t *testing.T) {
	rcu, _ := createRecursor("svc", recursorCfg{
		Verbose: verbose,
		Aliases: map[string]aliasCfg{
			"shuffle": {
				Hosts:        []string{"one.one.one.one"},
				IpsTransform: []string{"shuffle"},
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

func TestRecursor_should_sort_asc_and_desc(t *testing.T) {
	rcu, _ := createRecursor("svc", recursorCfg{
		Verbose: verbose,
		Aliases: map[string]aliasCfg{
			"asc": {
				Ips:          []string{"10.0.0.3", "10.0.0.1", "10.0.0.2"},
				IpsTransform: []string{"sort_asc"},
			},
			"desc": {
				Ips:          []string{"10.0.0.3", "10.0.0.1", "10.0.0.2"},
				IpsTransform: []string{"sort_desc"},
			},
		},
	})

	gotAsc := getIpsOrder(t, rcu, "asc.svc")
	assert.Equal(t, []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}, gotAsc)

	gotDesc := getIpsOrder(t, rcu, "desc.svc")
	assert.Equal(t, []string{"10.0.0.3", "10.0.0.2", "10.0.0.1"}, gotDesc)
}

func TestRecursor_should_keep_first_and_last(t *testing.T) {
	rcu, _ := createRecursor("svc", recursorCfg{
		Verbose: verbose,
		Aliases: map[string]aliasCfg{
			"first": {
				Ips:          []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"},
				IpsTransform: []string{"first"},
			},
			"last": {
				Ips:          []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"},
				IpsTransform: []string{"last"},
			},
		},
	})

	gotFirst := getIpsOrder(t, rcu, "first.svc")
	assert.Equal(t, []string{"10.0.0.1"}, gotFirst)

	gotLast := getIpsOrder(t, rcu, "last.svc")
	assert.Equal(t, []string{"10.0.0.3"}, gotLast)
}

func TestRecursor_should_pick_random_one(t *testing.T) {
	rcu, _ := createRecursor("svc", recursorCfg{
		Verbose: verbose,
		Aliases: map[string]aliasCfg{
			"rnd": {
				Ips:          []string{"10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"},
				IpsTransform: []string{"random_one"},
			},
		},
	})

	got1 := getIpsOrder(t, rcu, "rnd.svc")
	got2 := getIpsOrder(t, rcu, "rnd.svc")

	// Always exactly one
	assert.Len(t, got1, 1)
	assert.Len(t, got2, 1)

	// With a few retries, expect different picks eventually
	i := 0
	for reflect.DeepEqual(got1, got2) && i < 10 {
		got2 = getIpsOrder(t, rcu, "rnd.svc")
		i++
	}
	assert.NotEqual(t, got1, got2, "random_one should eventually pick a different address")
}

func TestRecursor_should_prefer_ipv4_over_ipv6_and_vice_versa(t *testing.T) {
	// Example mix of v4 and v6 (string forms; your resolver should emit in a consistent, canonical slice order)
	rcu, _ := createRecursor("svc", recursorCfg{
		Verbose: verbose,
		Aliases: map[string]aliasCfg{
			"ipv4_first": {
				Ips:          []string{"2001:db8::1", "10.0.0.2", "2001:db8::2", "10.0.0.1"},
				IpsTransform: []string{"prefer_ipv4"},
			},
			"ipv6_first": {
				Ips:          []string{"10.0.0.2", "2001:db8::1", "10.0.0.1", "2001:db8::2"},
				IpsTransform: []string{"prefer_ipv6"},
			},
		},
	})

	gotV4 := getIpsOrder(t, rcu, "ipv4_first.svc", dns.TypeA, dns.TypeAAAA)
	// Expect all IPv4 first, preserving relative order within families
	assert.Equal(t, []string{"10.0.0.2", "10.0.0.1", "2001:db8::1", "2001:db8::2"}, gotV4)

	gotV6 := getIpsOrder(t, rcu, "ipv6_first.svc", dns.TypeA, dns.TypeAAAA)
	assert.Equal(t, []string{"2001:db8::1", "2001:db8::2", "10.0.0.2", "10.0.0.1"}, gotV6)
}

func TestRecursor_should_limit_n(t *testing.T) {
	rcu, _ := createRecursor("svc", recursorCfg{
		Verbose: verbose,
		Aliases: map[string]aliasCfg{
			"limit2": {
				Ips:          []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"},
				IpsTransform: []string{"limit_2"},
			},
			"limit0": {
				Ips:          []string{"10.0.0.1", "10.0.0.2"},
				IpsTransform: []string{"limit_0"},
			},
		},
	})

	got2 := getIpsOrder(t, rcu, "limit2.svc")
	assert.Equal(t, []string{"10.0.0.1", "10.0.0.2"}, got2)

	got0 := getIpsOrder(t, rcu, "limit0.svc")
	assert.Empty(t, got0)
}

func TestRecursor_should_apply_transformations_in_order(t *testing.T) {
	// Example: shuffle then first -> should pick a random single address, not always the same first.
	rcu, _ := createRecursor("svc", recursorCfg{
		Verbose: verbose,
		Aliases: map[string]aliasCfg{
			"pipeline": {
				Ips:          []string{"10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"},
				IpsTransform: []string{"shuffle", "first"},
			},
		},
	})

	got1 := getIpsOrder(t, rcu, "pipeline.svc")
	got2 := getIpsOrder(t, rcu, "pipeline.svc")

	assert.Len(t, got1, 1)
	assert.Len(t, got2, 1)

	i := 0
	for reflect.DeepEqual(got1, got2) && i < 10 {
		got2 = getIpsOrder(t, rcu, "pipeline.svc")
		i++
	}
	assert.NotEqual(t, got1, got2, "shuffle→first should eventually yield different single addresses")
}

func TestRecursor_should_ignore_unknown_transform_tokens(t *testing.T) {
	rcu, _ := createRecursor("svc", recursorCfg{
		Verbose: verbose,
		Aliases: map[string]aliasCfg{
			"unknown": {
				Ips:          []string{"10.0.0.3", "10.0.0.1", "10.0.0.2"},
				IpsTransform: []string{"__does_not_exist__", "sort_asc"},
			},
		},
	})

	got := getIpsOrder(t, rcu, "unknown.svc")
	assert.Equal(t, []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}, got)
}

func getIpsOrder(t *testing.T, rr recursor, question string, qTypes ...uint16) []string {
	t.Helper()
	if len(qTypes) == 0 {
		qTypes = []uint16{dns.TypeA, dns.TypeAAAA}
	}
	rec, _, err := askQuestion(question, qTypes, rr)
	require.NoError(t, err)

	var ips []string
	for _, ans := range rec.Msg.Answer {
		switch a := ans.(type) {
		case *dns.A:
			ips = append(ips, a.A.String())
		case *dns.AAAA:
			ips = append(ips, a.AAAA.String())
		}
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
