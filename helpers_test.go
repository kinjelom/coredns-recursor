package recursor

import (
	"math/rand"
	"net"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

func ips(ss ...string) []net.IP {
	out := make([]net.IP, 0, len(ss))
	for _, s := range ss {
		out = append(out, net.ParseIP(s))
	}
	return out
}

func strs(in []net.IP) []string {
	out := make([]string, 0, len(in))
	for _, ip := range in {
		out = append(out, ip.String())
	}
	return out
}

func TestIpsAppendUnique(t *testing.T) {
	got := ipsAppendUnique(ips("10.0.0.1"), ips("10.0.0.1", "10.0.0.2", "10.0.0.2", "::ffff:10.0.0.2", "2001:db8::1"))
	// ::ffff:10.0.0.2 is the IPv4-mapped form of 10.0.0.2 and String() renders it the same way.
	assert.Equal(t, []string{"10.0.0.1", "10.0.0.2", "2001:db8::1"}, strs(got))
	assert.Empty(t, ipsAppendUnique(nil, nil))
}

func TestExtractQuestions(t *testing.T) {
	q := func(types ...uint16) []dns.Question {
		var out []dns.Question
		for _, t := range types {
			out = append(out, dns.Question{Name: "x.", Qtype: t})
		}
		return out
	}
	cases := []struct {
		name    string
		in      []dns.Question
		a, aaaa bool
	}{
		{"none", nil, false, false},
		{"A", q(dns.TypeA), true, false},
		{"AAAA", q(dns.TypeAAAA), false, true},
		{"ANY", q(dns.TypeANY), true, true},
		{"A+AAAA", q(dns.TypeA, dns.TypeAAAA), true, true},
		{"MX", q(dns.TypeMX), false, false},
		{"MX+A", q(dns.TypeMX, dns.TypeA), true, false},
	}
	for _, c := range cases {
		a, aaaa := extractQuestions(c.in)
		assert.Equal(t, c.a, a, c.name+" A")
		assert.Equal(t, c.aaaa, aaaa, c.name+" AAAA")
	}
}

func TestFilterIPFamilies(t *testing.T) {
	mixed := ips("10.0.0.1", "2001:db8::1", "::ffff:10.0.0.2", "10.0.0.3")
	assert.Equal(t, []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}, strs(filterIPv4(mixed)), "IPv4-mapped counts as IPv4")
	assert.Equal(t, []string{"2001:db8::1"}, strs(filterIPv6(mixed)))
	assert.Empty(t, filterIPv4(nil))
	assert.Empty(t, filterIPv6(nil))
}

func TestTransformIps_edge_cases(t *testing.T) {
	r := recursor{random: rand.New(rand.NewSource(1))}
	three := ips("10.0.0.3", "10.0.0.1", "10.0.0.2")

	cases := []struct {
		name      string
		in        []net.IP
		transform []string
		want      []string
	}{
		{"empty input any transform", nil, []string{"shuffle", "sort_asc", "first", "last", "random_one", "prefer_ipv4", "limit_1"}, []string{}},
		{"first on single", ips("10.0.0.1"), []string{"first"}, []string{"10.0.0.1"}},
		{"last on single", ips("10.0.0.1"), []string{"last"}, []string{"10.0.0.1"}},
		{"limit larger than len", three, []string{"limit_10"}, []string{"10.0.0.3", "10.0.0.1", "10.0.0.2"}},
		{"limit negative clears", three, []string{"limit_-1"}, []string{}},
		{"limit not a number ignored", three, []string{"limit_x"}, []string{"10.0.0.3", "10.0.0.1", "10.0.0.2"}},
		{"limit without number ignored", three, []string{"limit_"}, []string{"10.0.0.3", "10.0.0.1", "10.0.0.2"}},
		{"sort then last", three, []string{"sort_asc", "last"}, []string{"10.0.0.3"}},
		{"sort then limit", three, []string{"sort_desc", "limit_2"}, []string{"10.0.0.3", "10.0.0.2"}},
		{"names are case sensitive", three, []string{"SORT_ASC"}, []string{"10.0.0.3", "10.0.0.1", "10.0.0.2"}},
		{"sort mixed families v4 before v6", ips("2001:db8::1", "10.0.0.1"), []string{"sort_asc"}, []string{"10.0.0.1", "2001:db8::1"}},
		{"prefer_ipv6 then first", ips("10.0.0.1", "2001:db8::1"), []string{"prefer_ipv6", "first"}, []string{"2001:db8::1"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, c.want, strs(r.transformIps(c.in, c.transform)))
		})
	}
}

func TestTransformIps_does_not_mutate_input(t *testing.T) {
	r := recursor{random: rand.New(rand.NewSource(1))}
	in := ips("10.0.0.3", "10.0.0.1", "10.0.0.2")
	r.transformIps(in, []string{"sort_asc", "shuffle", "prefer_ipv6"})
	assert.Equal(t, []string{"10.0.0.3", "10.0.0.1", "10.0.0.2"}, strs(in))
}

func TestFindAlias(t *testing.T) {
	r := recursor{aliases: map[string]aliasDef{"a": {ttl: 1}, "*": {ttl: 2}}}
	d, _, found, wild := r.findAlias("a")
	assert.True(t, found)
	assert.False(t, wild)
	assert.Equal(t, uint32(1), d.ttl)

	d, _, found, wild = r.findAlias("b")
	assert.True(t, found)
	assert.True(t, wild)
	assert.Equal(t, uint32(2), d.ttl)

	r = recursor{aliases: map[string]aliasDef{"a": {}}}
	_, _, found, _ = r.findAlias("b")
	assert.False(t, found)
}
