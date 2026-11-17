package recursor

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/coredns/coredns/plugin/test"
	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newRecursor(t *testing.T, zone string, cfg recursorCfg) recursor {
	t.Helper()
	r, err := createRecursor(zone, cfg)
	require.NoError(t, err)
	return r
}

func TestHermetic_custom_resolver_resolves_hosts_and_filters_by_qtype(t *testing.T) {
	up := startFakeDNS(t, map[string][]string{
		"backend.test": {"192.0.2.10", "192.0.2.11", "2001:db8::10"},
	})
	r := newRecursor(t, "svc", recursorCfg{
		Resolvers: map[string]resolverCfg{"up": {Urls: []string{up.url}, TimeoutMs: 500}},
		Aliases:   map[string]aliasCfg{"api": {Hosts: []string{"backend.test"}, Ttl: 7, ResolverName: "up"}},
	})

	a := serve(r, "api.svc.", dns.TypeA)
	require.NoError(t, a.err)
	assert.Equal(t, dns.RcodeSuccess, a.code)
	assert.ElementsMatch(t, []string{"192.0.2.10", "192.0.2.11"}, a.ips)
	assert.Equal(t, []uint32{7, 7}, a.ttls, "TTL from alias config")
	assert.Equal(t, []string{"api.svc.", "api.svc."}, a.owners, "answer owner name = query name")

	aaaa := serve(r, "api.svc.", dns.TypeAAAA)
	assert.Equal(t, []string{"2001:db8::10"}, aaaa.ips)

	both := serve(r, "api.svc.", dns.TypeANY)
	assert.ElementsMatch(t, []string{"192.0.2.10", "192.0.2.11", "2001:db8::10"}, both.ips)

	assert.True(t, up.asked("backend.test."), "custom resolver must be used instead of the system one")
}

func TestHermetic_static_ips_are_filtered_by_qtype(t *testing.T) {
	r := newRecursor(t, "svc", recursorCfg{
		Aliases: map[string]aliasCfg{
			"mixed":  {Ips: []string{"10.0.0.1", "2001:db8::1"}},
			"v4only": {Ips: []string{"10.0.0.1"}},
		},
	})
	assert.Equal(t, []string{"10.0.0.1"}, serve(r, "mixed.svc.", dns.TypeA).ips)
	assert.Equal(t, []string{"2001:db8::1"}, serve(r, "mixed.svc.", dns.TypeAAAA).ips)

	// AAAA query for an IPv4-only alias -> NOERROR with empty answer (NODATA), not a fallthrough.
	nodata := serve(r, "v4only.svc.", dns.TypeAAAA)
	require.NoError(t, nodata.err)
	assert.Equal(t, dns.RcodeSuccess, nodata.code)
	assert.Empty(t, nodata.ips)
}

func TestHermetic_query_name_is_case_insensitive_and_zone_may_be_fqdn(t *testing.T) {
	for _, zone := range []string{"svc", "svc.", "SVC."} {
		r := newRecursor(t, zone, recursorCfg{
			Aliases: map[string]aliasCfg{"api": {Ips: []string{"10.0.0.1"}}},
		})
		for _, q := range []string{"api.svc", "api.svc.", "API.SVC.", "Api.Svc"} {
			s := serve(r, q, dns.TypeA)
			assert.NoError(t, s.err, "zone %q query %q", zone, q)
			assert.Equal(t, []string{"10.0.0.1"}, s.ips, "zone %q query %q", zone, q)
		}
	}
}

func TestHermetic_multi_level_alias_names(t *testing.T) {
	r := newRecursor(t, "svc", recursorCfg{
		Aliases: map[string]aliasCfg{"a.b": {Ips: []string{"10.0.0.7"}}},
	})
	assert.Equal(t, []string{"10.0.0.7"}, serve(r, "a.b.svc.", dns.TypeA).ips)
}

func TestHermetic_falls_back_to_working_resolver_when_another_fails(t *testing.T) {
	up := startFakeDNS(t, map[string][]string{"backend.test": {"192.0.2.20"}})
	r := newRecursor(t, "svc", recursorCfg{
		Resolvers: map[string]resolverCfg{
			"multi": {Urls: []string{unreachableResolverURL(t), up.url}, TimeoutMs: 500},
		},
		Aliases: map[string]aliasCfg{"api": {Hosts: []string{"backend.test"}, ResolverName: "multi"}},
	})
	s := serve(r, "api.svc.", dns.TypeA)
	require.NoError(t, s.err)
	assert.Equal(t, []string{"192.0.2.20"}, s.ips)
}

func TestHermetic_resolving_error_falls_through_to_next_plugin(t *testing.T) {
	up := startFakeDNS(t, map[string][]string{}) // NXDOMAIN for everything
	r := newRecursor(t, "svc", recursorCfg{
		Resolvers: map[string]resolverCfg{"up": {Urls: []string{up.url}}},
		Aliases: map[string]aliasCfg{
			"api":    {Hosts: []string{"missing.test"}, ResolverName: "up"},
			"static": {Ips: []string{"10.0.0.1"}, Hosts: []string{"missing.test"}, ResolverName: "up"},
		},
	})
	r.Next = test.NextHandler(dns.RcodeRefused, nil)

	labels := prometheus.Labels{"port": "53", "zone": "svc.", "alias": "api", "reason": "resolving-error", "client_ip": "10.240.0.1"}
	before := testutil.ToFloat64(promQueryOmittedCountTotal.With(labels))

	s := serve(r, "api.svc.", dns.TypeA)
	assert.Equal(t, dns.RcodeRefused, s.code, "next plugin must handle the query")
	assert.Equal(t, before+1, testutil.ToFloat64(promQueryOmittedCountTotal.With(labels)))

	// Even when static IPs exist, a failing host makes the whole alias fall through (current behaviour).
	assert.Equal(t, dns.RcodeRefused, serve(r, "static.svc.", dns.TypeA).code)
}

func TestHermetic_without_next_plugin_returns_servfail_error(t *testing.T) {
	r := newRecursor(t, "svc", recursorCfg{
		Aliases: map[string]aliasCfg{"api": {Ips: []string{"10.0.0.1"}}},
	})
	s := serve(r, "unknown.svc.", dns.TypeA)
	assert.Error(t, s.err)
	assert.Equal(t, dns.RcodeServerFailure, s.code)
}

func TestHermetic_unhandled_queries_go_to_next_plugin(t *testing.T) {
	r := newRecursor(t, "svc", recursorCfg{
		Aliases: map[string]aliasCfg{"api": {Ips: []string{"10.0.0.1"}}},
	})
	nextErr := errors.New("next called")
	r.Next = test.NextHandler(dns.RcodeNameError, nextErr)

	cases := []struct {
		name, q string
		qt      uint16
		reason  string
		alias   string
	}{
		{"unknown alias", "nope.svc.", dns.TypeA, "alias-not-found", ""}, // query names never become label values
		{"unsupported qtype MX", "api.svc.", dns.TypeMX, "not-supported-query-code", "api"},
		{"unsupported qtype TXT", "api.svc.", dns.TypeTXT, "not-supported-query-code", "api"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			labels := prometheus.Labels{"port": "53", "zone": "svc.", "alias": c.alias, "reason": c.reason, "client_ip": "10.240.0.1"}
			before := testutil.ToFloat64(promQueryOmittedCountTotal.With(labels))
			s := serve(r, c.q, c.qt)
			assert.ErrorIs(t, s.err, nextErr)
			assert.Equal(t, dns.RcodeNameError, s.code)
			assert.Equal(t, before+1, testutil.ToFloat64(promQueryOmittedCountTotal.With(labels)), "omitted metric")
		})
	}
}

func TestHermetic_wildcard_forwards_original_query_name(t *testing.T) {
	up := startFakeDNS(t, map[string][]string{"anything.corp": {"192.0.2.30"}})
	r := newRecursor(t, "corp", recursorCfg{
		Resolvers: map[string]resolverCfg{"default": {Urls: []string{up.url}}},
		Aliases:   map[string]aliasCfg{"*": {Ttl: 30}},
	})
	s := serve(r, "Anything.corp.", dns.TypeA)
	require.NoError(t, s.err)
	assert.Equal(t, []string{"192.0.2.30"}, s.ips)
	assert.Equal(t, []uint32{30}, s.ttls)
	assert.True(t, up.asked("anything.corp."))
}

func TestHermetic_explicit_alias_wins_over_wildcard(t *testing.T) {
	r := newRecursor(t, "svc", recursorCfg{
		Aliases: map[string]aliasCfg{
			"api": {Ips: []string{"10.0.0.1"}},
			"*":   {Ips: []string{"10.9.9.9"}},
		},
	})
	assert.Equal(t, []string{"10.0.0.1"}, serve(r, "api.svc.", dns.TypeA).ips)
	assert.Equal(t, []string{"10.9.9.9"}, serve(r, "other.svc.", dns.TypeA).ips)
}

func TestHermetic_served_and_ip_metrics(t *testing.T) {
	r := newRecursor(t, "metrics.svc", recursorCfg{
		Aliases: map[string]aliasCfg{"m": {Ips: []string{"10.0.0.42"}}},
	})
	servedLabels := prometheus.Labels{"port": "53", "zone": "metrics.svc.", "alias": "m", "resolver": "default", "client_ip": "10.240.0.1"}
	ipLabels := prometheus.Labels{"port": "53", "zone": "metrics.svc.", "alias": "m", "resolver": "default", "ip": "10.0.0.42"}
	servedBefore := testutil.ToFloat64(promQueryServedCountTotal.With(servedLabels))
	ipBefore := testutil.ToFloat64(promResolveIpCountTotal.With(ipLabels))

	serve(r, "m.metrics.svc.", dns.TypeA)
	serve(r, "m.metrics.svc.", dns.TypeA)

	assert.Equal(t, servedBefore+2, testutil.ToFloat64(promQueryServedCountTotal.With(servedLabels)))
	assert.Equal(t, ipBefore+2, testutil.ToFloat64(promResolveIpCountTotal.With(ipLabels)))
}

func TestHermetic_resolve_metrics_record_result(t *testing.T) {
	up := startFakeDNS(t, map[string][]string{"ok.test": {"192.0.2.1"}})
	r := newRecursor(t, "rm.svc", recursorCfg{
		Resolvers: map[string]resolverCfg{"up": {Urls: []string{up.url}}},
		Aliases:   map[string]aliasCfg{"x": {Hosts: []string{"ok.test"}, ResolverName: "up"}},
	})
	labels := prometheus.Labels{"port": "53", "zone": "rm.svc.", "alias": "x", "resolver": "up", "host": "ok.test", "result": "success"}
	before := testutil.ToFloat64(promResolveCountTotal.With(labels))
	serve(r, "x.rm.svc.", dns.TypeA)
	assert.Equal(t, before+1, testutil.ToFloat64(promResolveCountTotal.With(labels)))
}

func TestHermetic_shuffle_does_not_mutate_alias_definition(t *testing.T) {
	r := newRecursor(t, "svc", recursorCfg{
		Aliases: map[string]aliasCfg{"s": {Ips: []string{"10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"}, ShuffleIps: true}},
	})
	for i := 0; i < 20; i++ {
		serve(r, "s.svc.", dns.TypeA)
	}
	var got []string
	for _, ip := range r.aliases["s"].ips {
		got = append(got, ip.String())
	}
	assert.Equal(t, []string{"10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"}, got)
}

func TestHermetic_concurrent_queries(t *testing.T) {
	up := startFakeDNS(t, map[string][]string{"backend.test": {"192.0.2.10"}})
	r := newRecursor(t, "svc", recursorCfg{
		Resolvers: map[string]resolverCfg{"up": {Urls: []string{up.url}}},
		Aliases: map[string]aliasCfg{
			"h": {Hosts: []string{"backend.test"}, ResolverName: "up"},
			// static IPs only: shuffle path is exercised concurrently (shared rand.Rand)
			"s": {Ips: []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}, IpsTransform: []string{"shuffle", "random_one"}},
		},
	})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	errs := make(chan error, 100)
	for i := 0; i < 50; i++ {
		go func() {
			s := serve(r, "h.svc.", dns.TypeA)
			if s.err == nil && len(s.ips) != 1 {
				s.err = errors.New("unexpected answer")
			}
			errs <- s.err
		}()
		go func() {
			s := serve(r, "s.svc.", dns.TypeA)
			if s.err == nil && len(s.ips) != 1 {
				s.err = errors.New("unexpected answer")
			}
			errs <- s.err
		}()
	}
	for i := 0; i < 100; i++ {
		select {
		case err := <-errs:
			assert.NoError(t, err)
		case <-ctx.Done():
			t.Fatal("timeout waiting for concurrent queries")
		}
	}
}

// blackHoleResolverURL returns a UDP URL of a socket that accepts packets but never answers.
func blackHoleResolverURL(t *testing.T) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = pc.Close() })
	return "udp://" + pc.LocalAddr().String()
}

// Regression: timeout_ms used to be applied only to net.Dialer (dialing UDP never blocks),
// so a silent upstream held the query for ~40s (Go resolver defaults) instead of timeout_ms.
func TestHermetic_timeout_ms_bounds_query_time(t *testing.T) {
	r := newRecursor(t, "svc", recursorCfg{
		Resolvers: map[string]resolverCfg{"dead": {Urls: []string{blackHoleResolverURL(t)}, TimeoutMs: 200}},
		Aliases:   map[string]aliasCfg{"x": {Hosts: []string{"backend.test"}, ResolverName: "dead"}},
	})
	r.Next = test.NextHandler(dns.RcodeRefused, nil)
	start := time.Now()
	s := serve(r, "x.svc.", dns.TypeA)
	elapsed := time.Since(start)
	assert.Equal(t, dns.RcodeRefused, s.code, "timed-out lookup falls through to next plugin")
	assert.GreaterOrEqual(t, elapsed, 150*time.Millisecond, "timeout should actually be waited for")
	assert.Less(t, elapsed, 2*time.Second, "timeout_ms must bound the whole lookup")
}

// Regression: multiResolve used to wait for every upstream, so one silent resolver
// delayed answers that a healthy resolver had already returned.
func TestHermetic_silent_resolver_does_not_delay_healthy_one(t *testing.T) {
	up := startFakeDNS(t, map[string][]string{"backend.test": {"192.0.2.40"}})
	r := newRecursor(t, "svc", recursorCfg{
		Resolvers: map[string]resolverCfg{
			"multi": {Urls: []string{blackHoleResolverURL(t), up.url}, TimeoutMs: 3000},
		},
		Aliases: map[string]aliasCfg{"x": {Hosts: []string{"backend.test"}, ResolverName: "multi"}},
	})
	start := time.Now()
	s := serve(r, "x.svc.", dns.TypeA)
	require.NoError(t, s.err)
	assert.Equal(t, []string{"192.0.2.40"}, s.ips)
	assert.Less(t, time.Since(start), time.Second, "answer must not wait for the silent resolver's 3s timeout")
}

func TestLockedRand_is_safe_for_concurrent_use(t *testing.T) {
	rnd := newLockedRand(1)
	done := make(chan struct{})
	for i := 0; i < 8; i++ {
		go func() {
			defer func() { done <- struct{}{} }()
			s := []int{1, 2, 3, 4, 5}
			for j := 0; j < 1000; j++ {
				rnd.Shuffle(len(s), func(a, b int) { s[a], s[b] = s[b], s[a] })
				_ = rnd.Intn(10)
			}
		}()
	}
	for i := 0; i < 8; i++ {
		<-done
	}
}

func TestReady(t *testing.T) {
	assert.False(t, newRecursor(t, "svc", recursorCfg{}).Ready(), "no aliases -> not ready")
	assert.True(t, newRecursor(t, "svc", recursorCfg{Aliases: map[string]aliasCfg{"*": {}}}).Ready())
}
