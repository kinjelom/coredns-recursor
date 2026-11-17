package recursor

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/plugin/test"
	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------- metric cardinality

func TestHardening_metric_labels_never_come_from_query_names(t *testing.T) {
	up := startFakeDNS(t, map[string][]string{"random-1.card.svc": {"192.0.2.1"}})
	r := newRecursor(t, "card.svc", recursorCfg{
		Resolvers: map[string]resolverCfg{"up": {Urls: []string{up.url}}},
		Aliases:   map[string]aliasCfg{"*": {ResolverName: "up"}},
	})
	s := serve(r, "random-1.card.svc.", dns.TypeA)
	require.NoError(t, s.err)
	assert.Equal(t, []string{"192.0.2.1"}, s.ips)

	served := prometheus.Labels{"port": "53", "zone": "card.svc.", "alias": "*", "resolver": "up", "client_ip": "10.240.0.1"}
	assert.Equal(t, 1.0, testutil.ToFloat64(promQueryServedCountTotal.With(served)), "wildcard answers are counted as alias '*'")
	resolve := prometheus.Labels{"port": "53", "zone": "card.svc.", "alias": "*", "resolver": "up", "host": "*", "result": "success"}
	assert.Equal(t, 1.0, testutil.ToFloat64(promResolveCountTotal.With(resolve)), "wildcard lookups are counted as host '*'")
	ip := prometheus.Labels{"port": "53", "zone": "card.svc.", "alias": "*", "resolver": "up", "ip": "192.0.2.1"}
	assert.Equal(t, 1.0, testutil.ToFloat64(promResolveIpCountTotal.With(ip)))

	assert.Zero(t, countSeriesWithLabel(t, promQueryServedCountTotal, "alias", "random-1"))
	assert.Zero(t, countSeriesWithLabel(t, promResolveCountTotal, "host", "random-1.card.svc."))
}

func TestHardening_unsupported_query_for_unknown_name_uses_empty_alias(t *testing.T) {
	r := newRecursor(t, "card2.svc", recursorCfg{Aliases: map[string]aliasCfg{"a": {Ips: []string{"10.0.0.1"}}}})
	r.Next = test.NextHandler(dns.RcodeRefused, nil)
	labels := prometheus.Labels{"port": "53", "zone": "card2.svc.", "alias": "", "reason": "not-supported-query-code", "client_ip": "10.240.0.1"}
	before := testutil.ToFloat64(promQueryOmittedCountTotal.With(labels))
	serve(r, "whatever-123.card2.svc.", dns.TypeMX)
	assert.Equal(t, before+1, testutil.ToFloat64(promQueryOmittedCountTotal.With(labels)))
	assert.Zero(t, countSeriesWithLabel(t, promQueryOmittedCountTotal, "alias", "whatever-123"))
}

func TestHardening_client_ip_metrics_can_be_disabled(t *testing.T) {
	off := false
	r := newRecursor(t, "noclient.svc", recursorCfg{
		ClientIpMetrics: &off,
		Aliases:         map[string]aliasCfg{"a": {Ips: []string{"10.0.0.1"}}},
	})
	serveFrom(r, "10.9.9.9", "a.noclient.svc.", dns.TypeA)
	labels := prometheus.Labels{"port": "53", "zone": "noclient.svc.", "alias": "a", "resolver": "default", "client_ip": ""}
	assert.Equal(t, 1.0, testutil.ToFloat64(promQueryServedCountTotal.With(labels)))
	assert.Zero(t, countSeriesWithLabel(t, promQueryServedCountTotal, "client_ip", "10.9.9.9"))

	on := newRecursor(t, "client.svc", recursorCfg{Aliases: map[string]aliasCfg{"a": {Ips: []string{"10.0.0.1"}}}})
	assert.True(t, on.clientIpMetrics, "enabled by default")
}

func TestHardening_client_ip_metrics_config(t *testing.T) {
	c := caddy.NewTestController("dns", pluginName+" {\n client_ip_metrics false\n}")
	cfg, err := readCaddyControllerConfig(c)
	require.NoError(t, err)
	require.NotNil(t, cfg.ClientIpMetrics)
	assert.False(t, *cfg.ClientIpMetrics)

	y, err := readYamlConfig([]byte("client_ip_metrics: false\n"))
	require.NoError(t, err)
	assert.False(t, *y.ClientIpMetrics)

	c = caddy.NewTestController("dns", pluginName+" {\n client_ip_metrics no\n}")
	_, err = readCaddyControllerConfig(c)
	assert.ErrorContains(t, err, "must be true or false")
}

// ---------------------------------------------------------------- lookups

func TestHardening_slower_lookups_are_cancelled_after_first_answer(t *testing.T) {
	up := startFakeDNS(t, map[string][]string{"backend.test": {"192.0.2.40"}})
	r := newRecursor(t, "cancel.svc", recursorCfg{
		Resolvers: map[string]resolverCfg{
			"multi": {Urls: []string{blackHoleResolverURL(t), up.url}, TimeoutMs: 5000},
		},
		Aliases: map[string]aliasCfg{"x": {Hosts: []string{"backend.test"}, ResolverName: "multi"}},
	})
	for i := 0; i < 20; i++ {
		require.Equal(t, []string{"192.0.2.40"}, serve(r, "x.cancel.svc.", dns.TypeA).ips)
	}
	errLabels := prometheus.Labels{"port": "53", "zone": "cancel.svc.", "alias": "x", "resolver": "multi", "host": "backend.test", "result": "error"}
	assert.Zero(t, testutil.ToFloat64(promResolveCountTotal.With(errLabels)), "cancelled lookups aren't upstream errors")
}

// LookupIP returns as soon as its context is cancelled, but the exchange it started runs on in
// a goroutine of its own, reading from the upstream until its deadline. The resolver's Dial must
// unblock that read when the context is cancelled.
func TestHardening_cancel_unblocks_upstream_read(t *testing.T) {
	rd, err := createResolver("r", resolverCfg{Urls: []string{blackHoleResolverURL(t)}, TimeoutMs: 5000})
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	conn, err := rd.resolverRefs[0].Dial(ctx, "udp", "ignored:53")
	require.NoError(t, err)
	defer conn.Close()
	read := make(chan error, 1)
	go func() {
		_, err := conn.Read(make([]byte, 512))
		read <- err
	}()
	cancel()
	select {
	case err := <-read:
		assert.ErrorIs(t, err, os.ErrDeadlineExceeded)
	case <-time.After(time.Second):
		_ = conn.Close()
		t.Fatal("read from a silent upstream is not interrupted by cancellation")
	}
}

func TestHardening_default_timeout(t *testing.T) {
	rd, err := createResolver("r", resolverCfg{Urls: []string{"udp://127.0.0.1:53"}})
	require.NoError(t, err)
	assert.Equal(t, defaultResolveTimeout, rd.timeout)
	rd, err = createResolver("r", resolverCfg{Urls: []string{"udp://127.0.0.1:53"}, TimeoutMs: 300})
	require.NoError(t, err)
	assert.Equal(t, 300*time.Millisecond, rd.timeout)
	r := newRecursor(t, "svc", recursorCfg{})
	assert.Equal(t, defaultResolveTimeout, r.resolvers[defaultResolverName].timeout)
}

func TestHardening_resolver_url_validation(t *testing.T) {
	for _, u := range []string{"udp://127.0.0.1:53", "tcp://127.0.0.1:53", "udp://[::1]:53", "udp://dns.example:5353"} {
		_, err := createResolver("r", resolverCfg{Urls: []string{u}})
		assert.NoError(t, err, u)
	}
	for _, u := range []string{"udp://127.0.0.1", "http://127.0.0.1:53", "127.0.0.1:53", "udp://:53", "udp://127.0.0.1:0",
		"udp://127.0.0.1:99999", "udp://127.0.0.1:dns", "://default"} {
		_, err := createResolver("r", resolverCfg{Urls: []string{u}})
		assert.Error(t, err, u)
	}
}

func TestHardening_truncated_udp_answer_is_retried_over_tcp(t *testing.T) {
	up := startFakeDNSWith(t, fakeOpts{records: map[string][]string{"big.test": {"192.0.2.7"}}, truncateUDP: true})
	r := newRecursor(t, "tc.svc", recursorCfg{
		Resolvers: map[string]resolverCfg{"up": {Urls: []string{up.url}}},
		Aliases:   map[string]aliasCfg{"x": {Hosts: []string{"big.test"}, ResolverName: "up"}},
	})
	s := serve(r, "x.tc.svc.", dns.TypeA)
	require.NoError(t, s.err)
	assert.Equal(t, []string{"192.0.2.7"}, s.ips)
	assert.Positive(t, up.count("big.test", dns.TypeA, "tcp"), "the TC answer must be retried over TCP")
}

func TestHardening_tcp_scheme_uses_tcp(t *testing.T) {
	up := startFakeDNSWith(t, fakeOpts{records: map[string][]string{"tcp.test": {"192.0.2.8"}}, refuseUDP: true})
	r := newRecursor(t, "tcp.svc", recursorCfg{
		Resolvers: map[string]resolverCfg{"up": {Urls: []string{up.tcpURL}}},
		Aliases:   map[string]aliasCfg{"x": {Hosts: []string{"tcp.test"}, ResolverName: "up"}},
	})
	assert.Equal(t, []string{"192.0.2.8"}, serve(r, "x.tcp.svc.", dns.TypeA).ips)
	assert.Zero(t, up.count("tcp.test", 0, "udp"))
}

func TestHardening_upstream_is_asked_only_for_the_requested_family(t *testing.T) {
	up := startFakeDNS(t, map[string][]string{
		"dual.test": {"192.0.2.1", "2001:db8::1"},
		"v6.test":   {"2001:db8::6"},
	})
	r := newRecursor(t, "fam.svc", recursorCfg{
		Resolvers: map[string]resolverCfg{"up": {Urls: []string{up.url}}},
		Aliases: map[string]aliasCfg{
			"dual": {Hosts: []string{"dual.test"}, ResolverName: "up"},
			"v6":   {Hosts: []string{"v6.test"}, ResolverName: "up"},
		},
	})
	assert.Equal(t, []string{"192.0.2.1"}, serve(r, "dual.fam.svc.", dns.TypeA).ips)
	assert.Equal(t, 1, up.count("dual.test", dns.TypeA, ""))
	assert.Zero(t, up.count("dual.test", dns.TypeAAAA, ""), "an A query must not ask the upstream for AAAA")

	assert.Equal(t, []string{"2001:db8::1"}, serve(r, "dual.fam.svc.", dns.TypeAAAA).ips)
	assert.Equal(t, 1, up.count("dual.test", dns.TypeA, ""), "an AAAA query must not ask the upstream for A")

	// A host without IPv4 addresses: empty answer (NODATA), not a failure.
	s := serve(r, "v6.fam.svc.", dns.TypeA)
	require.NoError(t, s.err)
	assert.Equal(t, dns.RcodeSuccess, s.code)
	assert.Empty(t, s.ips)
}

func TestHardening_hosts_are_resolved_in_parallel(t *testing.T) {
	up := startFakeDNSWith(t, fakeOpts{
		records: map[string][]string{"slow1.test": {"192.0.2.1"}, "slow2.test": {"192.0.2.2"}, "slow3.test": {"192.0.2.3"}},
		delays:  map[string]time.Duration{"slow1.test.": 300 * time.Millisecond, "slow2.test.": 300 * time.Millisecond, "slow3.test.": 300 * time.Millisecond},
	})
	r := newRecursor(t, "par.svc", recursorCfg{
		Resolvers: map[string]resolverCfg{"up": {Urls: []string{up.url}, TimeoutMs: 2000}},
		Aliases:   map[string]aliasCfg{"x": {Hosts: []string{"slow1.test", "slow2.test", "slow3.test"}, ResolverName: "up"}},
	})
	start := time.Now()
	s := serve(r, "x.par.svc.", dns.TypeA)
	elapsed := time.Since(start)
	require.NoError(t, s.err)
	assert.Equal(t, []string{"192.0.2.1", "192.0.2.2", "192.0.2.3"}, s.ips, "configured order is kept")
	assert.Less(t, elapsed, 700*time.Millisecond, "3 hosts x 300ms must not take 900ms")
}

// ---------------------------------------------------------------- configuration

func TestHardening_strict_configuration(t *testing.T) {
	_, err := readYamlConfig([]byte("resolvers:\n  r:\n    urls: [udp://127.0.0.1:53]\n    timeout: 500\n"))
	assert.ErrorContains(t, err, "timeout", "unknown YAML key")
	_, err = readJsonConfig([]byte(`{"aliases": {"a": {"ips": ["10.0.0.1"], "tll": 5}}}`))
	assert.ErrorContains(t, err, "tll", "unknown JSON key")
	_, err = readYamlConfig([]byte(""))
	assert.NoError(t, err, "an empty YAML file is an empty config")

	for _, body := range []string{"shuffle_ips yes", "shuffle_ips 1", "ttl -1", "ttl 4294967296", "ttl 1.5"} {
		c := caddy.NewTestController("dns", pluginName+" {\n alias a {\n  ips 10.0.0.1\n  "+body+"\n }\n}")
		_, err := readCaddyControllerConfig(c)
		assert.Error(t, err, body)
	}
	_, err = createRecursor("svc", recursorCfg{Aliases: map[string]aliasCfg{"a": {Ips: []string{"10.0.0.1"}, Ttl: maxTTL + 1}}})
	assert.ErrorContains(t, err, "out of range")
	_, err = createRecursor("svc", recursorCfg{Aliases: map[string]aliasCfg{"a": {Ips: []string{"10.0.0.1"}, Ttl: maxTTL}}})
	assert.NoError(t, err)
}

func TestHardening_alias_names_are_case_insensitive(t *testing.T) {
	r := newRecursor(t, "svc", recursorCfg{Aliases: map[string]aliasCfg{"Api.V1": {Ips: []string{"10.0.0.1"}}}})
	assert.Equal(t, []string{"10.0.0.1"}, serve(r, "api.v1.svc.", dns.TypeA).ips)

	_, err := createRecursor("svc", recursorCfg{Aliases: map[string]aliasCfg{
		"API": {Ips: []string{"10.0.0.1"}},
		"api": {Ips: []string{"10.0.0.2"}},
	}})
	assert.ErrorContains(t, err, "duplicate alias")
}

func TestHardening_external_config_path_relative_to_corefile(t *testing.T) {
	dir := t.TempDir()
	corefile := filepath.Join(dir, "Corefile")
	require.NoError(t, os.WriteFile(filepath.Join(dir, "rec.yaml"), []byte("verbose: 1\n"), 0o600))

	assert.Equal(t, filepath.Join(dir, "rec.yaml"), configFilePath(corefile, "rec.yaml"), "next to the Corefile")
	assert.Equal(t, "examples/demo.yaml", configFilePath(corefile, "examples/demo.yaml"), "fallback: working directory")
	assert.Equal(t, "/abs/x.yaml", configFilePath(corefile, "/abs/x.yaml"))
	assert.Equal(t, "x.yaml", configFilePath("", "x.yaml"))
}

// ---------------------------------------------------------------- responses

func TestHardening_answers_are_authoritative_and_nodata_has_soa(t *testing.T) {
	r := newRecursor(t, "auth.svc", recursorCfg{Aliases: map[string]aliasCfg{
		"v4": {Ips: []string{"10.0.0.1"}, Ttl: 30, Services: []string{"https:443"}},
	}})
	a := serve(r, "v4.auth.svc.", dns.TypeA)
	assert.True(t, a.rec.Msg.Authoritative)
	assert.Empty(t, a.rec.Msg.Ns, "no SOA with a non-empty answer")

	for _, s := range []served{
		serve(r, "v4.auth.svc.", dns.TypeAAAA),            // A/AAAA path
		serve(r, "_https._tcp.v4.auth.svc.", dns.TypeTXT), // service path
	} {
		require.Empty(t, s.rec.Msg.Answer)
		assert.True(t, s.rec.Msg.Authoritative)
		require.Len(t, s.rec.Msg.Ns, 1)
		soa, ok := s.rec.Msg.Ns[0].(*dns.SOA)
		require.True(t, ok)
		assert.Equal(t, "auth.svc.", soa.Hdr.Name)
		assert.Equal(t, "ns.auth.svc.", soa.Ns)
		assert.Equal(t, "hostmaster.auth.svc.", soa.Mbox)
		assert.Equal(t, uint32(30), soa.Hdr.Ttl)
		assert.Equal(t, uint32(30), soa.Minttl, "negative caching TTL = alias ttl")
	}
}

func TestHardening_soa_for_root_zone(t *testing.T) {
	r := newRecursor(t, ".", recursorCfg{})
	soa := r.soa(5).(*dns.SOA)
	assert.Equal(t, ".", soa.Hdr.Name)
	assert.Equal(t, "ns.", soa.Ns)
}

func TestHardening_build_info_is_one(t *testing.T) {
	updateInfoMetrics("bi.svc.", "53", newRecursor(t, "bi.svc", recursorCfg{}))
	assert.Equal(t, 1.0, testutil.ToFloat64(promBuildInfo.With(prometheus.Labels{"version": pluginVersion})))
}

// countSeriesWithLabel returns the number of series of a metric vector whose label has the value.
func countSeriesWithLabel(t *testing.T, c prometheus.Collector, label, value string) int {
	t.Helper()
	ch := make(chan prometheus.Metric, 10000)
	c.Collect(ch)
	close(ch)
	n := 0
	for m := range ch {
		var pb dto.Metric
		require.NoError(t, m.Write(&pb))
		for _, lp := range pb.GetLabel() {
			if lp.GetName() == label && lp.GetValue() == value {
				n++
			}
		}
	}
	return n
}
