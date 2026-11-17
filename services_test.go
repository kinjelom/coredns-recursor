package recursor

import (
	"testing"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/plugin/test"
	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseService_valid(t *testing.T) {
	cases := map[string]serviceDef{
		"https:443":          {name: "https", port: 443, protocol: "tcp"},
		"dns:53/udp":         {name: "dns", port: 53, protocol: "udp"},
		"dns:53/tcp":         {name: "dns", port: 53, protocol: "tcp"},
		"sip:5060/sctp":      {name: "sip", port: 5060, protocol: "sctp"},
		" HTTPS:443/TCP ":    {name: "https", port: 443, protocol: "tcp"},
		"xmpp-client:5222":   {name: "xmpp-client", port: 5222, protocol: "tcp"},
		"a:1":                {name: "a", port: 1, protocol: "tcp"},
		"x509:65535":         {name: "x509", port: 65535, protocol: "tcp"},
		"abcdefghijklmno:80": {name: "abcdefghijklmno", port: 80, protocol: "tcp"}, // 15 chars
	}
	for spec, want := range cases {
		got, err := parseService(spec)
		require.NoError(t, err, spec)
		assert.Equal(t, want, got, spec)
	}
}

func TestParseService_invalid(t *testing.T) {
	for _, spec := range []string{
		"", "https", "https:", ":443", "https:0", "https:65536", "https:-1", "https:abc",
		"https:443/", "https:443/icmp", "https:443/tcp/x", "https:443:1",
		"-https:443", "https-:443", "ht--tps:443", "ht_tps:443", "ht.tps:443", "_https:443",
		"123:443", "abcdefghijklmnop:80", // 16 chars
	} {
		_, err := parseService(spec)
		assert.Error(t, err, "%q should be rejected", spec)
	}
}

func TestParseServiceQueryName(t *testing.T) {
	type res struct {
		base, name, proto string
		enum, ok          bool
	}
	cases := map[string]res{
		"_https._tcp.alias1":            {"alias1", "https", "tcp", false, true},
		"_dns._udp.a.b":                 {"a.b", "dns", "udp", false, true},
		"_services._dns-sd._udp.alias1": {"alias1", "", "", true, true},
		"_services._dns-sd._udp.a.b":    {"a.b", "", "", true, true},
		"alias1":                        {},
		"_https.alias1":                 {},
		"_https._tcp":                   {},
		"https._tcp.alias1":             {},
		"_https.tcp.alias1":             {},
		"_._tcp.alias1":                 {},
		"_services._dns-sd._udp.":       {},
		"_services._dns-sd._udp":        {"_udp", "services", "dns-sd", false, true}, // syntactically a service; protocol never matches
	}
	for in, want := range cases {
		base, name, proto, enum, ok := parseServiceQueryName(in)
		assert.Equal(t, want, res{base, name, proto, enum, ok}, in)
	}
}

func TestCreateAlias_services_validation(t *testing.T) {
	_, err := createRecursor("svc", recursorCfg{Aliases: map[string]aliasCfg{
		"a": {Ips: []string{"10.0.0.1"}, Services: []string{"dns:53/udp", "dns:53/tcp", "https:443"}},
	}})
	assert.NoError(t, err, "same name on different protocols is allowed")

	bad := map[string]aliasCfg{
		"duplicate name+protocol":        {Ips: []string{"10.0.0.1"}, Services: []string{"https:443", "https:8443/tcp"}},
		"invalid spec":                   {Ips: []string{"10.0.0.1"}, Services: []string{"https"}},
		"services without ips and hosts": {Services: []string{"https:443"}},
	}
	for name, a := range bad {
		_, err := createRecursor("svc", recursorCfg{Aliases: map[string]aliasCfg{"a": a}})
		assert.Error(t, err, name)
	}
	_, err = createRecursor("svc", recursorCfg{Aliases: map[string]aliasCfg{"*": {Services: []string{"https:443"}}}})
	assert.ErrorContains(t, err, "wildcard")
}

func TestConfig_controller_reads_services(t *testing.T) {
	c := caddy.NewTestController("dns", pluginName+` {
		alias a {
			ips 10.0.0.1
			services https:443 dns:53/udp
			services dns:53/tcp
		}
	}`)
	cfg, err := readCaddyControllerConfig(c)
	require.NoError(t, err)
	assert.Equal(t, []string{"https:443", "dns:53/udp", "dns:53/tcp"}, cfg.Aliases["a"].Services, "repeated directive appends")

	c = caddy.NewTestController("dns", pluginName+" {\n alias a {\n  ips 10.0.0.1\n  services\n }\n}")
	_, err = readCaddyControllerConfig(c)
	assert.Error(t, err, "empty services list")
}

func servicesRecursor(t *testing.T) recursor {
	t.Helper()
	r := newRecursor(t, "svc", recursorCfg{
		Aliases: map[string]aliasCfg{
			"alias1": {
				Ips:      []string{"10.0.0.1", "2001:db8::1"},
				Ttl:      11,
				Services: []string{"https:443", "dns:53/udp", "dns:53/tcp"},
			},
			"plain": {Ips: []string{"10.0.0.2"}},
		},
	})
	r.Next = test.NextHandler(dns.RcodeRefused, nil)
	return r
}

func TestServices_srv_answer_with_glue(t *testing.T) {
	r := servicesRecursor(t)
	s := serve(r, "_https._tcp.alias1.svc.", dns.TypeSRV)
	require.NoError(t, s.err)
	require.Equal(t, dns.RcodeSuccess, s.code)
	msg := s.rec.Msg
	assert.True(t, msg.Authoritative)
	require.Len(t, msg.Answer, 1)
	srv, ok := msg.Answer[0].(*dns.SRV)
	require.True(t, ok)
	assert.Equal(t, "_https._tcp.alias1.svc.", srv.Hdr.Name)
	assert.Equal(t, uint32(11), srv.Hdr.Ttl)
	assert.Equal(t, uint16(0), srv.Priority)
	assert.Equal(t, uint16(0), srv.Weight)
	assert.Equal(t, uint16(443), srv.Port)
	assert.Equal(t, "alias1.svc.", srv.Target)

	// Additional section carries the target's A and AAAA records.
	var glue []string
	for _, rr := range msg.Extra {
		assert.Equal(t, "alias1.svc.", rr.Header().Name)
		assert.Equal(t, uint32(11), rr.Header().Ttl)
		switch a := rr.(type) {
		case *dns.A:
			glue = append(glue, a.A.String())
		case *dns.AAAA:
			glue = append(glue, a.AAAA.String())
		}
	}
	assert.ElementsMatch(t, []string{"10.0.0.1", "2001:db8::1"}, glue)
}

func TestServices_srv_same_name_different_protocols(t *testing.T) {
	r := servicesRecursor(t)
	for _, q := range []string{"_dns._udp.alias1.svc.", "_dns._tcp.alias1.svc."} {
		s := serve(r, q, dns.TypeSRV)
		require.Len(t, s.rec.Msg.Answer, 1, q)
		assert.Equal(t, uint16(53), s.rec.Msg.Answer[0].(*dns.SRV).Port, q)
	}
}

func TestServices_names_are_case_insensitive(t *testing.T) {
	r := servicesRecursor(t)
	s := serve(r, "_HTTPS._Tcp.ALIAS1.svc.", dns.TypeSRV)
	require.Len(t, s.rec.Msg.Answer, 1)
	assert.Equal(t, uint16(443), s.rec.Msg.Answer[0].(*dns.SRV).Port)
}

func TestServices_enumeration_ptr(t *testing.T) {
	r := servicesRecursor(t)
	s := serve(r, "_services._dns-sd._udp.alias1.svc.", dns.TypePTR)
	require.NoError(t, s.err)
	var ptrs []string
	for _, rr := range s.rec.Msg.Answer {
		p := rr.(*dns.PTR)
		assert.Equal(t, "_services._dns-sd._udp.alias1.svc.", p.Hdr.Name)
		assert.Equal(t, uint32(11), p.Hdr.Ttl)
		ptrs = append(ptrs, p.Ptr)
	}
	assert.Equal(t, []string{"_https._tcp.alias1.svc.", "_dns._udp.alias1.svc.", "_dns._tcp.alias1.svc."}, ptrs, "config order")
}

func TestServices_any_query(t *testing.T) {
	r := servicesRecursor(t)
	assert.Len(t, serve(r, "_https._tcp.alias1.svc.", dns.TypeANY).rec.Msg.Answer, 1)
	assert.Len(t, serve(r, "_services._dns-sd._udp.alias1.svc.", dns.TypeANY).rec.Msg.Answer, 3)
}

func TestServices_other_types_get_nodata(t *testing.T) {
	r := servicesRecursor(t)
	for _, c := range []struct {
		q  string
		qt uint16
	}{
		{"_https._tcp.alias1.svc.", dns.TypeA},
		{"_https._tcp.alias1.svc.", dns.TypeTXT},
		{"_services._dns-sd._udp.alias1.svc.", dns.TypeSRV},
	} {
		s := serve(r, c.q, c.qt)
		require.NoError(t, s.err, c.q)
		assert.Equal(t, dns.RcodeSuccess, s.code, c.q)
		assert.Empty(t, s.rec.Msg.Answer, c.q)
		assert.Empty(t, s.rec.Msg.Extra, c.q)
	}
}

func TestServices_unknown_names_fall_through(t *testing.T) {
	r := servicesRecursor(t)
	labels := prometheus.Labels{"port": "53", "zone": "svc.", "alias": "alias1", "reason": "service-not-found", "client_ip": "10.240.0.1"}
	before := testutil.ToFloat64(promQueryOmittedCountTotal.With(labels))

	assert.Equal(t, dns.RcodeRefused, serve(r, "_ldap._tcp.alias1.svc.", dns.TypeSRV).code, "unknown service")
	assert.Equal(t, dns.RcodeRefused, serve(r, "_https._udp.alias1.svc.", dns.TypeSRV).code, "known name, other protocol")
	assert.Equal(t, before+2, testutil.ToFloat64(promQueryOmittedCountTotal.With(labels)))

	// Aliases without services and unknown aliases behave as before (not service names).
	assert.Equal(t, dns.RcodeRefused, serve(r, "_https._tcp.plain.svc.", dns.TypeSRV).code)
	assert.Equal(t, dns.RcodeRefused, serve(r, "_services._dns-sd._udp.plain.svc.", dns.TypePTR).code)
	assert.Equal(t, dns.RcodeRefused, serve(r, "_https._tcp.nope.svc.", dns.TypeSRV).code)
}

func TestServices_alias_queries_unchanged(t *testing.T) {
	r := servicesRecursor(t)
	assert.Equal(t, []string{"10.0.0.1"}, serve(r, "alias1.svc.", dns.TypeA).ips)
	assert.Equal(t, dns.RcodeRefused, serve(r, "alias1.svc.", dns.TypeSRV).code, "SRV on the alias itself is not supported")
}

func TestServices_explicit_alias_wins_over_service_name(t *testing.T) {
	r := newRecursor(t, "svc", recursorCfg{
		Aliases: map[string]aliasCfg{
			"a":         {Ips: []string{"10.0.0.1"}, Services: []string{"x:80"}},
			"_x._tcp.a": {Ips: []string{"10.9.9.9"}},
		},
	})
	assert.Equal(t, []string{"10.9.9.9"}, serve(r, "_x._tcp.a.svc.", dns.TypeA).ips)
}

func TestServices_wildcard_still_handles_service_like_names_of_aliases_without_services(t *testing.T) {
	r := newRecursor(t, "svc", recursorCfg{
		Aliases: map[string]aliasCfg{
			"a": {Ips: []string{"10.0.0.1"}},
			"*": {Ips: []string{"10.9.9.9"}},
		},
	})
	assert.Equal(t, []string{"10.9.9.9"}, serve(r, "_x._tcp.a.svc.", dns.TypeA).ips)
}

func TestServices_glue_uses_resolved_hosts_and_transforms(t *testing.T) {
	up := startFakeDNS(t, map[string][]string{"backend.test": {"192.0.2.1", "192.0.2.2", "2001:db8::2"}})
	r := newRecursor(t, "svc", recursorCfg{
		Resolvers: map[string]resolverCfg{"up": {Urls: []string{up.url}, TimeoutMs: 1000}},
		Aliases: map[string]aliasCfg{"web": {
			Hosts: []string{"backend.test"}, ResolverName: "up",
			IpsTransform: []string{"prefer_ipv4", "first"},
			Services:     []string{"https:443"},
		}},
	})
	s := serve(r, "_https._tcp.web.svc.", dns.TypeSRV)
	require.Len(t, s.rec.Msg.Answer, 1)
	require.Len(t, s.rec.Msg.Extra, 1, "ips_transform applies to glue like to an A/AAAA answer")
	assert.Equal(t, "192.0.2.1", s.rec.Msg.Extra[0].(*dns.A).A.String())
}

func TestServices_srv_answered_without_glue_when_hosts_fail(t *testing.T) {
	up := startFakeDNS(t, map[string][]string{}) // NXDOMAIN
	r := newRecursor(t, "svc", recursorCfg{
		Resolvers: map[string]resolverCfg{"up": {Urls: []string{up.url}}},
		Aliases:   map[string]aliasCfg{"web": {Hosts: []string{"missing.test"}, ResolverName: "up", Services: []string{"https:443"}}},
	})
	s := serve(r, "_https._tcp.web.svc.", dns.TypeSRV)
	require.NoError(t, s.err)
	assert.Len(t, s.rec.Msg.Answer, 1)
	assert.Empty(t, s.rec.Msg.Extra)
}

func TestServices_root_zone_target(t *testing.T) {
	r := newRecursor(t, ".", recursorCfg{
		Aliases: map[string]aliasCfg{"host": {Ips: []string{"10.0.0.1"}, Services: []string{"https:443"}}},
	})
	s := serve(r, "_https._tcp.host.", dns.TypeSRV)
	require.Len(t, s.rec.Msg.Answer, 1)
	assert.Equal(t, "host.", s.rec.Msg.Answer[0].(*dns.SRV).Target)
}

func TestServices_info_metrics_and_reload_cleanup(t *testing.T) {
	zone, port := "metrics-svc.", "1053"
	first := newRecursor(t, zone, recursorCfg{Aliases: map[string]aliasCfg{
		"a": {Ips: []string{"10.0.0.1"}, Services: []string{"https:443", "dns:53/udp"}},
		"b": {Ips: []string{"10.0.0.2"}},
	}})
	updateInfoMetrics(zone, port, first)
	https := prometheus.Labels{"zone": zone, "port": port, "alias": "a", "resolver": "default", "service": "https", "protocol": "tcp", "service_port": "443"}
	dnsUdp := prometheus.Labels{"zone": zone, "port": port, "alias": "a", "resolver": "default", "service": "dns", "protocol": "udp", "service_port": "53"}
	assert.Equal(t, 1.0, testutil.ToFloat64(promAliasesServicesInfo.With(https)))
	assert.Equal(t, 1.0, testutil.ToFloat64(promAliasesServicesInfo.With(dnsUdp)))

	// Another server block must survive a reload of this one.
	otherZone := prometheus.Labels{"zone": "other.", "port": port, "alias": "x", "resolver": "default", "service": "ssh", "protocol": "tcp", "service_port": "22"}
	promAliasesServicesInfo.With(otherZone).Set(1)

	// Reload: service dns/udp and alias b removed.
	second := newRecursor(t, zone, recursorCfg{Aliases: map[string]aliasCfg{
		"a": {Ips: []string{"10.0.0.1"}, Services: []string{"https:443"}},
	}})
	updateInfoMetrics(zone, port, second)

	assert.Equal(t, 1, countSeries(t, promAliasesServicesInfo, zone, port), "only https/tcp left")
	assert.Equal(t, 1.0, testutil.ToFloat64(promAliasesServicesInfo.With(https)))
	assert.Equal(t, 1, countSeries(t, promAliasesInfo, zone, port), "alias b removed from aliases_info")
	assert.Equal(t, 1, countSeries(t, promAliasesServicesInfo, "other.", port), "other server block untouched")
}

// countSeries returns the number of series of the vector with the given zone and port labels.
func countSeries(t *testing.T, v *prometheus.GaugeVec, zone, port string) int {
	t.Helper()
	ch := make(chan prometheus.Metric, 1000)
	v.Collect(ch)
	close(ch)
	n := 0
	for m := range ch {
		pb := &dto.Metric{}
		require.NoError(t, m.Write(pb))
		labels := map[string]string{}
		for _, lp := range pb.GetLabel() {
			labels[lp.GetName()] = lp.GetValue()
		}
		if labels["zone"] == zone && labels["port"] == port {
			n++
		}
	}
	return n
}
