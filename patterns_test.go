package recursor

import (
	"testing"

	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAliasPattern_match(t *testing.T) {
	p, err := parseAliasPattern("*-x")
	require.NoError(t, err)
	for in, want := range map[string]bool{
		"foo-x":     true,
		"a-b-x":     true,
		"-x":        false, // `*` matches at least one character
		"foo-y":     false,
		"a.foo-x":   false, // `*` doesn't cross labels
		"foo-x.eu":  false,
		"foo-xx":    false,
		"x":         false,
		"foo-x-bar": false,
	} {
		assert.Equal(t, want, p.match(in), in)
	}

	p, err = parseAliasPattern("api-*.eu")
	require.NoError(t, err)
	assert.True(t, p.match("api-1.eu"))
	assert.False(t, p.match("api-1.us"))
	assert.False(t, p.match("api-a.b.eu"))

	p, err = parseAliasPattern("*.dev")
	require.NoError(t, err)
	assert.True(t, p.match("web.dev"))
	assert.False(t, p.match("a.web.dev"), "a whole-label `*` still matches one label only")
}

func TestAliasPattern_invalid(t *testing.T) {
	for _, name := range []string{"*-*", "a**", ".*-x", "*-x.", "a..*"} {
		_, err := parseAliasPattern(name)
		assert.Error(t, err, name)
	}
}

func TestAliasPattern_precedence_does_not_depend_on_config_order(t *testing.T) {
	patterns := []aliasPattern{}
	for _, n := range []string{"*", "a*", "abc*", "*-x", "web-*", "*b-x", "web-*-x"} {
		if isAliasPattern(n) {
			p, err := parseAliasPattern(n)
			require.NoError(t, err)
			patterns = append(patterns, p)
		}
	}
	sortAliasPatterns(patterns)
	var names []string
	for _, p := range patterns {
		names = append(names, p.name)
	}
	// most literal characters first; with the same count the longer suffix wins (`*b-x` before `abc*`)
	assert.Equal(t, []string{"web-*-x", "web-*", "*b-x", "abc*", "*-x", "a*"}, names)
}

func patternRecursor(t *testing.T) recursor {
	t.Helper()
	return newRecursor(t, "in", recursorCfg{
		Aliases: map[string]aliasCfg{
			"api-x":   {Ips: []string{"10.0.0.1"}},
			"*-x":     {Ips: []string{"10.0.0.50"}, Ttl: 30},
			"web-*-x": {Ips: []string{"10.0.0.60"}},
			"web-*":   {Ips: []string{"10.0.0.70"}},
			"*":       {Ips: []string{"10.9.9.9"}},
		},
	})
}

func TestHermetic_pattern_alias_precedence(t *testing.T) {
	r := patternRecursor(t)
	for q, want := range map[string]string{
		"api-x.in.":     "10.0.0.1",  // exact alias wins over patterns
		"foo-x.in.":     "10.0.0.50", // `*-x`
		"FOO-X.in.":     "10.0.0.50", // case-insensitive
		"web-1-x.in.":   "10.0.0.60", // `web-*-x` is more specific than `*-x` and `web-*`
		"web-1.in.":     "10.0.0.70", // `web-*`
		"web-x.in.":     "10.0.0.70", // matches `web-*` (4 literal characters) and `*-x` (2): `web-*` wins
		"a.foo-x.in.":   "10.9.9.9",  // `*` in a pattern doesn't cross labels, so the `*` alias answers
		"something.in.": "10.9.9.9",
	} {
		s := serve(r, q, dns.TypeA)
		require.NoError(t, s.err, q)
		assert.Equal(t, []string{want}, s.ips, q)
	}
}

func TestHermetic_pattern_alias_without_ips_resolves_query_name(t *testing.T) {
	up := startFakeDNS(t, map[string][]string{"foo-x.in": {"192.0.2.40"}})
	r := newRecursor(t, "in", recursorCfg{
		Resolvers: map[string]resolverCfg{"up": {Urls: []string{up.url}, TimeoutMs: 500}},
		Aliases:   map[string]aliasCfg{"*-x": {ResolverName: "up"}},
	})
	s := serve(r, "foo-x.in.", dns.TypeA)
	require.NoError(t, s.err)
	assert.Equal(t, []string{"192.0.2.40"}, s.ips)
	assert.True(t, up.asked("foo-x.in."))
}

func TestHermetic_pattern_alias_metric_label_is_the_pattern(t *testing.T) {
	r := newRecursor(t, "pattern.svc", recursorCfg{Aliases: map[string]aliasCfg{"*-x": {Ips: []string{"10.0.0.50"}}}})
	labels := prometheus.Labels{"port": "53", "zone": "pattern.svc.", "alias": "*-x", "resolver": "default", "client_ip": "10.240.0.1"}
	before := testutil.ToFloat64(promQueryServedCountTotal.With(labels))
	serve(r, "random1-x.pattern.svc.", dns.TypeA)
	serve(r, "random2-x.pattern.svc.", dns.TypeA)
	assert.Equal(t, before+2, testutil.ToFloat64(promQueryServedCountTotal.With(labels)))
}

func TestCreateRecursor_pattern_validation(t *testing.T) {
	_, err := createRecursor("in", recursorCfg{Aliases: map[string]aliasCfg{"*-*": {Ips: []string{"10.0.0.1"}}}})
	assert.ErrorContains(t, err, "only one '*'")
	_, err = createRecursor("in", recursorCfg{Aliases: map[string]aliasCfg{"*-x": {Ips: []string{"10.0.0.1"}, Services: []string{"https:443"}}}})
	assert.ErrorContains(t, err, "can't define services")
	_, err = createRecursor("in", recursorCfg{Aliases: map[string]aliasCfg{"*-x": {}}})
	assert.NoError(t, err, "a pattern without ips and hosts resolves the query name, like `*`")
}

func TestHermetic_pattern_alias_tie_longer_suffix_wins(t *testing.T) {
	// `ab-x` matches both patterns, each with 3 characters other than `*`: the longer suffix wins.
	r := newRecursor(t, "in", recursorCfg{
		Aliases: map[string]aliasCfg{
			"ab-*": {Ips: []string{"10.0.0.1"}},
			"*b-x": {Ips: []string{"10.0.0.2"}},
		},
	})
	s := serve(r, "ab-x.in.", dns.TypeA)
	require.NoError(t, s.err)
	assert.Equal(t, []string{"10.0.0.2"}, s.ips)
	assert.Equal(t, []string{"10.0.0.1"}, serve(r, "ab-y.in.", dns.TypeA).ips, "only `ab-*` matches")
}
