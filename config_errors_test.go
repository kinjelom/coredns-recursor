package recursor

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/coredns/caddy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConfig_controller_rejects_invalid_configs(t *testing.T) {
	cases := map[string]string{
		"unknown property":          "foo bar",
		"verbose not an int":        "verbose abc",
		"verbose without arg":       "verbose",
		"verbose with two args":     "verbose 1 2",
		"external-json missing":     "external-json /nonexistent/recursor.json",
		"external-yaml missing":     "external-yaml /nonexistent/recursor.yaml",
		"resolver unknown param":    "resolver r {\n urls udp://127.0.0.1:53\n bogus 1\n}",
		"resolver timeout not int":  "resolver r {\n urls udp://127.0.0.1:53\n timeout_ms fast\n}",
		"resolver timeout 2 args":   "resolver r {\n urls udp://127.0.0.1:53\n timeout_ms 1 2\n}",
		"resolver without name":     "resolver {\n urls udp://127.0.0.1:53\n}",
		"alias unknown param":       "alias a {\n ips 10.0.0.1\n bogus 1\n}",
		"alias ttl not int":         "alias a {\n ips 10.0.0.1\n ttl long\n}",
		"alias ttl 2 args":          "alias a {\n ips 10.0.0.1\n ttl 1 2\n}",
		"alias empty hosts":         "alias a {\n hosts\n}",
		"alias empty ips_transform": "alias a {\n ips 10.0.0.1\n ips_transform\n}",
		"alias shuffle_ips no arg":  "alias a {\n ips 10.0.0.1\n shuffle_ips\n}",
		"alias resolver_name 2":     "alias a {\n ips 10.0.0.1\n resolver_name a b\n}",
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			c := caddy.NewTestController("dns", pluginName+" {\n"+body+"\n}")
			_, err := readCaddyControllerConfig(c)
			assert.Error(t, err)
		})
	}
}

func TestConfig_controller_reads_all_alias_params(t *testing.T) {
	c := caddy.NewTestController("dns", pluginName+` {
		verbose 2
		resolver r {
			urls udp://127.0.0.1:53 tcp://127.0.0.2:53
			timeout_ms 250
		}
		alias a {
			hosts h1.test h2.test
			ips 10.0.0.1 2001:db8::1
			shuffle_ips true
			ips_transform prefer_ipv4 limit_1
			ttl 42
			resolver_name r
		}
		alias b {
			ips 10.0.0.2
			shuffle_ips false
		}
	}`)
	cfg, err := readCaddyControllerConfig(c)
	require.NoError(t, err)
	assert.Equal(t, 2, cfg.Verbose)
	assert.Equal(t, resolverCfg{Urls: []string{"udp://127.0.0.1:53", "tcp://127.0.0.2:53"}, TimeoutMs: 250}, cfg.Resolvers["r"])
	assert.Equal(t, aliasCfg{
		Hosts:        []string{"h1.test", "h2.test"},
		Ips:          []string{"10.0.0.1", "2001:db8::1"},
		ShuffleIps:   true,
		IpsTransform: []string{"prefer_ipv4", "limit_1"},
		Ttl:          42,
		ResolverName: "r",
	}, cfg.Aliases["a"])
	assert.False(t, cfg.Aliases["b"].ShuffleIps)
	assert.Equal(t, defaultResolverName, cfg.Aliases["b"].ResolverName, "inline alias defaults to the default resolver")
}

func TestConfig_rejects_malformed_json_and_yaml(t *testing.T) {
	_, err := readJsonConfig([]byte(`{"aliases": [}`))
	assert.Error(t, err)
	_, err = readJsonConfig([]byte(`{"verbose": "high"}`))
	assert.Error(t, err, "wrong field type")
	_, err = readYamlConfig([]byte("aliases: [unclosed"))
	assert.Error(t, err)
	_, err = readYamlConfig([]byte("aliases:\n  a:\n    ttl: -5\n"))
	assert.Error(t, err, "negative ttl does not fit uint32")
}

func TestConfig_external_file_parse_errors_are_reported(t *testing.T) {
	dir := t.TempDir()
	badJson := filepath.Join(dir, "bad.json")
	badYaml := filepath.Join(dir, "bad.yaml")
	require.NoError(t, os.WriteFile(badJson, []byte("{"), 0o600))
	require.NoError(t, os.WriteFile(badYaml, []byte("aliases: [x"), 0o600))

	for _, body := range []string{"external-json " + badJson, "external-yaml " + badYaml} {
		c := caddy.NewTestController("dns", pluginName+" {\n"+body+"\n}")
		_, err := readCaddyControllerConfig(c)
		assert.ErrorContains(t, err, "parsing external", body)
	}
}

func TestConfig_json_and_yaml_alias_defaults_to_default_resolver(t *testing.T) {
	j, err := readJsonConfig([]byte(`{"aliases": {"a": {"ips": ["10.0.0.1"]}}}`))
	require.NoError(t, err)
	assert.Equal(t, defaultResolverName, j.Aliases["a"].ResolverName)

	y, err := readYamlConfig([]byte("aliases:\n  a:\n    ips: [10.0.0.1]\n"))
	require.NoError(t, err)
	assert.Equal(t, defaultResolverName, y.Aliases["a"].ResolverName)
}

func TestCreateRecursor_rejects_invalid_definitions(t *testing.T) {
	cases := map[string]recursorCfg{
		"invalid alias ip": {Aliases: map[string]aliasCfg{"a": {Ips: []string{"10.0.0.300"}}}},
		"hostname as ip":   {Aliases: map[string]aliasCfg{"a": {Ips: []string{"example.org"}}}},
		"unknown resolver": {Aliases: map[string]aliasCfg{"a": {Ips: []string{"10.0.0.1"}, ResolverName: "nope"}}},
		"empty alias":      {Aliases: map[string]aliasCfg{"a": {}}},
		"resolver no urls": {Resolvers: map[string]resolverCfg{"r": {}}},
		"bad resolver url": {Resolvers: map[string]resolverCfg{"r": {Urls: []string{"127.0.0.1:53"}}}},
	}
	for name, cfg := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := createRecursor("svc", cfg)
			assert.Error(t, err)
		})
	}
}

func TestCreateRecursor_always_has_default_resolver(t *testing.T) {
	r, err := createRecursor("svc", recursorCfg{})
	require.NoError(t, err)
	def, ok := r.resolvers[defaultResolverName]
	require.True(t, ok)
	assert.Len(t, def.resolverRefs, 1)
	assert.Equal(t, "svc.", r.configZone, "zone is canonicalised")
}

func TestCreateRecursor_custom_default_resolver_overrides_system_one(t *testing.T) {
	r, err := createRecursor("svc", recursorCfg{
		Resolvers: map[string]resolverCfg{defaultResolverName: {Urls: []string{"udp://127.0.0.1:5353"}}},
		Aliases:   map[string]aliasCfg{"a": {Hosts: []string{"h.test"}}},
	})
	require.NoError(t, err)
	assert.Equal(t, []string{"udp://127.0.0.1:5353"}, r.aliases["a"].resolverDefRef.urls)
}

func TestSetup_registers_plugin_and_sets_next(t *testing.T) {
	c := caddy.NewTestController("dns", pluginName+" {\n alias a {\n  ips 10.0.0.1\n }\n}")
	require.NoError(t, setup(c))
}

func TestRecursorCfg_String_lists_resolvers_and_aliases(t *testing.T) {
	s := recursorCfg{
		Verbose:   1,
		Resolvers: map[string]resolverCfg{"res1": {Urls: []string{"udp://127.0.0.1:53"}}},
		Aliases:   map[string]aliasCfg{"alias1": {Ips: []string{"10.0.0.1"}}},
	}.String()
	assert.Contains(t, s, "resolvers: {map[res1:")
	assert.Contains(t, s, "aliases: {map[alias1:")
}
