package recursor

import (
	"os"
	"testing"

	"github.com/coredns/caddy"
	"github.com/stretchr/testify/assert"
)

// Tests the various configs that should be parsed

func TestConfig_should_parse_json(t *testing.T) {
	filePath := "examples/config1.json"
	fileBytes, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatalf("read config file %s error, %v", filePath, err)
	}
	rcu, err := readJsonConfig(fileBytes)
	checkRcu(t, err, rcu)
}

func TestConfig_should_parse_yaml(t *testing.T) {
	filePath := "examples/config1.yaml"
	fileBytes, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatalf("read config file %s error, %v", filePath, err)
	}
	rcu, err := readYamlConfig(fileBytes)
	checkRcu(t, err, rcu)
}

func TestConfig_controller_should_read_external_json(t *testing.T) {
	rcu, err := loadCaddyControllerConfig(t, "examples/config-with-json-ref1.caddy")
	checkRcu(t, err, rcu)
}

func TestConfig_controller_should_read_external_yaml(t *testing.T) {
	rcu, err := loadCaddyControllerConfig(t, "examples/config-with-yaml-ref1.caddy")
	checkRcu(t, err, rcu)
}

func TestConfig_controller_should_read_inline_caddy(t *testing.T) {
	rcu, err := loadCaddyControllerConfig(t, "examples/config1.caddy")
	checkRcu(t, err, rcu)
	rcu, err = loadCaddyControllerConfig(t, "examples/config2.caddy")
	assert.Nil(t, err)
	_, found := rcu.Aliases["*"]
	assert.True(t, found)
	rcu, err = loadCaddyControllerConfig(t, "examples/config3.caddy")
	assert.Nil(t, err)
	_, found = rcu.Aliases["*"]
	assert.True(t, found)
	rcu, err = loadCaddyControllerConfig(t, "examples/config3.caddy")
	assert.Nil(t, err)
	_, found = rcu.Aliases["x"]
	assert.False(t, found)
}

func loadCaddyControllerConfig(t *testing.T, filePath string) (recursorCfg, error) {
	fileBytes, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatalf("read config file %s error, %v", filePath, err)
	}
	c := caddy.NewTestController("dns", string(fileBytes))
	return readCaddyControllerConfig(c)
}

func checkRcu(t *testing.T, err error, rcu recursorCfg) {
	if err != nil {
		t.Fatalf("expected no errors, but got: %v", err)
	}
	assert.Equal(t, 0, rcu.Verbose, "verbose")

	// resolvers
	assert.Equal(t, 2, len(rcu.Resolvers), "resolvers len")
	rsl := rcu.Resolvers["resolver_primary"]
	assert.Equal(t, 2, len(rsl.Urls), "resolver_primary urls len")
	assert.Equal(t, "udp://10.0.0.1:53", rsl.Urls[0], "resolver_primary url[0]")
	assert.Equal(t, "udp://10.0.0.2:53", rsl.Urls[1], "resolver_primary url[1]")
	assert.Equal(t, 10, rsl.TimeoutMs, "resolver_primary timeout")

	rsl = rcu.Resolvers["resolver_secondary"]
	assert.Equal(t, 1, len(rsl.Urls), "resolver_secondary urls len")
	assert.Equal(t, "udp://10.0.0.3:53", rsl.Urls[0], "resolver_secondary url[0]")
	assert.Equal(t, 0, rsl.TimeoutMs, "resolver_secondary timeout")

	// aliases
	assert.Equal(t, 3, len(rcu.Aliases), "aliases len")
	a := rcu.Aliases["alias1"]
	assert.Equal(t, 2, len(a.Ips), "alias1 ips len")
	assert.Equal(t, "10.1.1.1", a.Ips[0], "alias1 ips[0]")
	assert.Equal(t, "10.1.1.2", a.Ips[1], "alias1 ips[1]")
	assert.Equal(t, 2, len(a.Hosts), "alias1 hosts len")
	assert.Equal(t, "www.example.org", a.Hosts[0], "alias1 hosts[0]")
	assert.Equal(t, "www.example.com", a.Hosts[1], "alias1 hosts[1]")
	assert.Equal(t, []string{"shuffle", "first"}, a.IpsTransform, "alias1 has shuffle,first transform")
	assert.Equal(t, uint32(5), a.Ttl, "alias1 ttl")
	assert.Equal(t, "resolver_primary", a.ResolverName, "alias1 resolverName")

	a = rcu.Aliases["alias2"]
	assert.Equal(t, 2, len(a.Ips), "alias2 ips len")
	assert.Equal(t, "10.1.1.1", a.Ips[0], "alias2 ips[0]")
	assert.Equal(t, "10.1.1.2", a.Ips[1], "alias2 ips[1]")
	assert.Equal(t, 0, len(a.Hosts), "alias2 hosts len")
	assert.Empty(t, a.IpsTransform, "alias2 without ips transform")
	assert.Equal(t, uint32(0), a.Ttl, "alias2 ttl")
	assert.Equal(t, "default", a.ResolverName, "alias2 resolverName")

	a = rcu.Aliases["alias3"]
	assert.Equal(t, 0, len(a.Ips), "alias3 ips len")
	assert.Equal(t, 2, len(a.Hosts), "alias3 hosts len")
	assert.Equal(t, "www.example.org", a.Hosts[0], "alias3 hosts[0]")
	assert.Equal(t, "www.example.com", a.Hosts[1], "alias3 hosts[1]")
	assert.Empty(t, []string{}, "alias3 without ips transform")
	assert.Equal(t, uint32(15), a.Ttl, "alias3 ttl")
	assert.Equal(t, "resolver_secondary", a.ResolverName, "alias3 resolverName")

}
