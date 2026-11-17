package recursor

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The README shows examples/demo.caddy inline and links the YAML/JSON equivalents,
// so all of them must describe exactly the same configuration.
func TestExamples_demo_formats_are_equivalent(t *testing.T) {
	caddyCfg, err := loadCaddyControllerConfig(t, "examples/demo.caddy")
	require.NoError(t, err)

	yamlBytes, err := os.ReadFile("examples/demo.yaml")
	require.NoError(t, err)
	yamlCfg, err := readYamlConfig(yamlBytes)
	require.NoError(t, err)

	jsonBytes, err := os.ReadFile("examples/demo.json")
	require.NoError(t, err)
	jsonCfg, err := readJsonConfig(jsonBytes)
	require.NoError(t, err)

	assert.Equal(t, caddyCfg, yamlCfg, "demo.yaml differs from demo.caddy")
	assert.Equal(t, caddyCfg, jsonCfg, "demo.json differs from demo.caddy")

	for _, ref := range []string{"examples/demo-yaml.caddy", "examples/demo-json.caddy"} {
		refCfg, err := loadCaddyControllerConfig(t, ref)
		require.NoError(t, err, ref)
		assert.Equal(t, caddyCfg, refCfg, ref)
	}

	_, err = createRecursor("demo.svc", caddyCfg)
	require.NoError(t, err, "demo config must be valid")
}

func TestExamples_readme_shows_demo_corefile(t *testing.T) {
	readme, err := os.ReadFile("README.md")
	require.NoError(t, err)
	demo, err := os.ReadFile("examples/demo.caddy")
	require.NoError(t, err)
	assert.True(t, strings.Contains(string(readme), string(demo)),
		"README must contain examples/demo.caddy verbatim; update one of them")
}
