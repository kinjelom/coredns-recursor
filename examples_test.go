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

// The README shows examples/patterns.caddy inline with a table of the names it answers.
func TestExamples_patterns(t *testing.T) {
	readme, err := os.ReadFile("README.md")
	require.NoError(t, err)
	example, err := os.ReadFile("examples/patterns.caddy")
	require.NoError(t, err)
	assert.True(t, strings.Contains(string(readme), string(example)),
		"README must contain examples/patterns.caddy verbatim; update one of them")

	cfg, err := loadCaddyControllerConfig(t, "examples/patterns.caddy")
	require.NoError(t, err)
	r, err := createRecursor("in", cfg)
	require.NoError(t, err)
	for q, want := range map[string]string{
		"api-x.in.":   "api-x",
		"foo-x.in.":   "*-x",
		"web-1.in.":   "web-*",
		"web-x.in.":   "web-*",
		"foo-x.eu.in": "*-x.eu",
		"-x.in.":      "*",
		"a.foo-x.in.": "*",
	} {
		alias := strings.TrimSuffix(strings.TrimSuffix(q, "."), ".in")
		_, name, found, _ := r.findAlias(alias)
		assert.True(t, found, q)
		assert.Equal(t, want, name, q)
	}
}
