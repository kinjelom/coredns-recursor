package recursor

import (
	"github.com/stretchr/testify/assert"
	"os"
	"testing"

	"github.com/coredns/caddy"
)

// Tests the various setups

func TestSetup_controller_should_work_with_full_example_config(t *testing.T) {
	filePath := "examples/config1.caddy"
	fileBytes, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatalf("read config file %s error, %v", filePath, err)
	}
	c := caddy.NewTestController("dns", string(fileBytes))
	if err := setup(c); err != nil {
		t.Fatalf("Expected no errors, but got: %v", err)
	}
}

func TestSetup_controller_should_work_with_minimal_config(t *testing.T) {
	c := caddy.NewTestController("dns", pluginName+" ")
	assert.Nil(t, setup(c), "empty config")

	c = caddy.NewTestController("dns", pluginName+" {\n}")
	assert.Nil(t, setup(c), "empty config")

	c = caddy.NewTestController("dns", pluginName+" {\nverbose 0\n}")
	assert.Nil(t, setup(c), "empty config")
}

func TestSetup_controller_should_fail_with_incorrect_config(t *testing.T) {
	c := caddy.NewTestController("dns", pluginName+` {
		resolver incorrect {
        }
	}`)
	assert.Error(t, setup(c), "incorrect resolver config")

	c = caddy.NewTestController("dns", pluginName+` {
		resolver incorrect {
			urls
        }
	}`)
	assert.Error(t, setup(c), "incorrect resolver config")

	c = caddy.NewTestController("dns", pluginName+` {
		alias incorrect {
        }
	}`)
	assert.Error(t, setup(c), "incorrect alias config")

	c = caddy.NewTestController("dns", pluginName+` {
		alias incorrect {
			ips
        }
	}`)
	assert.Error(t, setup(c), "wrong alias config")
}

func TestSetup_controller_should_work_with_wildcard_config(t *testing.T) {
	c := caddy.NewTestController("dns", pluginName+` {
		alias * {
        }
	}`)
	assert.Nil(t, setup(c), "wildcard aliases don't need hosts or ips")

	c = caddy.NewTestController("dns", pluginName+` {
		alias * {
			ips 1.1.1.1
			hosts www.example.org
        }
	}`)
	assert.Nil(t, setup(c), "wildcard aliases accept hosts and ips")

	c = caddy.NewTestController("dns", pluginName+` {
		alias not-wildcard {
        }
	}`)
	assert.Error(t, setup(c), "not-wildcard aliases should have ips or hosts defined")
}
