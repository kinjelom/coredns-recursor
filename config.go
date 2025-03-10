package recursor

import (
	"encoding/json"
	"fmt"
	"github.com/coredns/caddy"
	"gopkg.in/yaml.v3"
	"os"
	"strconv"
	"strings"
)

type recursorCfg struct {
	Verbose   int                    `json:"verbose" yaml:"verbose"`
	Resolvers map[string]resolverCfg `json:"resolvers" yaml:"resolvers"`
	Aliases   map[string]aliasCfg    `json:"aliases" yaml:"aliases"`
}

func (rcu recursorCfg) String() string {
	return fmt.Sprintf("{verbose: %v, resolvers: {%v}, aliases: {%v}}", rcu.Verbose, rcu.Resolvers, rcu.Resolvers)
}

type aliasCfg struct {
	Hosts        []string `json:"hosts" yaml:"hosts"`
	Ips          []string `json:"ips" yaml:"ips"`
	ShuffleIps   bool     `json:"shuffle_ips" yaml:"shuffle_ips"`
	Ttl          uint32   `json:"ttl" yaml:"ttl"`
	ResolverName string   `json:"resolver_name" yaml:"resolver_name"`
}

func (c aliasCfg) String() string {
	return fmt.Sprintf("{hosts: [%s], ips: [%s], ttl: %v, resolverName: %s}", c.Hosts, c.Ips, c.Ttl, c.ResolverName)
}

type resolverCfg struct {
	Urls      []string `json:"urls" yaml:"urls"`
	TimeoutMs int      `json:"timeout_ms" yaml:"timeout_ms"`
}

func (c resolverCfg) String() string {
	return fmt.Sprintf("{urls: [%v], timeoutMs: %d}", c.Urls, c.TimeoutMs)
}

func readCaddyControllerConfig(c *caddy.Controller) (recursorCfg, error) {
	rcu := recursorCfg{
		Aliases:   map[string]aliasCfg{},
		Resolvers: map[string]resolverCfg{},
	}
	rcu.Verbose = 0
	c.Next() // omit plugin name
	c.Next() // omit "{"
mainLoop:
	for c.Next() {
		segmentName := strings.TrimSpace(c.Val())
		if segmentName == "}" {
			break mainLoop
		}
		args := c.RemainingArgs()
		if len(args) != 1 {
			return rcu, fmt.Errorf("invalid block %s arguments count, should be %d: %q", segmentName, 1, args)
		}
		switch segmentName {
		case "external-json":
			filePath := args[0]
			fileBytes, err := os.ReadFile(filePath)
			if err != nil {
				return recursorCfg{}, fmt.Errorf("reading external-json file %s error, %w", filePath, err)
			}
			rcu, err = readJsonConfig(fileBytes)
			if err != nil {
				return recursorCfg{}, fmt.Errorf("parsing external-json file %s error, %w", filePath, err)
			}
		case "external-yaml":
			filePath := args[0]
			fileBytes, err := os.ReadFile(filePath)
			if err != nil {
				return recursorCfg{}, fmt.Errorf("reading external-yaml file %s (work-dir %s) error, %w", filePath, getWorkDirInfo(), err)
			}
			rcu, err = readYamlConfig(fileBytes)
			if err != nil {
				return recursorCfg{}, fmt.Errorf("parsing external-yaml file %s (work-dir %s) error, %w", filePath, getWorkDirInfo(), err)
			}
		case "verbose":
			v, err := strconv.Atoi(strings.TrimSpace(args[0]))
			if err != nil {
				return recursorCfg{}, fmt.Errorf("parsing verbose error, %w", err)
			}
			rcu.Verbose = v
		case "resolver":
			name := args[0]
			c.NextLine()
			rsl, err := readResolverCfg(c)
			if err != nil {
				return rcu, fmt.Errorf("parsing resolver '%s' error %w", name, err)
			}
			rcu.Resolvers[name] = rsl
		case "alias":
			name := strings.TrimSpace(args[0]) //TODO? dns.Fqdn()
			c.NextLine()
			ali, err := readAliasCfg(c)
			if err != nil {
				return rcu, fmt.Errorf("parsing alias '%s' error %w", name, err)
			}
			rcu.Aliases[name] = ali
		default:
			return rcu, fmt.Errorf("unknown property '%s'", c.Val())
		}
	}
	return rcu, nil
}

func getWorkDirInfo() string {
	path, err := os.Getwd()
	if err != nil {
		return "error: " + err.Error()
	}
	return path
}
func normalizeConfig(rcu *recursorCfg) {
	for a, cfg := range rcu.Aliases {
		if len(cfg.ResolverName) == 0 {
			cfg.ResolverName = defaultResolverName
			rcu.Aliases[a] = cfg
		}
	}
}
func readJsonConfig(jsonBytes []byte) (recursorCfg, error) {
	r := recursorCfg{
		Verbose:   0,
		Aliases:   map[string]aliasCfg{},
		Resolvers: map[string]resolverCfg{},
	}
	err := json.Unmarshal(jsonBytes, &r)
	if err != nil {
		return r, fmt.Errorf("unmarshal JSON config error: %w", err)
	}
	normalizeConfig(&r)
	return r, nil
}

func readYamlConfig(yamlBytes []byte) (recursorCfg, error) {
	r := recursorCfg{
		Verbose:   0,
		Aliases:   map[string]aliasCfg{},
		Resolvers: map[string]resolverCfg{},
	}
	err := yaml.Unmarshal(yamlBytes, &r)
	if err != nil {
		return r, fmt.Errorf("unmarshal YAML config error: %w", err)
	}
	normalizeConfig(&r)
	return r, nil
}

func readAliasCfg(c *caddy.Controller) (aliasCfg, error) {
	cfg := aliasCfg{
		ResolverName: defaultResolverName,
	}
	for c.NextBlock() {
		paramName := strings.TrimSpace(c.Val())
		args := c.RemainingArgs()
		switch paramName {
		case "ips":
			if len(args) < 1 {
				return cfg, fmt.Errorf("empty ips list")
			}
			cfg.Ips = args
		case "hosts":
			if len(args) < 1 {
				return cfg, fmt.Errorf("empty hosts list")
			}
			cfg.Hosts = args
		case "shuffle_ips":
			if len(args) != 1 {
				return cfg, fmt.Errorf("wrong 'shuffle_ips' definition")
			}
			cfg.ShuffleIps = args[0] == "true"
		case "resolver_name":
			if len(args) != 1 {
				return cfg, fmt.Errorf("wrong 'resolver_name' definition")
			}
			cfg.ResolverName = strings.TrimSpace(args[0])
		case "ttl":
			if len(args) != 1 {
				return cfg, fmt.Errorf("wrong 'ttl' definition")
			}
			val, err := strconv.Atoi(strings.TrimSpace(args[0]))
			if err != nil {
				return cfg, fmt.Errorf("ttl isn't an integer '%s'", args[0])
			}
			cfg.Ttl = uint32(val)
		default:
			return cfg, fmt.Errorf("unknown param name '%s'", paramName)
		}
	}
	return cfg, nil
}

func readResolverCfg(c *caddy.Controller) (resolverCfg, error) {
	cfg := resolverCfg{}
	for c.NextBlock() {
		paramName := strings.TrimSpace(c.Val())
		args := c.RemainingArgs()
		switch paramName {
		case "timeout_ms":
			if len(args) != 1 {
				return cfg, fmt.Errorf("wrong 'timeout_ms' definition")
			}
			val, err := strconv.Atoi(strings.TrimSpace(args[0]))
			if err != nil {
				return cfg, fmt.Errorf("timeout_ms isn't an integer '%s'", args[0])
			}
			cfg.TimeoutMs = val
		case "urls":
			if len(args) < 1 {
				return cfg, fmt.Errorf("wrong 'urls' definition")
			}
			cfg.Urls = args
		default:
			return cfg, fmt.Errorf("unknown param name '%s'", paramName)
		}
	}
	return cfg, nil
}
