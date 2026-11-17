package recursor

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/coredns/caddy"
	"gopkg.in/yaml.v3"
)

type recursorCfg struct {
	Verbose int `json:"verbose" yaml:"verbose"`
	// ClientIpMetrics adds the client_ip label value to the query metrics; nil means true.
	ClientIpMetrics *bool                  `json:"client_ip_metrics" yaml:"client_ip_metrics"`
	Resolvers       map[string]resolverCfg `json:"resolvers" yaml:"resolvers"`
	Aliases         map[string]aliasCfg    `json:"aliases" yaml:"aliases"`
}

func (rcu recursorCfg) String() string {
	clientIpMetrics := "default"
	if rcu.ClientIpMetrics != nil {
		clientIpMetrics = strconv.FormatBool(*rcu.ClientIpMetrics)
	}
	return fmt.Sprintf("{verbose: %v, client_ip_metrics: %s, resolvers: {%v}, aliases: {%v}}", rcu.Verbose, clientIpMetrics, rcu.Resolvers, rcu.Aliases)
}

type aliasCfg struct {
	Hosts        []string `json:"hosts" yaml:"hosts"`
	Ips          []string `json:"ips" yaml:"ips"`
	ShuffleIps   bool     `json:"shuffle_ips" yaml:"shuffle_ips"`
	IpsTransform []string `json:"ips_transform" yaml:"ips_transform"`
	Services     []string `json:"services" yaml:"services"`
	Ttl          uint32   `json:"ttl" yaml:"ttl"`
	ResolverName string   `json:"resolver_name" yaml:"resolver_name"`
}

func (c aliasCfg) String() string {
	return fmt.Sprintf("{hosts: %v, ips: %v, services: %v, ttl: %v, resolverName: %s}", c.Hosts, c.Ips, c.Services, c.Ttl, c.ResolverName)
}

type resolverCfg struct {
	Urls      []string `json:"urls" yaml:"urls"`
	TimeoutMs int      `json:"timeout_ms" yaml:"timeout_ms"`
}

func (c resolverCfg) String() string {
	return fmt.Sprintf("{urls: %v, timeoutMs: %d}", c.Urls, c.TimeoutMs)
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
			filePath := configFilePath(c.File(), args[0])
			fileBytes, err := os.ReadFile(filePath)
			if err != nil {
				return recursorCfg{}, fmt.Errorf("reading external-json file %s error, %w", filePath, err)
			}
			rcu, err = readJsonConfig(fileBytes)
			if err != nil {
				return recursorCfg{}, fmt.Errorf("parsing external-json file %s error, %w", filePath, err)
			}
		case "external-yaml":
			filePath := configFilePath(c.File(), args[0])
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
		case "client_ip_metrics":
			v, err := parseBool("client_ip_metrics", args[0])
			if err != nil {
				return recursorCfg{}, err
			}
			rcu.ClientIpMetrics = &v
		case "resolver":
			name := args[0]
			c.NextLine()
			rsl, err := readResolverCfg(c)
			if err != nil {
				return rcu, fmt.Errorf("parsing resolver '%s' error %w", name, err)
			}
			rcu.Resolvers[name] = rsl
		case "alias":
			name := strings.TrimSpace(args[0])
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

// configFilePath resolves a relative external config path against the Corefile's directory,
// like CoreDNS `import`. If the file isn't there, the path is used as given (relative to the
// CoreDNS working directory), as in versions before 1.5.0.
func configFilePath(corefile, path string) string {
	if filepath.IsAbs(path) || corefile == "" {
		return path
	}
	candidate := filepath.Join(filepath.Dir(corefile), path)
	if _, err := os.Stat(candidate); err == nil {
		return candidate
	}
	return path
}

// parseBool accepts only true or false, so typos like `yes` fail instead of meaning false.
func parseBool(name, value string) (bool, error) {
	switch strings.TrimSpace(value) {
	case "true":
		return true, nil
	case "false":
		return false, nil
	}
	return false, fmt.Errorf("'%s' must be true or false, got '%s'", name, value)
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
	dec := json.NewDecoder(bytes.NewReader(jsonBytes))
	dec.DisallowUnknownFields() // typos in keys fail instead of being ignored
	err := dec.Decode(&r)
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
	dec := yaml.NewDecoder(bytes.NewReader(yamlBytes))
	dec.KnownFields(true) // typos in keys fail instead of being ignored
	err := dec.Decode(&r)
	if err != nil && err != io.EOF {
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
			v, err := parseBool("shuffle_ips", args[0])
			if err != nil {
				return cfg, err
			}
			cfg.ShuffleIps = v
		case "ips_transform":
			if len(args) < 1 {
				return cfg, fmt.Errorf("empty `ips_transform` list")
			}
			cfg.IpsTransform = args
		case "services":
			if len(args) < 1 {
				return cfg, fmt.Errorf("empty services list")
			}
			// may be repeated to split long lists over several lines
			cfg.Services = append(cfg.Services, args...)
		case "resolver_name":
			if len(args) != 1 {
				return cfg, fmt.Errorf("wrong 'resolver_name' definition")
			}
			cfg.ResolverName = strings.TrimSpace(args[0])
		case "ttl":
			if len(args) != 1 {
				return cfg, fmt.Errorf("wrong 'ttl' definition")
			}
			val, err := strconv.ParseUint(strings.TrimSpace(args[0]), 10, 32)
			if err != nil {
				return cfg, fmt.Errorf("ttl must be a number in range 0-%d, got '%s'", maxTTL, args[0])
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
