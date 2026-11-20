package recursor

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
)

// init registers this plugin.
func init() { plugin.Register(pluginName, setup) }

func setup(c *caddy.Controller) error {
	cfg := dnsserver.GetConfig(c)
	log.Infof("Setup plugin %s/%s, zone: %s, port: %s", pluginName, pluginVersion, cfg.Zone, cfg.Port)
	rcuCfg, err := readCaddyControllerConfig(c)
	if err != nil {
		return plugin.Error(pluginName, fmt.Errorf("%s/%s read config error: %w", pluginName, pluginVersion, err))
	}
	rcu, err := createRecursor(cfg.Zone, rcuCfg)
	if err != nil {
		return plugin.Error(pluginName, fmt.Errorf("%s/%s create recursor error: %w", pluginName, pluginVersion, err))
	}
	updateInfoMetrics(cfg.Zone, cfg.Port, rcu)
	if rcu.verbose > 1 {
		log.Infof("Plugin %s/%s created (zone '%s', port %s): %s", pluginName, pluginVersion, cfg.Zone, cfg.Port, rcu.String())
	}
	cfg.AddPlugin(func(next plugin.Handler) plugin.Handler {
		rcu.Next = next
		if rcu.verbose > 0 {
			log.Infof("Plugin %s/%s added (zone '%s', port %s)", pluginName, pluginVersion, cfg.Zone, cfg.Port)
		}
		return rcu
	})
	return nil
}

func updateInfoMetrics(zone, port string, rcu recursor) {
	promBuildInfo.With(prometheus.Labels{"version": pluginVersion}).Set(1)
	// Drop series of this server block left from a previous config (CoreDNS reload runs setup again
	// in the same process), so removed resolvers, aliases and services disappear from the catalog.
	serverBlock := prometheus.Labels{"zone": zone, "port": port}
	promResolvesInfo.DeletePartialMatch(serverBlock)
	promAliasesInfo.DeletePartialMatch(serverBlock)
	promAliasesEntriesInfo.DeletePartialMatch(serverBlock)
	promAliasesServicesInfo.DeletePartialMatch(serverBlock)
	for name, def := range rcu.resolvers {
		promResolvesInfo.With(prometheus.Labels{"zone": zone, "port": port, "resolver": name, "urls": strings.Join(def.urls, ",")}).Set(1)
	}
	for name, def := range rcu.aliases {
		promAliasesInfo.With(prometheus.Labels{"zone": zone, "port": port, "alias": name, "resolver": def.resolverDefRef.name, "ttl": strconv.Itoa(int(def.ttl))}).Set(1)
		for _, host := range def.hosts {
			promAliasesEntriesInfo.With(prometheus.Labels{"zone": zone, "port": port, "alias": name, "resolver": def.resolverDefRef.name, "type": "host", "entry": host}).Set(1)
		}
		for _, ip := range def.ips {
			promAliasesEntriesInfo.With(prometheus.Labels{"zone": zone, "port": port, "alias": name, "resolver": def.resolverDefRef.name, "type": "ip", "entry": ip.String()}).Set(1)
		}
		for _, s := range def.services {
			promAliasesServicesInfo.With(prometheus.Labels{"zone": zone, "port": port, "alias": name, "resolver": def.resolverDefRef.name,
				"service": s.name, "protocol": s.protocol, "service_port": strconv.Itoa(int(s.port))}).Set(1)
		}
	}
}

func createRecursor(configZone string, cfg recursorCfg) (recursor, error) {
	r := recursor{
		random:          newLockedRand(time.Now().UnixNano()),
		configZone:      dns.CanonicalName(configZone),
		verbose:         cfg.Verbose,
		clientIpMetrics: cfg.ClientIpMetrics == nil || *cfg.ClientIpMetrics,
		soaSerial:       uint32(time.Now().Unix()),
		resolvers:       map[string]resolverDef{},
		aliases:         map[string]aliasDef{},
	}
	r.resolvers[defaultResolverName] = resolverDef{
		name:         defaultResolverName,
		resolverRefs: []*net.Resolver{net.DefaultResolver},
		urls:         []string{"://" + defaultResolverName},
		timeout:      defaultResolveTimeout,
	}
	for key, rslCfg := range cfg.Resolvers {
		rsl, err := createResolver(key, rslCfg)
		if err != nil {
			return r, fmt.Errorf("creating resolver '%s' error: %w, config: %s", key, err, rslCfg.String())
		}
		r.resolvers[key] = rsl
	}
	for key, aCfg := range cfg.Aliases {
		// Query names are matched lower-case, so alias names are too.
		name := strings.ToLower(key)
		if _, dup := r.aliases[name]; dup {
			return r, fmt.Errorf("duplicate alias '%s' (alias names are case-insensitive)", name)
		}
		a, err := createAlias(name, aCfg, r.resolvers)
		if err != nil {
			return r, fmt.Errorf("creating alias '%s' error: %w, config: %s", key, err, aCfg.String())
		}
		r.aliases[name] = a
		if isAliasPattern(name) {
			p, err := parseAliasPattern(name)
			if err != nil {
				return r, fmt.Errorf("creating alias '%s' error: %w", key, err)
			}
			r.patterns = append(r.patterns, p)
		}
	}
	sortAliasPatterns(r.patterns)
	return r, nil
}

func createResolver(name string, p resolverCfg) (resolverDef, error) {
	rslDef := resolverDef{
		name:    name,
		timeout: defaultResolveTimeout,
	}
	if p.TimeoutMs > 0 {
		rslDef.timeout = time.Duration(p.TimeoutMs) * time.Millisecond
	}
	if len(p.Urls) < 1 {
		return rslDef, fmt.Errorf("resolver URLs can't be empty")
	}
	for _, urlStr := range p.Urls {
		u, err := parseResolverURL(urlStr)
		if err != nil {
			return resolverDef{}, fmt.Errorf("invalid resolver URL '%s': %w", urlStr, err)
		}
		var resolverRef = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
				// The Go resolver asks for "udp" and retries truncated answers over "tcp",
				// so a udp:// upstream follows it; a tcp:// upstream always uses TCP.
				if u.Scheme == "tcp" {
					network = "tcp"
				}
				var d net.Dialer
				conn, err := d.DialContext(ctx, network, u.Host)
				if err != nil {
					return nil, err
				}
				// The Go resolver stops waiting for an answer only at the deadline, not when ctx is
				// cancelled (e.g. another URL answered first), so unblock the read on cancellation.
				context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Now()) })
				return conn, nil
			},
		}
		rslDef.resolverRefs = append(rslDef.resolverRefs, resolverRef)
		rslDef.urls = append(rslDef.urls, urlStr)
	}
	return rslDef, nil
}

// parseResolverURL validates a resolver URL: udp:// or tcp://, a host and a numeric port.
func parseResolverURL(urlStr string) (*url.URL, error) {
	u, err := url.Parse(urlStr)
	if err != nil {
		return nil, err
	}
	if u.Scheme != "udp" && u.Scheme != "tcp" {
		return nil, fmt.Errorf("scheme must be udp or tcp, e.g. udp://127.0.0.1:53")
	}
	host, port, err := net.SplitHostPort(u.Host)
	if err != nil {
		return nil, fmt.Errorf("expected host:port, e.g. udp://127.0.0.1:53: %w", err)
	}
	if host == "" {
		return nil, fmt.Errorf("missing host")
	}
	if p, err := strconv.ParseUint(port, 10, 16); err != nil || p == 0 {
		return nil, fmt.Errorf("port must be a number in range 1-65535, got '%s'", port)
	}
	return u, nil
}

func createAlias(aName string, aCfg aliasCfg, resolvers map[string]resolverDef) (aliasDef, error) {
	a := aliasDef{
		hosts:        aCfg.Hosts,
		shuffleIps:   aCfg.ShuffleIps,
		ipsTransform: aCfg.IpsTransform,
		ttl:          aCfg.Ttl,
	}
	for _, ip := range aCfg.Ips {
		addr := net.ParseIP(ip)
		if addr == nil {
			return a, fmt.Errorf("wrong alias ip '%s'", ip)
		}
		a.ips = append(a.ips, addr)
	}
	// `*` and patterns without ips and hosts resolve the original query name.
	wildcard := aName == "*" || isAliasPattern(aName)
	if !wildcard {
		if len(a.ips) == 0 && len(a.hosts) == 0 {
			return a, fmt.Errorf("alias ips and hosts are empty")
		}
	}
	if aCfg.Ttl > maxTTL {
		return a, fmt.Errorf("ttl %d is out of range 0-%d", aCfg.Ttl, maxTTL)
	}
	if err := validateIpsTransform(aCfg.IpsTransform); err != nil {
		return a, err
	}
	if wildcard && len(aCfg.Services) > 0 {
		return a, fmt.Errorf("the wildcard alias and alias patterns can't define services")
	}
	seen := map[string]bool{}
	for _, spec := range aCfg.Services {
		s, err := parseService(spec)
		if err != nil {
			return a, fmt.Errorf("invalid service '%s': %w", spec, err)
		}
		key := s.name + "/" + s.protocol
		if seen[key] {
			return a, fmt.Errorf("duplicate service '%s'", key)
		}
		seen[key] = true
		a.services = append(a.services, s)
	}
	rslName := defaultResolverName
	if len(aCfg.ResolverName) > 0 {
		rslName = aCfg.ResolverName
	}
	r, ok := resolvers[rslName]
	if !ok {
		return a, fmt.Errorf("alias resolver '%s' not found", rslName)
	}
	a.resolverDefRef = &r
	return a, nil
}
