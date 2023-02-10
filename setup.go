package recursor

import (
	"context"
	"fmt"
	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
	"github.com/prometheus/client_golang/prometheus"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
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
	rcu, err := createRecursor(rcuCfg)
	if err != nil {
		return plugin.Error(pluginName, fmt.Errorf("%s/%s create recursor error: %w", pluginName, pluginVersion, err))
	}
	updateInfoMetrics(rcu)
	if rcu.verbose > 1 {
		log.Infof("Plugin %s/%s created (zone '%s'): %s", pluginName, pluginVersion, rcu.zone, rcu.String())
	}
	cfg.AddPlugin(func(next plugin.Handler) plugin.Handler {
		rcu.Next = next
		if rcu.verbose > 0 {
			log.Infof("Plugin %s/%s added (zone '%s')", pluginName, pluginVersion, rcu.zone)
		}
		return rcu
	})
	return nil
}

func updateInfoMetrics(rcu recursor) {
	promBuildInfo.With(prometheus.Labels{"version": pluginVersion}).Set(0)
	for name, def := range rcu.resolvers {
		promResolvesInfo.With(prometheus.Labels{"zone": rcu.zone, "resolver": name, "urls": strings.Join(def.urls, ",")}).Set(1)
	}
	for name, def := range rcu.aliases {
		promAliasesInfo.With(prometheus.Labels{"zone": rcu.zone, "alias": name, "resolver": def.resolverDefRef.name, "ttl": strconv.Itoa(int(def.ttl))}).Set(1)
		for _, host := range def.hosts {
			promAliasesEntriesInfo.With(prometheus.Labels{"zone": rcu.zone, "alias": name, "resolver": def.resolverDefRef.name, "type": "host", "entry": host}).Set(1)
		}
		for _, ip := range def.ips {
			promAliasesEntriesInfo.With(prometheus.Labels{"zone": rcu.zone, "alias": name, "resolver": def.resolverDefRef.name, "type": "ip", "entry": ip.String()}).Set(1)
		}
	}
}

func createRecursor(cfg recursorCfg) (recursor, error) {
	r := recursor{
		verbose:   cfg.Verbose,
		zone:      cfg.Zone,
		resolvers: map[string]resolverDef{},
		aliases:   map[string]aliasDef{},
	}
	r.resolvers[defaultResolverName] = resolverDef{
		name:         defaultResolverName,
		resolverRefs: []*net.Resolver{net.DefaultResolver},
		urls:         []string{"://" + defaultResolverName},
	}
	for key, rslCfg := range cfg.Resolvers {
		rsl, err := createResolver(key, rslCfg)
		if err != nil {
			return r, fmt.Errorf("creating resolver '%s' error: %w, config: %s", key, err, rslCfg.String())
		}
		r.resolvers[key] = rsl
	}
	for key, aCfg := range cfg.Aliases {
		a, err := createAlias(key, aCfg, r.resolvers)
		if err != nil {
			return r, fmt.Errorf("creating alias '%s' error: %w, config: %s", key, err, aCfg.String())
		}
		r.aliases[key] = a
	}
	return r, nil
}

func createResolver(name string, p resolverCfg) (resolverDef, error) {
	rslDef := resolverDef{
		name: name,
	}
	if len(p.Urls) < 1 {
		return rslDef, fmt.Errorf("resolver urls can't be empty")
	} else {
		for _, urlStr := range p.Urls {
			u, err := url.Parse(urlStr)
			if err != nil {
				return resolverDef{}, fmt.Errorf("parsing resolver urls '%v' error: %w", urlStr, err)
			}
			var resolverRef = &net.Resolver{
				PreferGo: true,
				Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
					d := net.Dialer{}
					if p.TimeoutMs > 0 {
						d = net.Dialer{
							Timeout: time.Duration(p.TimeoutMs) * time.Millisecond,
						}
					}
					return d.DialContext(ctx, u.Scheme, u.Host)
				},
			}
			rslDef.resolverRefs = append(rslDef.resolverRefs, resolverRef)
			rslDef.urls = append(rslDef.urls, urlStr)
		}
		return rslDef, nil
	}
}

func createAlias(aName string, aCfg aliasCfg, resolvers map[string]resolverDef) (aliasDef, error) {
	a := aliasDef{
		ips:   []net.IP{},
		hosts: aCfg.Hosts,
		ttl:   aCfg.Ttl,
	}
	var ips []net.IP
	for _, ip := range aCfg.Ips {
		addr := net.ParseIP(ip)
		if addr != nil {
			ips = append(ips, addr)
		} else {
			return a, fmt.Errorf("wrong alias ip '%s'", ip)
		}
	}
	a.ips = ips
	if aName != "*" {
		if len(a.ips) == 0 && len(a.hosts) == 0 {
			return a, fmt.Errorf("alias ips and hosts are empty")
		}
	}
	rslName := defaultResolverName
	if len(aCfg.ResolverName) > 0 {
		rslName = aCfg.ResolverName
	}
	if r, ok := resolvers[rslName]; ok {
		a.resolverDefRef = &r
	} else {
		return a, fmt.Errorf("alias resolver '%s' not found", rslName)
	}
	return a, nil
}
