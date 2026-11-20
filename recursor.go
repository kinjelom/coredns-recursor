package recursor

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/coredns/coredns/plugin"
	clog "github.com/coredns/coredns/plugin/pkg/log"
	"github.com/coredns/coredns/request"
	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
)

const pluginName = "recursor"
const pluginVersion = "1.6.0"
const defaultResolverName = "default"

// defaultResolveTimeout bounds a lookup when the resolver has no timeout_ms,
// so a silent upstream can't hold queries (and goroutines) for the Go resolver's ~40s.
const defaultResolveTimeout = 2 * time.Second

// maxTTL is the largest TTL allowed by RFC 2181 §8.
const maxTTL = 2147483647

var log = clog.NewWithPlugin(pluginName)

// recursor configuration.
// Note: "zone" is removed as it will be taken from the parent CoreDNS configuration.
type recursor struct {
	random     *rand.Rand
	configZone string
	aliases    map[string]aliasDef
	// patterns are the aliases with a `*` inside a label (e.g. `*-x`), most specific first.
	patterns  []aliasPattern
	resolvers map[string]resolverDef
	verbose   int
	// clientIpMetrics adds the client's IP to the query metrics (one series per client).
	clientIpMetrics bool
	// soaSerial is the serial of the synthesized SOA record returned with empty answers.
	soaSerial uint32
	Next      plugin.Handler
}

// Name returns the plugin name.
func (r recursor) Name() string { return pluginName }

// String returns a string representation of the recursor.
func (r recursor) String() string {
	nextPluginName := "nil"
	if r.Next != nil {
		nextPluginName = r.Next.Name()
	}
	return fmt.Sprintf("{name: %s, zone: %s, resolvers: {%v}, aliases: {%v}, verbose: %v, next-plugin-handler: %v}", r.Name(), r.configZone, r.resolvers, r.aliases, r.verbose, nextPluginName)
}

// resolverDef holds resolver settings.
type resolverDef struct {
	name         string
	resolverRefs []*net.Resolver
	urls         []string
	// timeout bounds a whole lookup (all retries) per upstream.
	timeout time.Duration
}

// lockedSource makes a rand.Source safe for concurrent use: ServeDNS runs in parallel
// and *rand.Rand is not goroutine-safe on its own. Shuffle/Intn only touch the source.
type lockedSource struct {
	mu  sync.Mutex
	src rand.Source64
}

func newLockedRand(seed int64) *rand.Rand {
	return rand.New(&lockedSource{src: rand.NewSource(seed).(rand.Source64)})
}

func (s *lockedSource) Int63() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.src.Int63()
}

func (s *lockedSource) Uint64() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.src.Uint64()
}

func (s *lockedSource) Seed(seed int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.src.Seed(seed)
}

func (rd resolverDef) String() string {
	return fmt.Sprintf("[%v]", rd.urls)
}

// aliasDef holds alias settings.
type aliasDef struct {
	hosts          []string
	ips            []net.IP
	shuffleIps     bool
	ipsTransform   []string
	ttl            uint32
	services       []serviceDef
	resolverDefRef *resolverDef
}

func (a aliasDef) String() string {
	hostsStr := "[" + strings.Join(a.hosts, ",") + "]"
	ipsStr := "["
	for _, ip := range a.ips {
		ipsStr += ip.String() + ","
	}
	ipsStr += "]"
	servicesStr := "["
	for _, s := range a.services {
		servicesStr += s.String() + ","
	}
	servicesStr += "]"
	return fmt.Sprintf("{hosts: %s, ips: %s, services: %s, ttl: %v, resolver: %s}", hostsStr, ipsStr, servicesStr, a.ttl, a.resolverDefRef.urls)
}

// ServeDNS handles DNS queries.
func (r recursor) ServeDNS(ctx context.Context, out dns.ResponseWriter, query *dns.Msg) (int, error) {
	state := request.Request{W: out, Req: query}
	clientIp := state.IP()
	domain := dns.CanonicalName(state.Name())
	zone := r.configZone
	zoneSuffix := strings.Trim(r.configZone, ". ")
	alias := strings.TrimSuffix(strings.Trim(domain, "."), "."+zoneSuffix)
	port := state.LocalPort()
	// Metric labels come from the configuration, never from the query name, so random names can't
	// create new series. The real names are only logged.
	aliasLabel := r.metricAlias(alias)
	clientLabel := r.metricClient(clientIp)
	if r.verbose > 0 {
		log.Infof("Recursor query: domain '%s', alias '%s', port '%s', config-zone '%s', state-zone '%s', client_ip '%s'", domain, alias, port, r.configZone, state.Zone, clientIp)
	}

	// Service names (`_name._proto.<alias>`, `_services._dns-sd._udp.<alias>`) of an explicit alias with services.
	// An explicitly configured alias of the same name always wins, so existing configs keep working.
	if _, explicit := r.aliases[alias]; !explicit {
		if base, name, protocol, enum, ok := parseServiceQueryName(alias); ok {
			if aDef, found := r.aliases[base]; found && len(aDef.services) > 0 {
				return r.serveServiceQuery(ctx, out, query, aDef, base, name, protocol, enum, port, zone, domain, clientLabel)
			}
		}
	}

	qA, qAAAA := extractQuestions(query.Question)
	if r.verbose > 1 {
		log.Infof("Recursor query details: A=%t, AAAA=%t, client_ip=%s\n```\n%s```", qA, qAAAA, clientIp, query.String())
	}
	if !qA && !qAAAA {
		promQueryOmittedCountTotal.With(prometheus.Labels{"port": port, "zone": zone, "alias": aliasLabel, "reason": "not-supported-query-code", "client_ip": clientLabel}).Inc()
		log.Debugf("Query code not supported: port '%s', zone '%s', domain '%s', alias '%s'", port, zone, domain, alias)
		return plugin.NextOrFailure(r.Name(), r.Next, ctx, out, query)
	}

	aliasDef, _, found, isWildcard := r.findAlias(alias)
	if !found {
		promQueryOmittedCountTotal.With(prometheus.Labels{"port": port, "zone": zone, "alias": aliasLabel, "reason": "alias-not-found", "client_ip": clientLabel}).Inc()
		log.Debugf("Alias not found: port '%s', zone '%s', domain '%s', alias '%s'", port, zone, domain, alias)
		return plugin.NextOrFailure(r.Name(), r.Next, ctx, out, query)
	}
	if isWildcard {
		if len(aliasDef.hosts) == 0 && len(aliasDef.ips) == 0 {
			aliasDef.hosts = []string{"*"}
		}
	} else {
		if len(aliasDef.hosts) == 0 && len(aliasDef.ips) == 0 {
			promQueryOmittedCountTotal.With(prometheus.Labels{"port": port, "zone": zone, "alias": aliasLabel, "reason": "alias-empty-def", "client_ip": clientLabel}).Inc()
			log.Debugf("Empty alias definition: port '%s', zone '%s', domain '%s', alias '%s'", port, zone, domain, alias)
			return plugin.NextOrFailure(r.Name(), r.Next, ctx, out, query)
		}
	}

	ips, err := r.aliasIps(ctx, aliasDef, state.Name(), lookupNetwork(qA, qAAAA), port, zone, aliasLabel)
	if err != nil {
		promQueryOmittedCountTotal.With(prometheus.Labels{"port": port, "zone": zone, "alias": aliasLabel, "reason": "resolving-error", "client_ip": clientLabel}).Inc()
		log.Warningf("%v: port '%s', zone '%s', domain '%s', alias '%s'", err, port, zone, domain, alias)
		return plugin.NextOrFailure(r.Name(), r.Next, ctx, out, query)
	}
	workIps := r.finalizeIps(ips, aliasDef, qA, qAAAA)
	dnsMsg := createDnsAnswer(query, port, zone, domain, aliasLabel, aliasDef.resolverDefRef.name, workIps, qA, qAAAA, aliasDef.ttl)
	if len(dnsMsg.Answer) == 0 {
		dnsMsg.Ns = []dns.RR{r.soa(aliasDef.ttl)}
	}
	if r.verbose > 1 {
		log.Infof("Recursor answer:\n```\n%s```", dnsMsg.String())
	}
	err = out.WriteMsg(dnsMsg)
	if err != nil {
		log.Errorf("Could not write message: %v", err)
		return dns.RcodeServerFailure, err
	}
	promQueryServedCountTotal.With(prometheus.Labels{"port": port, "zone": zone, "alias": aliasLabel, "resolver": aliasDef.resolverDefRef.name, "client_ip": clientLabel}).Inc()
	return dns.RcodeSuccess, nil
}

// metricAlias returns the alias label for metrics: the configured alias or pattern that handles
// the name (`*` for the wildcard alias), or empty when no alias matches.
func (r recursor) metricAlias(alias string) string {
	_, name, _, _ := r.findAlias(alias)
	return name
}

// metricClient returns the client_ip label for metrics, empty when client IP metrics are disabled.
func (r recursor) metricClient(clientIp string) string {
	if r.clientIpMetrics {
		return clientIp
	}
	return ""
}

// lookupNetwork returns the address family to ask the upstreams for: only what the client asked.
func lookupNetwork(qA, qAAAA bool) string {
	switch {
	case qA && !qAAAA:
		return "ip4"
	case qAAAA && !qA:
		return "ip6"
	}
	return "ip"
}

// aliasIps returns the alias' static IPs plus the addresses resolved for its hosts, deduplicated,
// in the configured order. The hosts are resolved in parallel. The host "*" stands for queryName.
// Any host that cannot be resolved fails the whole alias.
func (r recursor) aliasIps(ctx context.Context, aDef aliasDef, queryName, network, port, zone, aliasLabel string) ([]net.IP, error) {
	ips := ipsAppendUnique(nil, aDef.ips)
	n := len(aDef.hosts)
	results := make([][]net.IP, n)
	errs := make([]error, n)
	resolve := func(i int) {
		host := aDef.hosts[i]
		queryHost := host
		if host == "*" {
			queryHost = queryName
		}
		results[i], errs[i] = resolveHost(ctx, aDef.resolverDefRef, network, port, zone, aliasLabel, host, queryHost)
	}
	if n == 1 {
		resolve(0)
	} else {
		var wg sync.WaitGroup
		for i := range aDef.hosts {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				resolve(i)
			}(i)
		}
		wg.Wait()
	}
	for i, host := range aDef.hosts {
		if errs[i] != nil {
			return nil, fmt.Errorf("could not resolve host '%s': %w", host, errs[i])
		}
		ips = ipsAppendUnique(ips, results[i])
	}
	return ips, nil
}

// resolveHost resolves host for the address family `network` ("ip4", "ip6" or "ip").
// When a single-family lookup finds nothing, it is repeated for both families: a host that exists
// without addresses of the asked family then gets an empty answer, while a host that doesn't
// exist still fails, as with a lookup of both families.
func resolveHost(ctx context.Context, rd *resolverDef, network, port, zone, aliasLabel, hostLabel, host string) ([]net.IP, error) {
	ips, err := multiResolve(ctx, rd, network, port, zone, aliasLabel, hostLabel, host)
	var dnsErr *net.DNSError
	if err != nil && network != "ip" && errors.As(err, &dnsErr) && dnsErr.IsNotFound {
		return multiResolve(ctx, rd, "ip", port, zone, aliasLabel, hostLabel, host)
	}
	return ips, err
}

// finalizeIps filters the addresses to the asked families and applies shuffle_ips and ips_transform.
func (r recursor) finalizeIps(ips []net.IP, aDef aliasDef, qA, qAAAA bool) []net.IP {
	workIps := ips
	if qA != qAAAA {
		if qA {
			workIps = filterIPv4(ips)
		} else {
			workIps = filterIPv6(ips)
		}
	}
	if aDef.shuffleIps {
		r.random.Shuffle(len(workIps), func(i, j int) {
			workIps[i], workIps[j] = workIps[j], workIps[i]
		})
	}
	if len(aDef.ipsTransform) > 0 {
		workIps = r.transformIps(workIps, aDef.ipsTransform)
	}
	return workIps
}

// ipsTransformFunctions are the supported ips_transform functions, besides `limit_<n>`.
var ipsTransformFunctions = map[string]bool{
	"shuffle": true, "sort_asc": true, "sort_desc": true, "first": true, "last": true,
	"random_one": true, "prefer_ipv4": true, "prefer_ipv6": true,
}

// validateIpsTransform rejects unknown ips_transform functions, so typos fail at startup.
func validateIpsTransform(transform []string) error {
	for _, f := range transform {
		if ipsTransformFunctions[f] {
			continue
		}
		if s, ok := strings.CutPrefix(f, "limit_"); ok {
			if n, err := strconv.Atoi(s); err == nil && n >= 0 {
				continue
			}
		}
		return fmt.Errorf("unknown ips_transform function '%s'", f)
	}
	return nil
}

// transformIps applies transformations in order.
// The functions are validated at startup (validateIpsTransform); unknown ones are ignored here.
func (r recursor) transformIps(ips []net.IP, transform []string) []net.IP {
	// Work on a copy to avoid side effects if a caller reuses the slice
	ips = append([]net.IP(nil), ips...)

	for _, f := range transform {
		switch {
		case f == "shuffle":
			if len(ips) > 1 {
				r.random.Shuffle(len(ips), func(i, j int) { ips[i], ips[j] = ips[j], ips[i] })
			}

		case f == "sort_asc":
			sort.Slice(ips, func(i, j int) bool { return bytes.Compare(ips[i], ips[j]) < 0 })

		case f == "sort_desc":
			sort.Slice(ips, func(i, j int) bool { return bytes.Compare(ips[i], ips[j]) > 0 })

		case f == "first":
			if len(ips) > 1 {
				ips = ips[:1]
			}

		case f == "last":
			if n := len(ips); n > 1 {
				ips = ips[n-1:]
			}

		case f == "random_one":
			if n := len(ips); n > 1 {
				idx := r.random.Intn(n)
				ips = ips[idx : idx+1]
			}

		case f == "prefer_ipv4":
			if len(ips) > 1 {
				ipv4, ipv6 := stablePartitionByFamily(ips)
				ips = append(ipv4, ipv6...)
			}

		case f == "prefer_ipv6":
			if len(ips) > 1 {
				ipv4, ipv6 := stablePartitionByFamily(ips)
				ips = append(ipv6, ipv4...)
			}

		case strings.HasPrefix(f, "limit_"):
			if n, err := strconv.Atoi(strings.TrimPrefix(f, "limit_")); err == nil {
				if n <= 0 {
					ips = ips[:0]
				} else if len(ips) > n {
					ips = ips[:n]
				}
			}
		}
	}
	return ips
}

func stablePartitionByFamily(ips []net.IP) (ipv4 []net.IP, ipv6 []net.IP) {
	for _, ip := range ips {
		if ip.To4() != nil {
			ipv4 = append(ipv4, ip)
		} else {
			ipv6 = append(ipv6, ip)
		}
	}
	return
}

func filterIPv4(ips []net.IP) []net.IP {
	out := make([]net.IP, 0, len(ips))
	for _, ip := range ips {
		if ip.To4() != nil {
			out = append(out, ip)
		}
	}
	return out
}

func filterIPv6(ips []net.IP) []net.IP {
	out := make([]net.IP, 0, len(ips))
	for _, ip := range ips {
		if ip.To4() == nil {
			out = append(out, ip)
		}
	}
	return out
}

// findAlias returns the alias definition for a query name relative to the zone, the configured name
// that matched, and flags indicating if found and if it matched a wildcard (a pattern or `*`).
// Precedence: the exact alias, then the most specific pattern (see aliasPattern), then `*`.
func (r recursor) findAlias(alias string) (aliasDef, string, bool, bool) {
	if aDef, found := r.aliases[alias]; found {
		return aDef, alias, true, false
	}
	for _, p := range r.patterns {
		if p.match(alias) {
			return r.aliases[p.name], p.name, true, true
		}
	}
	if aDef, found := r.aliases["*"]; found {
		return aDef, "*", true, true
	}
	return aliasDef{}, "", false, false
}

// multiResolve queries the resolver URLs in parallel and returns the first successful result.
// The lookups still running then are cancelled. Each lookup is bounded by the resolver timeout.
func multiResolve(ctx context.Context, resolverDefRef *resolverDef, network, port, zone, aliasLabel, hostLabel, host string) ([]net.IP, error) {
	type result struct {
		ips         []net.IP
		err         error
		resolverURL string
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	n := len(resolverDefRef.resolverRefs)
	// Buffered, so lookups finishing after we return never block.
	resCh := make(chan result, n)
	for ri, resolver := range resolverDefRef.resolverRefs {
		go func(rsl *net.Resolver, resolverURL string) {
			lookupCtx := ctx
			if resolverDefRef.timeout > 0 {
				var lookupCancel context.CancelFunc
				lookupCtx, lookupCancel = context.WithTimeout(ctx, resolverDefRef.timeout)
				defer lookupCancel()
			}
			start := time.Now()
			ips, err := rsl.LookupIP(lookupCtx, network, host)
			elapsed := time.Since(start)
			if err == nil && len(ips) == 0 {
				err = fmt.Errorf("no addresses for host '%s'", host)
			}
			if err != nil && ctx.Err() != nil {
				// Cancelled because another URL answered first (or the query was abandoned):
				// not an upstream failure, so it isn't counted.
				resCh <- result{err: err, resolverURL: resolverURL}
				return
			}
			resultLabel := "success"
			if err != nil {
				resultLabel = "error"
			}
			labels := prometheus.Labels{"port": port, "zone": zone, "alias": aliasLabel, "resolver": resolverDefRef.name, "host": hostLabel, "result": resultLabel}
			promResolveDurationMs.With(labels).Set(float64(elapsed.Milliseconds()))
			promResolveCountTotal.With(labels).Inc()
			promResolveDurationMsTotal.With(labels).Add(float64(elapsed.Milliseconds()))
			resCh <- result{ips: ips, err: err, resolverURL: resolverURL}
		}(resolver, resolverDefRef.urls[ri])
	}
	var lastErr error
	for i := 0; i < n; i++ {
		res := <-resCh
		if res.err == nil {
			return res.ips, nil
		}
		lastErr = fmt.Errorf("resolver '%s' error: %w", res.resolverURL, res.err)
		log.Debug(lastErr.Error())
	}
	return nil, lastErr
}

// extractQuestions checks if the query contains A and/or AAAA questions.
func extractQuestions(questions []dns.Question) (bool, bool) {
	hasA := false
	hasAAAA := false
	for _, q := range questions {
		switch q.Qtype {
		case dns.TypeA:
			hasA = true
		case dns.TypeAAAA:
			hasAAAA = true
		case dns.TypeANY:
			hasA = true
			hasAAAA = true
		}
	}
	return hasA, hasAAAA
}

// ipsAppendUnique appends IP addresses from src to dest ensuring uniqueness.
func ipsAppendUnique(dest []net.IP, src []net.IP) []net.IP {
	seen := make(map[string]struct{})
	for _, ip := range dest {
		seen[ip.String()] = struct{}{}
	}
	for _, ip := range src {
		if _, exists := seen[ip.String()]; !exists {
			dest = append(dest, ip)
			seen[ip.String()] = struct{}{}
		}
	}
	return dest
}

// createDnsAnswer constructs the DNS response message.
func createDnsAnswer(qMsg *dns.Msg, port, zone, domain, aliasLabel, resolver string, ips []net.IP, qA bool, qAAAA bool, ttl uint32) *dns.Msg {
	aMsg := new(dns.Msg)
	aMsg.SetReply(qMsg)
	aMsg.Authoritative = true
	aMsg.Answer = ipRRs(domain, ips, qA, qAAAA, ttl)
	for _, rr := range aMsg.Answer {
		var ip net.IP
		switch a := rr.(type) {
		case *dns.A:
			ip = a.A
		case *dns.AAAA:
			ip = a.AAAA
		}
		promResolveIpCountTotal.With(prometheus.Labels{"port": port, "zone": zone, "alias": aliasLabel, "resolver": resolver, "ip": ip.String()}).Inc()
	}
	return aMsg
}

// soa returns the synthesized SOA record of the zone, added to the authority section of empty
// (NODATA) answers so downstream resolvers can cache them (RFC 2308). The negative TTL is ttl.
func (r recursor) soa(ttl uint32) dns.RR {
	apex := strings.TrimSuffix(r.configZone, ".")
	return &dns.SOA{
		Hdr:     dns.RR_Header{Name: r.configZone, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: ttl},
		Ns:      dns.Fqdn("ns." + apex),
		Mbox:    dns.Fqdn("hostmaster." + apex),
		Serial:  r.soaSerial,
		Refresh: 7200,
		Retry:   1800,
		Expire:  86400,
		Minttl:  ttl,
	}
}

// ipRRs builds A/AAAA records named `name` for the addresses of the asked families.
func ipRRs(name string, ips []net.IP, qA bool, qAAAA bool, ttl uint32) []dns.RR {
	var rrs []dns.RR
	owner := dns.CanonicalName(name)
	for _, ip := range ips {
		if ip.To4() != nil {
			if qA {
				rrs = append(rrs, &dns.A{
					Hdr: dns.RR_Header{Name: owner, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl},
					A:   ip,
				})
			}
		} else if qAAAA {
			rrs = append(rrs, &dns.AAAA{
				Hdr:  dns.RR_Header{Name: owner, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: ttl},
				AAAA: ip,
			})
		}
	}
	return rrs
}
