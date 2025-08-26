package recursor

import (
	"bytes"
	"context"
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
const pluginVersion = "1.4.0"
const defaultResolverName = "default"

var log = clog.NewWithPlugin(pluginName)

// recursor configuration.
// Note: "zone" is removed as it will be taken from the parent CoreDNS configuration.
type recursor struct {
	random     *rand.Rand
	configZone string
	aliases    map[string]aliasDef
	resolvers  map[string]resolverDef
	verbose    int
	Next       plugin.Handler
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
	resolverDefRef *resolverDef
}

func (a aliasDef) String() string {
	hostsStr := "[" + strings.Join(a.hosts, ",") + "]"
	ipsStr := "["
	for _, ip := range a.ips {
		ipsStr += ip.String() + ","
	}
	ipsStr += "]"
	return fmt.Sprintf("{hosts: %s, ips: %s, ttl: %v, resolver: %s}", hostsStr, ipsStr, a.ttl, a.resolverDefRef.urls)
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
	if r.verbose > 0 {
		log.Infof("Recursor query: domain '%s', alias '%s', port '%s', config-zone '%s', state-zone '%s', client_ip '%s'", domain, alias, port, r.configZone, state.Zone, clientIp)
	}
	qA, qAAAA := extractQuestions(query.Question)
	if r.verbose > 1 {
		log.Infof("Recursor query details: A=%t, AAAA=%t, client_ip=%s\n```\n%s```", qA, qAAAA, clientIp, query.String())
	}
	if !qA && !qAAAA {
		promQueryOmittedCountTotal.With(prometheus.Labels{"port": port, "zone": zone, "alias": alias, "reason": "not-supported-query-code", "client_ip": clientIp}).Inc()
		log.Errorf("Query code not supported: port '%s', zone '%s', domain '%s', alias '%s'", port, zone, domain, alias)
		return plugin.NextOrFailure(r.Name(), r.Next, ctx, out, query)
	}

	aliasDef, found, isWildcard := r.findAlias(alias)
	if !found {
		promQueryOmittedCountTotal.With(prometheus.Labels{"port": port, "zone": zone, "alias": alias, "reason": "alias-not-found", "client_ip": clientIp}).Inc()
		log.Errorf("Alias not found: port '%s', zone '%s', domain '%s', alias '%s'", port, zone, domain, alias)
		return plugin.NextOrFailure(r.Name(), r.Next, ctx, out, query)
	}
	if isWildcard {
		if len(aliasDef.hosts) == 0 && len(aliasDef.ips) == 0 {
			aliasDef.hosts = []string{"*"}
		}
	} else {
		if len(aliasDef.hosts) == 0 && len(aliasDef.ips) == 0 {
			promQueryOmittedCountTotal.With(prometheus.Labels{"port": port, "zone": zone, "alias": alias, "reason": "alias-empty-def", "client_ip": clientIp}).Inc()
			log.Errorf("Empty alias definition: port '%s', zone '%s', domain '%s', alias '%s'", port, zone, domain, alias)
			return plugin.NextOrFailure(r.Name(), r.Next, ctx, out, query)
		}
	}

	// Start with statically defined IPs
	var ips []net.IP
	ips = ipsAppendUnique(ips, aliasDef.ips)
	hosts := aliasDef.hosts
	// Resolve dynamic IPs for each host.
	for _, host := range hosts {
		// If the host is "*", use the original query name.
		queryHost := host
		if host == "*" {
			queryHost = state.Name()
		}
		dynIps, err := multiResolve(ctx, aliasDef.resolverDefRef, port, zone, alias, queryHost)
		if err != nil {
			promQueryOmittedCountTotal.With(prometheus.Labels{"port": port, "zone": zone, "alias": alias, "reason": "resolving-error", "client_ip": clientIp}).Inc()
			log.Errorf("Could not resolve host '%s': port '%s', zone '%s', domain '%s', alias '%s'", host, port, zone, domain, alias)
			return plugin.NextOrFailure(r.Name(), r.Next, ctx, out, query)
		}
		ips = ipsAppendUnique(ips, dynIps)
	}

	workIps := ips
	if qA != qAAAA {
		if qA {
			workIps = filterIPv4(ips)
		} else {
			workIps = filterIPv6(ips)
		}
	}

	// Shuffle IPs if configured.
	if aliasDef.shuffleIps {
		r.random.Shuffle(len(workIps), func(i, j int) {
			workIps[i], workIps[j] = workIps[j], workIps[i]
		})
	}
	if len(aliasDef.ipsTransform) > 0 {
		workIps = r.transformIps(workIps, aliasDef.ipsTransform)
	}
	dnsMsg := createDnsAnswer(query, port, zone, domain, alias, aliasDef.resolverDefRef.name, workIps, qA, qAAAA, aliasDef.ttl)
	if r.verbose > 1 {
		log.Infof("Recursor answer:\n```\n%s```", dnsMsg.String())
	}
	err := out.WriteMsg(dnsMsg)
	if err != nil {
		log.Errorf("Could not write message: %v", err)
		return dns.RcodeServerFailure, err
	}
	promQueryServedCountTotal.With(prometheus.Labels{"port": port, "zone": zone, "alias": alias, "resolver": aliasDef.resolverDefRef.name, "client_ip": clientIp}).Inc()
	return dns.RcodeSuccess, nil
}

// transformIps applies transformations in order.
// Unknown transformation names are ignored.
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

// findAlias returns the alias definition and flags indicating if found and if it is a wildcard alias.
func (r recursor) findAlias(alias string) (aliasDef, bool, bool) {
	isWildcard := false
	aDef, found := r.aliases[alias]
	if !found {
		aDef, found = r.aliases["*"]
		if found {
			isWildcard = true
		}
	}
	return aDef, found, isWildcard
}

// multiResolve queries the resolver(s) in parallel and returns the first successful result.
func multiResolve(ctx context.Context, resolverDefRef *resolverDef, port, zone, alias, host string) ([]net.IP, error) {
	type result struct {
		ips         []net.IP
		err         error
		elapsed     time.Duration
		resolverURL string
	}
	resCh := make(chan result, len(resolverDefRef.resolverRefs))
	var wg sync.WaitGroup
	for ri, resolver := range resolverDefRef.resolverRefs {
		resolverURL := resolverDefRef.urls[ri]
		wg.Add(1)
		go func(rsl *net.Resolver, resolverURL string) {
			defer wg.Done()
			start := time.Now()
			ips, err := rsl.LookupIP(ctx, "ip", host)
			elapsed := time.Since(start)
			resCh <- result{ips: ips, err: err, elapsed: elapsed, resolverURL: resolverURL}
		}(resolver, resolverURL)
	}
	wg.Wait()
	close(resCh)
	var lastErr error
	for res := range resCh {
		labels := prometheus.Labels{"port": port, "zone": zone, "alias": alias, "resolver": resolverDefRef.name, "host": host}
		resultLabel := "success"
		if res.err != nil {
			resultLabel = "error"
		}
		labels["result"] = resultLabel
		promResolveDurationMs.With(labels).Set(float64(res.elapsed.Milliseconds()))
		promResolveCountTotal.With(labels).Inc()
		promResolveDurationMsTotal.With(labels).Add(float64(res.elapsed.Milliseconds()))
		if res.err == nil && len(res.ips) > 0 {
			return res.ips, nil
		} else {
			lastErr = fmt.Errorf("resolver '%s' error: %w", res.resolverURL, res.err)
			log.Warning(lastErr.Error())
		}
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
func createDnsAnswer(qMsg *dns.Msg, port, zone, domain, alias, resolver string, ips []net.IP, qA bool, qAAAA bool, ttl uint32) *dns.Msg {
	aMsg := new(dns.Msg)
	aMsg.SetReply(qMsg)
	aMsg.Answer = []dns.RR{}
	for _, ip := range ips {
		var rr dns.RR
		if ip.To4() != nil {
			if qA {
				rr = &dns.A{
					Hdr: dns.RR_Header{
						Name:   dns.CanonicalName(domain),
						Rrtype: dns.TypeA,
						Class:  dns.ClassINET,
						Ttl:    ttl,
					},
					A: ip,
				}
			}
		} else {
			if qAAAA {
				rr = &dns.AAAA{
					Hdr: dns.RR_Header{
						Name:   dns.CanonicalName(domain),
						Rrtype: dns.TypeAAAA,
						Class:  dns.ClassINET,
						Ttl:    ttl,
					},
					AAAA: ip,
				}
			}
		}
		if rr != nil {
			promResolveIpCountTotal.With(prometheus.Labels{"port": port, "zone": zone, "alias": alias, "resolver": resolver, "ip": ip.String()}).Inc()
			aMsg.Answer = append(aMsg.Answer, rr)
		}
	}
	return aMsg
}
