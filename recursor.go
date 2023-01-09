package recursor

import (
	"context"
	"fmt"
	"github.com/coredns/coredns/plugin"
	clog "github.com/coredns/coredns/plugin/pkg/log"
	"github.com/coredns/coredns/request"
	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
	"net"
	"strings"
	"time"
)

const pluginName = "recursor"
const pluginVersion = "1.0.1"
const defaultResolverName = "default"

// Name implements the Handler interface.
func (r recursor) Name() string { return pluginName }

var log = clog.NewWithPlugin(pluginName)

type recursor struct {
	zone      string
	aliases   map[string]aliasDef
	resolvers map[string]resolverDef
	verbose   int
	Next      plugin.Handler
}

func (r recursor) String() string {
	nextPluginName := "nil"
	if r.Next != nil {
		nextPluginName = r.Next.Name()
	}
	return fmt.Sprintf("{name: %s, zone: %s, resolvers: {%v}, aliases: {%v}, verbose: %v, next-plugin-handler: %v}", r.Name(), r.zone, r.resolvers, r.aliases, r.verbose, nextPluginName)
}

type resolverDef struct {
	name         string
	resolverRefs []*net.Resolver
	urls         []string
}

func (r resolverDef) String() string {
	return fmt.Sprintf("[%v]", r.urls)
}

type aliasDef struct {
	hosts          []string
	ips            []net.IP
	ttl            uint32
	resolverDefRef *resolverDef
}

func (r aliasDef) String() string {
	hosts := "[" + strings.Join(r.hosts, ",") + "]"
	addresses := "["
	for _, addr := range r.ips {
		addresses += addr.String() + ","
	}
	addresses += "]"
	return fmt.Sprintf("{hosts: %s, ips: %s, ttl: %v, resolver: %s}", hosts, addresses, r.ttl, r.resolverDefRef.urls)
}

// ServeDNS implements the plugin.Handler interface. This method gets called when plugin is used in a Server.
func (r recursor) ServeDNS(ctx context.Context, out dns.ResponseWriter, query *dns.Msg) (int, error) {
	state := request.Request{W: out, Req: query}
	domain := dns.CanonicalName(state.Name())
	zoneSuffix := "." + dns.CanonicalName(r.zone)
	if !strings.HasSuffix(domain, zoneSuffix) {
		domain = domain + zoneSuffix
	}
	alias := strings.TrimSuffix(domain, zoneSuffix)
	if r.verbose > 0 {
		log.Infof("Recursor query domain '%s', alias '%s', zone '%s'", domain, alias, r.zone)
	}

	qA, qAAAA := extractQuestions(query.Question)
	if r.verbose > 1 {
		log.Infof("Recursor query:  A=%t, AAAA=%t\n```\n%s```", qA, qAAAA, query.String())
	}
	if !qA && !qAAAA {
		promQueryOmittedCountTotal.With(prometheus.Labels{"zone": r.zone, "alias": alias, "reason": "not-supported-query-code"}).Inc()
		log.Errorf("Query code not supported: zone '%s', domain '%s', alias '%s'", r.zone, domain, alias)
		return plugin.NextOrFailure(r.Name(), r.Next, ctx, out, query)
	}

	var aDef aliasDef
	var ok bool
	if aDef, ok = r.aliases[alias]; !ok {
		promQueryOmittedCountTotal.With(prometheus.Labels{"zone": r.zone, "alias": alias, "reason": "alias-not-found"}).Inc()
		log.Errorf("Alias not found: zone '%s', domain '%s', alias '%s'", r.zone, domain, alias)
		return plugin.NextOrFailure(r.Name(), r.Next, ctx, out, query)
	}
	if len(aDef.hosts) < 1 && len(aDef.ips) < 1 {
		promQueryOmittedCountTotal.With(prometheus.Labels{"zone": r.zone, "alias": alias, "reason": "alias-empty-def"}).Inc()
		log.Errorf("Empty alias definition: zone '%s', domain '%s', alias '%s'", r.zone, domain, alias)
		return plugin.NextOrFailure(r.Name(), r.Next, ctx, out, query)
	}

	var ips []net.IP
	ips = ipsAppendUniqe(ips, aDef.ips)
	for _, host := range aDef.hosts {
		dynIps, err := multiResolve(ctx, aDef.resolverDefRef, r.zone, domain, alias, host)
		if err != nil {
			promQueryOmittedCountTotal.With(prometheus.Labels{"zone": r.zone, "alias": alias, "reason": "resolving-error"}).Inc()
			log.Errorf("Could not resolve host '%s': zone '%s', domain '%s', alias '%s'", host, r.zone, domain, alias)
			return plugin.NextOrFailure(r.Name(), r.Next, ctx, out, query)
		}
		ips = ipsAppendUniqe(ips, dynIps)
	}

	aMsg := createDnsAnswer(query, r.zone, domain, alias, aDef.resolverDefRef.name, ips, qA, qAAAA, aDef.ttl)
	if r.verbose > 1 {
		log.Infof("Recursor answer:\n```\n%s```", aMsg.String())
	}
	err := out.WriteMsg(aMsg)
	if err != nil {
		log.Errorf("Could not write message: %v", err)
		return dns.RcodeServerFailure, err
	}
	promQueryServedCountTotal.With(prometheus.Labels{"zone": r.zone, "alias": alias, "resolver": aDef.resolverDefRef.name}).Inc()
	return dns.RcodeSuccess, nil
}

func multiResolve(ctx context.Context, resolverDefRef *resolverDef, zone string, domain string, alias string, host string) ([]net.IP, error) {
	var lastErr error
	for ri, rslRef := range resolverDefRef.resolverRefs {
		rslUrl := resolverDefRef.urls[ri]
		start := time.Now()
		ips, err := rslRef.LookupIP(ctx, "ip", host)
		elapsed := time.Since(start)
		result := "success"
		if err != nil {
			result = "error"
		}
		labels := prometheus.Labels{"zone": zone, "alias": alias, "resolver": resolverDefRef.name, "host": host, "result": result}
		promResolveDurationMs.With(labels).Set(float64(elapsed.Milliseconds()))
		promResolveCountTotal.With(labels).Inc()
		promResolveDurationMsTotal.With(labels).Add(float64(elapsed.Milliseconds()))
		if err == nil {
			return ips, nil
		} else {
			lastErr = fmt.Errorf("resolver '%s' error: %w", rslUrl, err)
			log.Warningf(lastErr.Error())
		}
	}
	return nil, lastErr
}

func extractQuestions(questions []dns.Question) (bool, bool) {
	qA := false
	qAAAA := false
	for _, q := range questions {
		switch q.Qtype {
		case dns.TypeA:
			qA = true
		case dns.TypeAAAA:
			qAAAA = true
		case dns.TypeANY:
			qA = true
			qAAAA = true
		}
	}
	return qA, qAAAA
}

func ipsAppendUniqe(dest []net.IP, src []net.IP) []net.IP {
	for _, ip := range src {
		if !ipsExists(dest, ip) {
			dest = append(dest, ip)
		}
	}
	return dest
}

func ipsExists(arr []net.IP, ipaToFind net.IP) bool {
	for _, ipa := range arr {
		if strings.EqualFold(ipa.String(), ipaToFind.String()) {
			return true
		}
	}
	return false
}

func createDnsAnswer(qMsg *dns.Msg, zone string, domain string, alias string, resolver string, ips []net.IP, qA bool, qAAAA bool, ttl uint32) *dns.Msg {
	aMsg := new(dns.Msg)
	aMsg.SetReply(qMsg)
	aMsg.Answer = []dns.RR{}
	for _, ip := range ips {
		var resRec dns.RR
		if ip.To4() != nil {
			if qA {
				resRec = &dns.A{
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
				resRec = &dns.AAAA{
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

		if resRec != nil {
			promResolveIpCountTotal.With(prometheus.Labels{"zone": zone, "alias": alias, "resolver": resolver, "ip": ip.String()}).Inc()
			aMsg.Answer = append(aMsg.Answer, resRec)
		}
	}
	return aMsg
}
