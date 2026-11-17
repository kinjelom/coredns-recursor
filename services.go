package recursor

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/coredns/coredns/plugin"
	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
)

// serviceEnumPrefix is the DNS-SD service type enumeration name (RFC 6763 §9),
// prepended to an alias: `_services._dns-sd._udp.<alias>.<zone>` lists the alias' services.
const serviceEnumPrefix = "_services._dns-sd._udp."

const defaultServiceProtocol = "tcp"

// serviceNameRe: RFC 6335 §5.1 service name characters, no leading/trailing hyphen.
var serviceNameRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`)

var serviceProtocols = map[string]bool{"tcp": true, "udp": true, "sctp": true}

// serviceDef is a service published under an alias as an SRV record `_<name>._<protocol>.<alias>.<zone>`.
type serviceDef struct {
	name     string
	port     uint16
	protocol string
}

func (s serviceDef) String() string {
	return fmt.Sprintf("%s:%d/%s", s.name, s.port, s.protocol)
}

// srvLabels returns the SRV owner name prefix, e.g. `_https._tcp`.
func (s serviceDef) srvLabels() string {
	return "_" + s.name + "._" + s.protocol
}

// parseService parses `name:port[/protocol]`, e.g. `https:443`, `dns:53/udp`.
// The protocol defaults to tcp. Names are case-insensitive and stored lower-case.
func parseService(spec string) (serviceDef, error) {
	s := strings.ToLower(strings.TrimSpace(spec))
	name, rest, ok := strings.Cut(s, ":")
	if !ok {
		return serviceDef{}, fmt.Errorf("expected 'name:port[/protocol]'")
	}
	portStr, protocol, hasProtocol := strings.Cut(rest, "/")
	if !hasProtocol {
		protocol = defaultServiceProtocol
	}
	if err := validateServiceName(name); err != nil {
		return serviceDef{}, err
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil || port == 0 {
		return serviceDef{}, fmt.Errorf("port must be a number in range 1-65535, got '%s'", portStr)
	}
	if !serviceProtocols[protocol] {
		return serviceDef{}, fmt.Errorf("protocol must be one of tcp, udp, sctp, got '%s'", protocol)
	}
	return serviceDef{name: name, port: uint16(port), protocol: protocol}, nil
}

// validateServiceName applies the RFC 6335 §5.1 rules, so the name is valid in an SRV label.
func validateServiceName(name string) error {
	switch {
	case len(name) < 1 || len(name) > 15:
		return fmt.Errorf("service name '%s' must be 1-15 characters long", name)
	case !serviceNameRe.MatchString(name):
		return fmt.Errorf("service name '%s' may contain only letters, digits and inner hyphens", name)
	case strings.Contains(name, "--"):
		return fmt.Errorf("service name '%s' must not contain consecutive hyphens", name)
	case !strings.ContainsAny(name, "abcdefghijklmnopqrstuvwxyz"):
		return fmt.Errorf("service name '%s' must contain at least one letter", name)
	}
	return nil
}

// parseServiceQueryName recognises service names relative to the zone:
//   - `_services._dns-sd._udp.<alias>` → enumeration of the alias' services,
//   - `_<name>._<protocol>.<alias>`   → a single service.
func parseServiceQueryName(relName string) (baseAlias, name, protocol string, enum, ok bool) {
	if base, found := strings.CutPrefix(relName, serviceEnumPrefix); found {
		if base == "" {
			return "", "", "", false, false
		}
		return base, "", "", true, true
	}
	labels := strings.SplitN(relName, ".", 3)
	if len(labels) != 3 || len(labels[0]) < 2 || len(labels[1]) < 2 ||
		labels[0][0] != '_' || labels[1][0] != '_' || labels[2] == "" {
		return "", "", "", false, false
	}
	return labels[2], labels[0][1:], labels[1][1:], false, true
}

// serveServiceQuery answers SRV (single service) and PTR (enumeration) queries for an alias with services.
func (r recursor) serveServiceQuery(ctx context.Context, out dns.ResponseWriter, query *dns.Msg,
	aDef aliasDef, alias, name, protocol string, enum bool, port, zone, domain, clientLabel string) (int, error) {

	m := new(dns.Msg)
	m.SetReply(query)
	m.Authoritative = true

	if enum {
		if hasQtype(query.Question, dns.TypePTR) {
			for _, s := range aDef.services {
				m.Answer = append(m.Answer, &dns.PTR{
					Hdr: dns.RR_Header{Name: domain, Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: aDef.ttl},
					Ptr: s.srvLabels() + "." + r.aliasFqdn(alias),
				})
			}
		}
	} else {
		var svc *serviceDef
		for i := range aDef.services {
			if aDef.services[i].name == name && aDef.services[i].protocol == protocol {
				svc = &aDef.services[i]
				break
			}
		}
		if svc == nil {
			promQueryOmittedCountTotal.With(prometheus.Labels{"port": port, "zone": zone, "alias": alias, "reason": "service-not-found", "client_ip": clientLabel}).Inc()
			log.Debugf("Service not found: port '%s', zone '%s', domain '%s', alias '%s'", port, zone, domain, alias)
			return plugin.NextOrFailure(r.Name(), r.Next, ctx, out, query)
		}
		if hasQtype(query.Question, dns.TypeSRV) {
			target := r.aliasFqdn(alias)
			m.Answer = append(m.Answer, &dns.SRV{
				Hdr:      dns.RR_Header{Name: domain, Rrtype: dns.TypeSRV, Class: dns.ClassINET, Ttl: aDef.ttl},
				Priority: 0,
				Weight:   0,
				Port:     svc.port,
				Target:   target,
			})
			// Glue: the target's addresses, so clients need no second query. Best effort.
			ips, err := r.aliasIps(ctx, aDef, target, "ip", port, zone, alias)
			if err != nil {
				log.Warningf("SRV additional section skipped for alias '%s': %v", alias, err)
			} else {
				m.Extra = append(m.Extra, ipRRs(target, r.finalizeIps(ips, aDef, true, true), true, true, aDef.ttl)...)
			}
		}
	}
	// A name that exists but has no records of the asked type gets an empty NOERROR (NODATA) answer.
	if len(m.Answer) == 0 {
		m.Ns = []dns.RR{r.soa(aDef.ttl)}
	}
	if r.verbose > 1 {
		log.Infof("Recursor service answer:\n```\n%s```", m.String())
	}
	if err := out.WriteMsg(m); err != nil {
		log.Errorf("Could not write message: %v", err)
		return dns.RcodeServerFailure, err
	}
	promQueryServedCountTotal.With(prometheus.Labels{"port": port, "zone": zone, "alias": alias, "resolver": aDef.resolverDefRef.name, "client_ip": clientLabel}).Inc()
	return dns.RcodeSuccess, nil
}

// hasQtype reports whether the query asks for the type t (ANY counts as every type).
func hasQtype(questions []dns.Question, t uint16) bool {
	for _, q := range questions {
		if q.Qtype == t || q.Qtype == dns.TypeANY {
			return true
		}
	}
	return false
}

// aliasFqdn returns the fully qualified name of an alias in the configured zone.
func (r recursor) aliasFqdn(alias string) string {
	if r.configZone == "." {
		return dns.Fqdn(alias)
	}
	return alias + "." + r.configZone
}
