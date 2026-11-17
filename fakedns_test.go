package recursor

import (
	"context"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coredns/coredns/plugin/pkg/dnstest"
	"github.com/coredns/coredns/plugin/test"
	"github.com/miekg/dns"
)

// fakeDNS is a hermetic, in-process upstream DNS server used by the tests,
// so that resolver behaviour can be verified without Internet access.
type fakeDNS struct {
	url     string // udp://127.0.0.1:<port>; TCP is served on the same port
	tcpURL  string // tcp://127.0.0.1:<port>
	mu      sync.Mutex
	queries []fakeQuery
}

type fakeQuery struct {
	name  string // lower-case FQDN
	qtype uint16
	net   string // "udp" or "tcp"
}

// fakeOpts tunes the fake server.
type fakeOpts struct {
	records     map[string][]string      // name -> IPs; unknown names get NXDOMAIN
	delays      map[string]time.Duration // name -> answer delay
	truncateUDP bool                     // answer UDP with an empty truncated (TC) message
	refuseUDP   bool                     // answer UDP with REFUSED (TCP only server)
}

func (f *fakeDNS) asked(name string) bool {
	return f.count(name, 0, "") > 0
}

// count returns how many queries for name were received, optionally only of qtype (0 = any)
// and network ("" = any).
func (f *fakeDNS) count(name string, qtype uint16, network string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, q := range f.queries {
		if q.name == dns.CanonicalName(name) && (qtype == 0 || q.qtype == qtype) && (network == "" || q.net == network) {
			n++
		}
	}
	return n
}

// startFakeDNS serves A/AAAA records from the given map (name -> IPs) on 127.0.0.1.
// Unknown names get NXDOMAIN.
func startFakeDNS(t *testing.T, records map[string][]string) *fakeDNS {
	return startFakeDNSWith(t, fakeOpts{records: records})
}

func startFakeDNSWith(t *testing.T, opts fakeOpts) *fakeDNS {
	t.Helper()
	pc, ln := listenUDPAndTCP(t)
	addr := pc.LocalAddr().String()
	f := &fakeDNS{url: "udp://" + addr, tcpURL: "tcp://" + addr}
	canon := map[string][]net.IP{}
	for name, ips := range opts.records {
		for _, ip := range ips {
			canon[dns.CanonicalName(name)] = append(canon[dns.CanonicalName(name)], net.ParseIP(ip))
		}
	}
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		q := r.Question[0]
		name := dns.CanonicalName(q.Name)
		network := "udp"
		if _, ok := w.RemoteAddr().(*net.TCPAddr); ok {
			network = "tcp"
		}
		f.mu.Lock()
		f.queries = append(f.queries, fakeQuery{name: name, qtype: q.Qtype, net: network})
		f.mu.Unlock()
		if d := opts.delays[name]; d > 0 {
			time.Sleep(d)
		}
		m := new(dns.Msg)
		m.SetReply(r)
		m.RecursionAvailable = true // like a real recursive resolver; Go treats NODATA without RA as a lame referral
		if network == "udp" && opts.refuseUDP {
			m.Rcode = dns.RcodeRefused
			_ = w.WriteMsg(m)
			return
		}
		if network == "udp" && opts.truncateUDP {
			m.Truncated = true
			_ = w.WriteMsg(m)
			return
		}
		ips, ok := canon[name]
		if !ok {
			m.Rcode = dns.RcodeNameError
		}
		for _, ip := range ips {
			hdr := dns.RR_Header{Name: q.Name, Class: dns.ClassINET, Ttl: 60}
			if ip.To4() != nil && q.Qtype == dns.TypeA {
				hdr.Rrtype = dns.TypeA
				m.Answer = append(m.Answer, &dns.A{Hdr: hdr, A: ip})
			} else if ip.To4() == nil && q.Qtype == dns.TypeAAAA {
				hdr.Rrtype = dns.TypeAAAA
				m.Answer = append(m.Answer, &dns.AAAA{Hdr: hdr, AAAA: ip})
			}
		}
		_ = w.WriteMsg(m)
	})
	for _, srv := range []*dns.Server{{PacketConn: pc, Handler: handler}, {Listener: ln, Handler: handler}} {
		started := make(chan struct{})
		srv.NotifyStartedFunc = func() { close(started) }
		go func(s *dns.Server) { _ = s.ActivateAndServe() }(srv)
		<-started
		t.Cleanup(func() { _ = srv.Shutdown() })
	}
	return f
}

// listenUDPAndTCP opens UDP and TCP sockets on the same free port of 127.0.0.1.
func listenUDPAndTCP(t *testing.T) (net.PacketConn, net.Listener) {
	t.Helper()
	for i := 0; i < 20; i++ {
		pc, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen udp: %v", err)
		}
		ln, err := net.Listen("tcp", pc.LocalAddr().String())
		if err == nil {
			return pc, ln
		}
		_ = pc.Close()
	}
	t.Fatal("no free port for both UDP and TCP")
	return nil, nil
}

// unreachableResolverURL returns a UDP URL with nothing listening on it (fast "connection refused").
func unreachableResolverURL(t *testing.T) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := pc.LocalAddr().String()
	_ = pc.Close()
	return "udp://" + addr
}

// served holds the answered IPs (in answer order), the TTLs/owner names of all answer records,
// the recorded message, the rcode and the error.
type served struct {
	ips    []string
	ttls   []uint32
	owners []string
	rec    *dnstest.Recorder
	code   int
	err    error
}

func serve(rr recursor, name string, qTypes ...uint16) served {
	return serveFrom(rr, "", name, qTypes...)
}

// serveFrom sends a query through the plugin from the client IP (default 10.240.0.1).
func serveFrom(rr recursor, clientIp, name string, qTypes ...uint16) served {
	msg := new(dns.Msg)
	for _, qt := range qTypes {
		msg.Question = append(msg.Question, dns.Question{Name: name, Qtype: qt, Qclass: dns.ClassINET})
	}
	rec := dnstest.NewRecorder(&test.ResponseWriter{RemoteIP: clientIp})
	code, err := rr.ServeDNS(context.Background(), rec, msg)
	s := served{rec: rec, code: code, err: err}
	if rec.Msg != nil {
		for _, rr := range rec.Msg.Answer {
			s.ttls = append(s.ttls, rr.Header().Ttl)
			s.owners = append(s.owners, strings.ToLower(rr.Header().Name))
			switch a := rr.(type) {
			case *dns.A:
				s.ips = append(s.ips, a.A.String())
			case *dns.AAAA:
				s.ips = append(s.ips, a.AAAA.String())
			}
		}
	}
	return s
}
