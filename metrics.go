package recursor

import (
	"sync"

	"github.com/coredns/coredns/plugin"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var promBuildInfo = promauto.NewGaugeVec(prometheus.GaugeOpts{
	Namespace: plugin.Namespace,
	Subsystem: pluginName,
	Name:      "build_info",
	Help:      "Plugin build info",
}, []string{"version"})
var promResolvesInfo = promauto.NewGaugeVec(prometheus.GaugeOpts{
	Namespace: plugin.Namespace,
	Subsystem: pluginName,
	Name:      "resolvers_info",
	Help:      "Resolves info",
}, []string{"zone", "resolver", "urls"})
var promAliasesInfo = promauto.NewGaugeVec(prometheus.GaugeOpts{
	Namespace: plugin.Namespace,
	Subsystem: pluginName,
	Name:      "aliases_info",
	Help:      "Aliases info",
}, []string{"zone", "alias", "resolver", "ttl"})
var promAliasesEntriesInfo = promauto.NewGaugeVec(prometheus.GaugeOpts{
	Namespace: plugin.Namespace,
	Subsystem: pluginName,
	Name:      "aliases_entries_info",
	Help:      "Aliases entries info",
}, []string{"zone", "alias", "resolver", "type", "entry"})

var promQueryServedCountTotal = promauto.NewCounterVec(prometheus.CounterOpts{
	Namespace: plugin.Namespace,
	Subsystem: pluginName,
	Name:      "query_served_count_total",
	Help:      "Total count of served queries",
}, []string{"zone", "alias", "resolver"})
var promQueryOmittedCountTotal = promauto.NewCounterVec(prometheus.CounterOpts{
	Namespace: plugin.Namespace,
	Subsystem: pluginName,
	Name:      "query_omitted_count_total",
	Help:      "Total count of omitted queries",
}, []string{"zone", "alias", "reason"})

var promResolveCountTotal = promauto.NewCounterVec(prometheus.CounterOpts{
	Namespace: plugin.Namespace,
	Subsystem: pluginName,
	Name:      "resolve_count_total",
	Help:      "Total count of resolve operations",
}, []string{"zone", "alias", "resolver", "host", "result"})
var promResolveDurationMs = promauto.NewGaugeVec(prometheus.GaugeOpts{
	Namespace: plugin.Namespace,
	Subsystem: pluginName,
	Name:      "resolve_duration_ms",
	Help:      "Duration of resolve operation in milliseconds",
}, []string{"zone", "alias", "resolver", "host", "result"})
var promResolveDurationMsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
	Namespace: plugin.Namespace,
	Subsystem: pluginName,
	Name:      "resolve_duration_ms_total",
	Help:      "Total duration of resolve operations in milliseconds",
}, []string{"zone", "alias", "resolver", "host", "result"})

var promResolveIpCountTotal = promauto.NewCounterVec(prometheus.CounterOpts{
	Namespace: plugin.Namespace,
	Subsystem: pluginName,
	Name:      "resolve_ip_count_total",
	Help:      "Total count of answers",
}, []string{"zone", "alias", "resolver", "ip"})

var once sync.Once
