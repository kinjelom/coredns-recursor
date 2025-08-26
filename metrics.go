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
}, []string{"port", "zone", "resolver", "urls"})
var promAliasesInfo = promauto.NewGaugeVec(prometheus.GaugeOpts{
	Namespace: plugin.Namespace,
	Subsystem: pluginName,
	Name:      "aliases_info",
	Help:      "Aliases info",
}, []string{"port", "zone", "alias", "resolver", "ttl"})
var promAliasesEntriesInfo = promauto.NewGaugeVec(prometheus.GaugeOpts{
	Namespace: plugin.Namespace,
	Subsystem: pluginName,
	Name:      "aliases_entries_info",
	Help:      "Aliases entries info",
}, []string{"port", "zone", "alias", "resolver", "type", "entry"})

var promQueryServedCountTotal = promauto.NewCounterVec(prometheus.CounterOpts{
	Namespace: plugin.Namespace,
	Subsystem: pluginName,
	Name:      "query_served_count_total",
	Help:      "Total count of served queries",
}, []string{"port", "zone", "alias", "resolver", "client_ip"})
var promQueryOmittedCountTotal = promauto.NewCounterVec(prometheus.CounterOpts{
	Namespace: plugin.Namespace,
	Subsystem: pluginName,
	Name:      "query_omitted_count_total",
	Help:      "Total count of omitted queries",
}, []string{"port", "zone", "alias", "reason", "client_ip"})

var commonLabels = []string{"port", "zone", "alias", "resolver", "host", "result"}

var promResolveCountTotal = promauto.NewCounterVec(prometheus.CounterOpts{
	Namespace: plugin.Namespace,
	Subsystem: pluginName,
	Name:      "resolve_count_total",
	Help:      "Total count of resolve operations",
}, commonLabels)
var promResolveDurationMs = promauto.NewGaugeVec(prometheus.GaugeOpts{
	Namespace: plugin.Namespace,
	Subsystem: pluginName,
	Name:      "resolve_duration_ms",
	Help:      "Duration of resolve operation in milliseconds",
}, commonLabels)
var promResolveDurationMsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
	Namespace: plugin.Namespace,
	Subsystem: pluginName,
	Name:      "resolve_duration_ms_total",
	Help:      "Total duration of resolve operations in milliseconds",
}, commonLabels)

var promResolveIpCountTotal = promauto.NewCounterVec(prometheus.CounterOpts{
	Namespace: plugin.Namespace,
	Subsystem: pluginName,
	Name:      "resolve_ip_count_total",
	Help:      "Total count of answers",
}, []string{"port", "zone", "alias", "resolver", "ip"})

var _ sync.Once
