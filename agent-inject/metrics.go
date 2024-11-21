package agent_inject

import (
	"slices"

	"github.com/prometheus/client_golang/prometheus"
	admissionv1 "k8s.io/api/admission/v1"
)

const (
	metricsNamespace         = "vault"
	metricsSubsystem         = "agent_injector"
	metricsLabelNamespace    = "namespace"
	metricsLabelType         = "injection_type"
	metricsLabelTypeDefault  = "sidecar"
	metricsLabelTypeInitOnly = "init_only"
)

var (
	requestQueue = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: metricsNamespace,
		Subsystem: metricsSubsystem,
		Name:      "request_queue_total",
		Help:      "Total count of webhook requests in the queue",
	})

	requestProcessingTime = prometheus.NewHistogram(prometheus.HistogramOpts{
		Namespace: metricsNamespace,
		Subsystem: metricsSubsystem,
		Name:      "request_processing_duration_ms",
		Help:      "Histogram of webhook request processing times in milliseconds",
		Buckets:   []float64{5, 10, 25, 50, 75, 100, 250, 500, 1000, 2500, 5000, 7500, 10000},
	})

	injectionsByNamespace = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: metricsNamespace,
		Subsystem: metricsSubsystem,
		Name:      "injections_by_namespace_total",
		Help:      "Total count of Agent Sidecar injections by namespace",
	}, []string{metricsLabelNamespace, metricsLabelType})

	failedInjectionsByNamespace = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: metricsNamespace,
		Subsystem: metricsSubsystem,
		Name:      "failed_injections_by_namespace_total",
		Help:      "Total count of failed Agent Sidecar injections by namespace",
	}, []string{metricsLabelNamespace})
)

func incrementInjections(namespace string, res admissionv1.AdmissionResponse) {
	typeLabel := metricsLabelTypeDefault
	if slices.Contains(res.Warnings, warningInitOnlyInjection) {
		typeLabel = metricsLabelTypeInitOnly
	}

	injectionsByNamespace.With(prometheus.Labels{
		metricsLabelNamespace: namespace,
		metricsLabelType:      typeLabel,
	}).Inc()
}

func incrementInjectionFailures(namespace string) {
	failedInjectionsByNamespace.With(prometheus.Labels{metricsLabelNamespace: namespace}).Inc()
}

func MustRegisterInjectorMetrics(registry prometheus.Registerer) {
	registry.MustRegister(
		requestQueue,
		requestProcessingTime,
		injectionsByNamespace,
		failedInjectionsByNamespace,
	)
}
