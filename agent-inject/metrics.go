// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package agent_inject

import (
	"github.com/prometheus/client_golang/prometheus"
)

const (
	metricsNamespace            = "vault"
	metricsSubsystem            = "agent_injector"
	metricsLabelNamespace       = "namespace"
	metricsLabelType            = "injection_type"
	metricsLabelTypeBoth        = "init_and_sidecar"
	metricsLabelTypeInitOnly    = "init_only"
	metricsLabelTypeSidecarOnly = "sidecar_only"
)

var (
	requestQueue = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: metricsNamespace,
		Subsystem: metricsSubsystem,
		Name:      "request_queue_length",
		Help:      "Count of webhook requests in the injector's queue",
	})

	requestProcessingTime = prometheus.NewHistogram(prometheus.HistogramOpts{
		Namespace: metricsNamespace,
		Subsystem: metricsSubsystem,
		Name:      "request_processing_duration_ms",
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

func incrementInjections(namespace string, res MutateResponse) {
	// Injection type can be one of: init_and_sidecar (default); init_only; or sidecar_only
	typeLabel := metricsLabelTypeBoth
	if res.InjectedInit && !res.InjectedSidecar {
		typeLabel = metricsLabelTypeInitOnly
	} else if res.InjectedSidecar && !res.InjectedInit {
		typeLabel = metricsLabelTypeSidecarOnly
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
