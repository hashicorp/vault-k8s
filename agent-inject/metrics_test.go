// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package agent_inject

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
)

func Test_incrementInjections(t *testing.T) {
	MustRegisterInjectorMetrics(prometheus.DefaultRegisterer)

	tests := map[string]struct {
		namespace      string
		mutateResponse MutateResponse
		expectedLabels map[string]string
	}{
		"init_only": {
			namespace: "init",
			mutateResponse: MutateResponse{
				InjectedInit:    true,
				InjectedSidecar: false,
			},
			expectedLabels: map[string]string{
				metricsLabelNamespace: "init",
				metricsLabelType:      metricsLabelTypeInitOnly,
			},
		},
		"sidecar_only": {
			namespace: "sidecar",
			mutateResponse: MutateResponse{
				InjectedInit:    false,
				InjectedSidecar: true,
			},
			expectedLabels: map[string]string{
				metricsLabelNamespace: "sidecar",
				metricsLabelType:      metricsLabelTypeSidecarOnly,
			},
		},
		"init_and_sidecar": {
			namespace: "both",
			mutateResponse: MutateResponse{
				InjectedInit:    true,
				InjectedSidecar: true,
			},
			expectedLabels: map[string]string{
				metricsLabelNamespace: "both",
				metricsLabelType:      metricsLabelTypeBoth,
			},
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Cleanup(func() {
				injectionsByNamespace.Reset()
			})
			incrementInjections(test.namespace, test.mutateResponse)
			assert.Equal(t, 1, testutil.CollectAndCount(injectionsByNamespace))
			check := injectionsByNamespace.With(prometheus.Labels(test.expectedLabels))
			assert.Equal(t, float64(1), testutil.ToFloat64(check))
		})
	}
}
