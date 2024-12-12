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
		noIncrement    bool
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
		"no_injection": {
			namespace: "none",
			mutateResponse: MutateResponse{
				InjectedInit:    false,
				InjectedSidecar: false,
			},
			expectedLabels: nil,
			noIncrement:    true,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Cleanup(func() {
				injectionsByNamespace.Reset()
			})

			expInc := 1
			if test.noIncrement {
				expInc = 0
			}

			incrementInjections(test.namespace, test.mutateResponse)
			assert.Equal(t, expInc, testutil.CollectAndCount(injectionsByNamespace))
			if !test.noIncrement {
				check := injectionsByNamespace.With(prometheus.Labels(test.expectedLabels))
				assert.Equal(t, float64(1), testutil.ToFloat64(check))
			}
		})
	}
}
