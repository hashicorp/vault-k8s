// Copyright IBM Corp. 2019, 2025
// SPDX-License-Identifier: MPL-2.0

package agent_inject

import (
	"errors"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
)

func Test_incrementInjections(t *testing.T) {
	reg := prometheus.NewRegistry()
	MustRegisterInjectorMetrics(reg)

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

func Test_incrementRequests(t *testing.T) {
	one := 1.0
	reg := prometheus.NewRegistry()
	MustRegisterInjectorMetrics(reg)

	tests := map[string]struct {
		err error
	}{
		"valid_request":        {err: nil},
		"invalid_content_type": {err: errors.New("Invalid content-type: ")},
		"error_reading_body":   {err: errors.New("error reading request body: ")},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			// Unlike CounterVec, Counter does not have a Reset() method. As a workaround, we can
			// collect the before and after counts and assert that the difference is 0 or 1, as
			// applicable.
			reqsExpected := testutil.ToFloat64(requestsReceived) + one
			errsExpected := testutil.ToFloat64(requestsErrored)
			if test.err != nil {
				errsExpected += one
			}

			incrementRequests(test.err)
			assert.Equal(t, reqsExpected, testutil.ToFloat64(requestsReceived))
			assert.Equal(t, errsExpected, testutil.ToFloat64(requestsErrored))
		})
	}
}
