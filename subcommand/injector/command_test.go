// Copyright IBM Corp. 2019, 2026
// SPDX-License-Identifier: MPL-2.0

package injector

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault-k8s/helper/cert"
	"github.com/stretchr/testify/assert"
)

func TestTLSConfig(t *testing.T) {
	tests := map[string]struct {
		tlsVersion    string
		suites        string
		expectedError error
	}{
		"defaults": {
			tlsVersion:    defaultTLSMinVersion,
			suites:        "",
			expectedError: nil,
		},
		"bad tls": {
			tlsVersion:    "tls1000",
			suites:        "",
			expectedError: fmt.Errorf(`invalid or unsupported TLS version "tls1000"`),
		},
		"non-default tls": {
			tlsVersion:    "tls13",
			suites:        "",
			expectedError: nil,
		},
		"suites specified": {
			tlsVersion:    defaultTLSMinVersion,
			suites:        "TLS_RSA_WITH_AES_128_GCM_SHA256,TLS_RSA_WITH_AES_256_GCM_SHA384",
			expectedError: nil,
		},
		"invalid suites specified": {
			tlsVersion:    defaultTLSMinVersion,
			suites:        "suite1,suite2,suite3",
			expectedError: fmt.Errorf(`failed to parse TLS cipher suites list "suite1,suite2,suite3": unsupported cipher "suite1"`),
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			c := &Command{}
			c.flagTLSMinVersion = tc.tlsVersion
			c.flagTLSCipherSuites = tc.suites
			result, err := c.makeTLSConfig()
			assert.Equal(t, tc.expectedError, err)
			if tc.expectedError == nil {
				assert.NotZero(t, result.MinVersion)
				if len(tc.suites) == 0 {
					assert.Nil(t, result.CipherSuites)
				} else {
					assert.Len(t, result.CipherSuites, len(strings.Split(tc.suites, ",")))
				}
			}
		})
	}
}

// TestCertWatcherBackoff verifies that configuring exponential backoff with
// MaxElapsedTime = 0 never returns backoff.Stop (-1) and keeps retrying at
// intervals bounded by MaxInterval, preventing tight loops when certificate updates fail.
func TestCertWatcherBackoff(t *testing.T) {
	c := &Command{}
	logger := hclog.NewNullLogger()

	// Simulate invalid certificate bundle (e.g. non-PEM data on disk)
	invalidBundle := cert.Bundle{
		Cert: []byte("not-a-valid-pem-cert"),
		Key:  []byte("not-a-valid-pem-key"),
	}

	// Verify updateCertificate fails on invalid keypair
	err := c.updateCertificate(context.Background(), nil, invalidBundle, nil, nil, logger)
	assert.Error(t, err, "expected updateCertificate to fail with invalid keypair")
	assert.Contains(t, err.Error(), "tls: failed to find any PEM data")

	// Verify exponential backoff configured with MaxElapsedTime = 0 never returns Stop on repeated failures
	expBackoff := backoff.NewExponentialBackOff(backoff.WithMaxElapsedTime(0))
	assert.Equal(t, time.Duration(0), expBackoff.MaxElapsedTime)

	for i := 0; i < 100; i++ {
		err = c.updateCertificate(context.Background(), nil, invalidBundle, nil, nil, logger)
		assert.Error(t, err)

		next := expBackoff.NextBackOff()
		assert.NotEqual(t, backoff.Stop, next, "NextBackOff should never return backoff.Stop when MaxElapsedTime is 0")
		assert.Positive(t, next, "retry interval must be positive to prevent tight loop")
	}
}
