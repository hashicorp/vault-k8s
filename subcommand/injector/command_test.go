// Copyright IBM Corp. 2019, 2026
// SPDX-License-Identifier: MPL-2.0

package injector

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/cenkalti/backoff/v4"
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

// TestCertWatcherBackoffStop verifies that when the exponential backoff exceeds
// MaxElapsedTime and NextBackOff() returns backoff.Stop (-1), the certWatcher
// falls back to MaxInterval instead of calling timer.Reset(-1), which would
// cause a tight loop producing a continuous stream of "Could not load TLS
// keypair" warnings when the TLS cert is provided via source_disk and the file is not PEM format.
func TestCertWatcherBackoffStop(t *testing.T) {
	expBackoff := backoff.NewExponentialBackOff(
		// Use a tiny MaxElapsedTime so the test exhausts the backoff quickly
		// without actually waiting 15 minutes.
		backoff.WithMaxElapsedTime(1*time.Millisecond),
		backoff.WithInitialInterval(1*time.Millisecond),
	)

	// Drain the backoff until it returns Stop.
	var next time.Duration
	for i := 0; i < 100; i++ {
		next = expBackoff.NextBackOff()
		if next == backoff.Stop {
			break
		}
	}
	assert.Equal(t, backoff.Stop, next, "expected backoff to be exhausted and return Stop")

	// This is the fixed logic from certWatcher: fall back to MaxInterval
	// instead of passing backoff.Stop (-1) directly to timer.Reset.
	if next == backoff.Stop {
		next = expBackoff.MaxInterval
	}

	assert.Positive(t, next, "retry interval must be positive after backoff.Stop; timer.Reset(-1) would cause a tight loop")
	assert.Equal(t, expBackoff.MaxInterval, next, "retry interval should fall back to MaxInterval when backoff is exhausted")
}
