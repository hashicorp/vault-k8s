// Copyright IBM Corp. 2019, 2026
// SPDX-License-Identifier: MPL-2.0

package injector

import (
	"fmt"
	"github.com/cenkalti/backoff/v4"
	"github.com/stretchr/testify/assert"
	"strings"
	"testing"
	"testing/synctest"
	"time"
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
	synctest.Test(t, func(t *testing.T) {
		expBackoff := newCertWatcherBackoff()
		// Sleeping for more than the default 15 minutes MaxElapsedTime and 1 hour (defaultLoopTime), 90 minutes of virtual time
		time.Sleep(90 * time.Minute)

		// With WithMaxElapsedTime(0), NextBackOff() must still return a valid positive retry
		// duration and NOT backoff.Stop (-1), even after 1 hour of elapsed time.
		for i := 0; i < 100; i++ {
			next := expBackoff.NextBackOff()
			assert.NotEqual(t, backoff.Stop, next, "NextBackOff should never return backoff.Stop when MaxElapsedTime is 0")
			assert.Positive(t, next, "retry interval must be positive to prevent tight loop")
		}
	})
}
