package injector

import (
	"fmt"
	"strings"
	"testing"

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
