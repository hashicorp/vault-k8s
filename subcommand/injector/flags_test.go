// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package injector

import (
	"os"
	"strconv"
	"testing"

	"github.com/hashicorp/go-hclog"
)

func TestCommandLogLevel(t *testing.T) {
	tests := []struct {
		level         string
		expectedLevel hclog.Level
		expectedErr   bool
	}{
		// info
		{level: "info", expectedLevel: hclog.Info, expectedErr: false},
		{level: "INFO", expectedLevel: hclog.Info, expectedErr: false},
		{level: "inFO", expectedLevel: hclog.Info, expectedErr: false},
		{level: " info ", expectedLevel: hclog.Info, expectedErr: false},
		{level: " INFO ", expectedLevel: hclog.Info, expectedErr: false},
		{level: "ofni", expectedLevel: hclog.NoLevel, expectedErr: true},
		{level: "inf", expectedLevel: hclog.NoLevel, expectedErr: true},
		// notice (info)
		{level: "notice", expectedLevel: hclog.Info, expectedErr: false},
		{level: "NOTICE", expectedLevel: hclog.Info, expectedErr: false},
		{level: "nOtIcE", expectedLevel: hclog.Info, expectedErr: false},
		{level: " notice ", expectedLevel: hclog.Info, expectedErr: false},
		{level: " NOTICE ", expectedLevel: hclog.Info, expectedErr: false},
		{level: "notify", expectedLevel: hclog.NoLevel, expectedErr: true},
		{level: "eciton", expectedLevel: hclog.NoLevel, expectedErr: true},
		// trace
		{level: "trace", expectedLevel: hclog.Trace, expectedErr: false},
		{level: "TRACE", expectedLevel: hclog.Trace, expectedErr: false},
		{level: "tRaCe", expectedLevel: hclog.Trace, expectedErr: false},
		{level: " trace ", expectedLevel: hclog.Trace, expectedErr: false},
		{level: " TRACE ", expectedLevel: hclog.Trace, expectedErr: false},
		{level: "tracing", expectedLevel: hclog.NoLevel, expectedErr: true},
		{level: "ecart", expectedLevel: hclog.NoLevel, expectedErr: true},
		// debug
		{level: "debug", expectedLevel: hclog.Debug, expectedErr: false},
		{level: "DEBUG", expectedLevel: hclog.Debug, expectedErr: false},
		{level: "dEbUg", expectedLevel: hclog.Debug, expectedErr: false},
		{level: " debug ", expectedLevel: hclog.Debug, expectedErr: false},
		{level: " DEBUG ", expectedLevel: hclog.Debug, expectedErr: false},
		{level: "debugging", expectedLevel: hclog.NoLevel, expectedErr: true},
		{level: "gubed", expectedLevel: hclog.NoLevel, expectedErr: true},
		// warn
		{level: "warn", expectedLevel: hclog.Warn, expectedErr: false},
		{level: "WARN", expectedLevel: hclog.Warn, expectedErr: false},
		{level: "wArN", expectedLevel: hclog.Warn, expectedErr: false},
		{level: " warn ", expectedLevel: hclog.Warn, expectedErr: false},
		{level: " WARN ", expectedLevel: hclog.Warn, expectedErr: false},
		{level: "warnn", expectedLevel: hclog.NoLevel, expectedErr: true},
		{level: "nraw", expectedLevel: hclog.NoLevel, expectedErr: true},
		// warning (warn)
		{level: "warning", expectedLevel: hclog.Warn, expectedErr: false},
		{level: "WARNING", expectedLevel: hclog.Warn, expectedErr: false},
		{level: "wArNiNg", expectedLevel: hclog.Warn, expectedErr: false},
		{level: " warning ", expectedLevel: hclog.Warn, expectedErr: false},
		{level: " WARNING ", expectedLevel: hclog.Warn, expectedErr: false},
		{level: "warnning", expectedLevel: hclog.NoLevel, expectedErr: true},
		{level: "gninnraw", expectedLevel: hclog.NoLevel, expectedErr: true},
		// err
		{level: "err", expectedLevel: hclog.Error, expectedErr: false},
		{level: "ERR", expectedLevel: hclog.Error, expectedErr: false},
		{level: "eRr", expectedLevel: hclog.Error, expectedErr: false},
		{level: " err ", expectedLevel: hclog.Error, expectedErr: false},
		{level: " ERR ", expectedLevel: hclog.Error, expectedErr: false},
		{level: "errors", expectedLevel: hclog.NoLevel, expectedErr: true},
		{level: "rre", expectedLevel: hclog.NoLevel, expectedErr: true},
		// error (err)
		{level: "error", expectedLevel: hclog.Error, expectedErr: false},
		{level: "ERROR", expectedLevel: hclog.Error, expectedErr: false},
		{level: "eRrOr", expectedLevel: hclog.Error, expectedErr: false},
		{level: " error ", expectedLevel: hclog.Error, expectedErr: false},
		{level: " ERROR ", expectedLevel: hclog.Error, expectedErr: false},
		{level: "errors", expectedLevel: hclog.NoLevel, expectedErr: true},
		{level: "rorre", expectedLevel: hclog.NoLevel, expectedErr: true},
		// junk
		{level: "foobar", expectedLevel: hclog.NoLevel, expectedErr: true},
		{level: "junk", expectedLevel: hclog.NoLevel, expectedErr: true},
		{level: "infotracedebug", expectedLevel: hclog.NoLevel, expectedErr: true},
		{level: "0", expectedLevel: hclog.NoLevel, expectedErr: true},
		{level: "1", expectedLevel: hclog.NoLevel, expectedErr: true},
		// default
		{level: "", expectedLevel: hclog.Info, expectedErr: false},
		{level: " ", expectedLevel: hclog.Info, expectedErr: false},
	}

	for _, tt := range tests {
		t.Run(tt.level, func(t *testing.T) {
			cmd := Command{flagLogLevel: tt.level}
			level, err := cmd.logLevel()
			if err != nil && !tt.expectedErr {
				t.Errorf("got error parsing log level, shouldn't have: %s", err)
			}

			if level != tt.expectedLevel {
				t.Errorf("wrong log level: got %d, expected %d", level, tt.expectedLevel)
			}
		})
	}
}

func TestCommandEnvs(t *testing.T) {
	var cmd Command
	tests := []struct {
		env    string
		value  string
		cmdPtr *string
	}{
		{env: "AGENT_INJECT_LISTEN", value: ":8080", cmdPtr: &cmd.flagListen},
		{env: "AGENT_INJECT_VAULT_ADDR", value: "http://vault:8200", cmdPtr: &cmd.flagVaultService},
		{env: "AGENT_INJECT_PROXY_ADDR", value: "http://proxy:3128", cmdPtr: &cmd.flagProxyAddress},
		{env: "AGENT_INJECT_VAULT_AUTH_PATH", value: "auth-path-test", cmdPtr: &cmd.flagVaultAuthPath},
		{env: "AGENT_INJECT_VAULT_IMAGE", value: "hashicorp/vault:1.12.3", cmdPtr: &cmd.flagVaultImage},
		{env: "AGENT_INJECT_VAULT_NAMESPACE", value: "test-namespace", cmdPtr: &cmd.flagVaultNamespace},
		{env: "AGENT_INJECT_TLS_KEY_FILE", value: "server.key", cmdPtr: &cmd.flagKeyFile},
		{env: "AGENT_INJECT_TLS_CERT_FILE", value: "server.crt", cmdPtr: &cmd.flagCertFile},
		{env: "AGENT_INJECT_TLS_AUTO_HOSTS", value: "foobar.com", cmdPtr: &cmd.flagAutoHosts},
		{env: "AGENT_INJECT_TLS_AUTO", value: "mutationWebhook", cmdPtr: &cmd.flagAutoName},
		{env: "AGENT_INJECT_LOG_LEVEL", value: "info", cmdPtr: &cmd.flagLogLevel},
		{env: "AGENT_INJECT_LOG_FORMAT", value: "standard", cmdPtr: &cmd.flagLogFormat},
		{env: "AGENT_INJECT_RUN_AS_USER", value: "1000", cmdPtr: &cmd.flagRunAsUser},
		{env: "AGENT_INJECT_RUN_AS_GROUP", value: "1001", cmdPtr: &cmd.flagRunAsGroup},
		{env: "AGENT_INJECT_TELEMETRY_PATH", value: "/metrics", cmdPtr: &cmd.flagTelemetryPath},
		{env: "AGENT_INJECT_DEFAULT_TEMPLATE", value: "json", cmdPtr: &cmd.flagDefaultTemplate},
		{env: "AGENT_INJECT_CPU_REQUEST", value: "10m", cmdPtr: &cmd.flagResourceRequestCPU},
		{env: "AGENT_INJECT_MEM_REQUEST", value: "256m", cmdPtr: &cmd.flagResourceRequestMem},
		{env: "AGENT_INJECT_CPU_LIMIT", value: "1000m", cmdPtr: &cmd.flagResourceLimitCPU},
		{env: "AGENT_INJECT_MEM_LIMIT", value: "256m", cmdPtr: &cmd.flagResourceLimitMem},
		{env: "AGENT_INJECT_TEMPLATE_STATIC_SECRET_RENDER_INTERVAL", value: "12s", cmdPtr: &cmd.flagStaticSecretRenderInterval},
		{env: "AGENT_INJECT_TLS_MIN_VERSION", value: "tls13", cmdPtr: &cmd.flagTLSMinVersion},
		{env: "AGENT_INJECT_TLS_CIPHER_SUITES", value: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA", cmdPtr: &cmd.flagTLSCipherSuites},
		{env: "AGENT_INJECT_AUTH_MIN_BACKOFF", value: "5s", cmdPtr: &cmd.flagAuthMinBackoff},
		{env: "AGENT_INJECT_AUTH_MAX_BACKOFF", value: "5s", cmdPtr: &cmd.flagAuthMaxBackoff},
		{env: "AGENT_INJECT_DISABLE_IDLE_CONNECTIONS", value: "auto-auth,caching,templating", cmdPtr: &cmd.flagDisableIdleConnections},
		{env: "AGENT_INJECT_DISABLE_KEEP_ALIVES", value: "auto-auth,caching,templating", cmdPtr: &cmd.flagDisableKeepAlives},
		{env: "AGENT_INJECT_VAULT_CACERT_VALUE", value: "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUZFRENDQXZnQ0NRRGlMY3JOdzMvTUhEQU5CZ2txaGtpRzl3MEJBUXNGQURCS01Rc3dDUVlEVlFRR0V3SlYKVXpFTE1Ba0dBMVVFQ0F3Q1NVd3hFREFPQmdOVkJBY01CME5vYVdOaFoyOHhEVEFMQmdOVkJBb01CRlJsYzNReApEVEFMQmdOVkJBc01CRlJsYzNRd0hoY05Nak13TXpFM01EQTFORFEzV2hjTk1qUXdNekUyTURBMU5EUTNXakJLCk1Rc3dDUVlEVlFRR0V3SlZVekVMTUFrR0ExVUVDQXdDU1V3eEVEQU9CZ05WQkFjTUIwTm9hV05oWjI4eERUQUwKQmdOVkJBb01CRlJsYzNReERUQUxCZ05WQkFzTUJGUmxjM1F3Z2dJaU1BMEdDU3FHU0liM0RRRUJBUVVBQTRJQwpEd0F3Z2dJS0FvSUNBUUR5eDQ1VVNrZUxNOWxqeWR0bldsZ3lrVDhsWk9OL0d3YmlTQllTTk9Pc21XSm90YnBTCnZFZjJrR1pqbHR5UWRQdmN6ZXhKRXRtcTNOTmhuQlRneHV1R005eFpPTUtGZDc0T2c1YkxnOHNLWlJmWExlOXgKZVFTNjlCS2FHQThvejVBTlZaajZaWXNwSzgyMFFPb3phcVY4UmNHMlZxSkRYVm5JYnpDbGM1eUhTOGxTVGw1aAp1eEc4UTZnUVM5WXNkVHJKRzI1OENMcitOTVBMUFZZaHZnaFdqb1ptODM5VExSSnNxOFZEZlp2elk3Y05WMGN4CkRpVERsWE9DeFAxV2pmdHd2MVhOMnNVRDhHK3pwcHo1eXdFVnlkSUErM0UzVksxSW9wNDNZMzBEMVlqRVJsYWYKeDYzT29uSkFpbTJ0aFBVM3VNZHZVY2V3WE1zeGZBZmpYRDJhUFZVVTMvQXpqQlJMSnhCQmlFUUxQSHNZSTZFbQo5OVd4NWpNT3l2ZVFKemNwVHY2cmxYU1l1SnQ2OEc5YzRCUndIOTQrY1I5MWlNYzE0UUZuRGFPREtZaEpLVkRRCnBtZ2gyak9ld0wzeVpXa0JXSmtsWVp5OGR3aFFmRFNwZW82MUN5elIwa3Y0VTVFS0U4Y2VMbmtrVFBkTTdaZWYKYXc4SisxNi9XdkxxQmJ3WkxIcVhXU2FvZ1pVWGEzMk96Q2pwVVBMYVpiNlNLYS9FTFMzRUhVaGdLdmVYdUVEdApUc2VacHZlT3h6RS9obVhvQ0xoblg3aG1zYU52aEJFaDVSVDQyV2lGYm41Ky91T1ZaVjBpdG55Z05XNEEvSVNhCmlpRFZOenlyck1VU2JNemxxNGljUFJBNWFqVWc5WXRzZ0hiVi9lQXZEK0FhQVN5WkpvU1RwU0p5MHdJREFRQUIKTUEwR0NTcUdTSWIzRFFFQkN3VUFBNElDQVFDN0l5c2NOL1oyYVYxTmRwcnFJMjhna1pGUUlSeitndHpJQ091VApEK3E0SFYzUkxQb2lQTjNzM0hzT2ZuM2dwQnA2NkRack12a3ZVUm9IZ2tXa0hYcTdLbEJETXRHa0xGSFdiUGpsCjU1TlJpUjBVcGg0WVgraWlUUXQ3UWRlZkdGOVUyNnhjS05Band0ZkkrWXFUaFcwNHZ2TUNBVUVqallITm9kQnkKT1kreDlYSXhPNUxoMkYzdWdKdWdHUWFPS2swcXN2Y05IZS96dXpuWHFHVGllSnlKVXRmRXROUGxBajU2ZE5oTQpCcGtZeFBCbi9MVndySDYwUHVEWnU4TFg1VzZOcUM1NlpFU2o4VkZFSzgvQTJ6cmhMdU8wRnI0Z2M0VDNiOUV0ClE5clpNcHFRcWRtY2oxL0s3a0taT1lpSVFoMWFNZ1VLY1Urc2ZMUFo3Yi9jUGtqbDJFZ2ZnM3dvSDRDL3QyejQKWG1iQldpSy9MZVArei9uMktucUV1Z2dBOTVQbjJQbnB5NERoTUF1ZVdZWFdNRVdwaTBpS2lOSDloOStvUGo0QgpVWU1YTXIwLy9UMDZ3VWhzZGl0NElGK2E4akF1QjR0R0xlWktGNVUreW5vakZLdmhvZy9FZkpiSGNVekc0TTh1CkFnSXZHbUx6TXUzYWw2WmdlREZJSDlseUFGQVdhMDdhWGZMZmJtdXE3b252QkRjUWE3eWlJaDNFYmhSZVJxcXYKNDkvMHltTGF4M2NQRFcvOU5xOEhUQ1k5R0ZRSGdLTzNIMjI5NWVaWEJRcjJOV0pheEFkS3Vqay9lSEhvQUpXOApOdlF2M1NMeFNJeG9RQWV6dXhSS25Db2hQVGdDNTMvUmtLZGQrYklabDhkOUhVdG5XUTlBQUEvQ0xYeWhIZVJBCi9Kci9sZz09Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0K", cmdPtr: &cmd.flagVaultCACertValue},
	}

	for _, tt := range tests {
		t.Run(tt.env, func(t *testing.T) {
			if err := os.Setenv(tt.env, tt.value); err != nil {
				t.Errorf("got error setting env, shouldn't have: %s", err)
			}
			defer os.Unsetenv(tt.env)

			if err := cmd.parseEnvs(); err != nil {
				t.Errorf("got error parsing envs, shouldn't have: %s", err)
			}

			if *tt.cmdPtr != tt.value {
				t.Errorf("env wasn't parsed, should have been: got %s, expected %s", *tt.cmdPtr, tt.value)
			}
		})
	}
}

func TestCommandEnvBools(t *testing.T) {
	var cmd Command
	tests := []struct {
		env    string
		value  bool
		cmdPtr *bool
	}{
		{env: "AGENT_INJECT_REVOKE_ON_SHUTDOWN", value: true, cmdPtr: &cmd.flagRevokeOnShutdown},
		{env: "AGENT_INJECT_REVOKE_ON_SHUTDOWN", value: false, cmdPtr: &cmd.flagRevokeOnShutdown},
		{env: "AGENT_INJECT_RUN_AS_SAME_USER", value: true, cmdPtr: &cmd.flagRunAsSameUser},
		{env: "AGENT_INJECT_RUN_AS_SAME_USER", value: false, cmdPtr: &cmd.flagRunAsSameUser},
		{env: "AGENT_INJECT_SET_SECURITY_CONTEXT", value: true, cmdPtr: &cmd.flagSetSecurityContext},
		{env: "AGENT_INJECT_SET_SECURITY_CONTEXT", value: false, cmdPtr: &cmd.flagSetSecurityContext},
		{env: "AGENT_INJECT_USE_LEADER_ELECTOR", value: true, cmdPtr: &cmd.flagUseLeaderElector},
		{env: "AGENT_INJECT_USE_LEADER_ELECTOR", value: false, cmdPtr: &cmd.flagUseLeaderElector},
		{env: "AGENT_INJECT_TEMPLATE_CONFIG_EXIT_ON_RETRY_FAILURE", value: true, cmdPtr: &cmd.flagExitOnRetryFailure},
		{env: "AGENT_INJECT_TEMPLATE_CONFIG_EXIT_ON_RETRY_FAILURE", value: false, cmdPtr: &cmd.flagExitOnRetryFailure},
	}

	for _, tt := range tests {
		t.Run(tt.env, func(t *testing.T) {
			if err := os.Setenv(tt.env, strconv.FormatBool(tt.value)); err != nil {
				t.Errorf("got error setting env, shouldn't have: %s", err)
			}
			defer os.Unsetenv(tt.env)

			if err := cmd.parseEnvs(); err != nil {
				t.Errorf("got error parsing envs, shouldn't have: %s", err)
			}

			if *tt.cmdPtr != tt.value {
				t.Errorf("env wasn't parsed, should have been: got %t, expected %t", *tt.cmdPtr, tt.value)
			}
		})
	}
}
