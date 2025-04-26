// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package agent

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewConfig(t *testing.T) {
	annotations := map[string]string{
		AnnotationAgentImage:                            "vault",
		AnnotationVaultService:                          "https://vault:8200",
		AnnotationAgentStatus:                           "",
		AnnotationAgentRequestNamespace:                 "foobar",
		AnnotationVaultRole:                             "foobar",
		AnnotationAgentPrePopulate:                      "true",
		AnnotationAgentPrePopulateOnly:                  "true",
		AnnotationVaultTLSServerName:                    "foobar.server",
		AnnotationVaultCACert:                           "ca-cert",
		AnnotationVaultCAKey:                            "ca-key",
		AnnotationVaultClientCert:                       "client-cert",
		AnnotationVaultClientKey:                        "client-key",
		AnnotationVaultSecretVolumePath:                 "/vault/secrets",
		AnnotationProxyAddress:                          "http://proxy:3128",
		"vault.hashicorp.com/agent-inject-secret-foo":   "db/creds/foo",
		"vault.hashicorp.com/agent-inject-template-foo": "template foo",
		"vault.hashicorp.com/agent-inject-secret-bar":   "db/creds/bar",

		// render this secret at a different path
		"vault.hashicorp.com/agent-inject-secret-different-path":                "different-path",
		fmt.Sprintf("%s-%s", AnnotationVaultSecretVolumePath, "different-path"): "/etc/container_environment",

		// render this secret from a template on disk
		"vault.hashicorp.com/agent-inject-secret-with-file-template":                  "with-file-template",
		fmt.Sprintf("%s-%s", AnnotationAgentInjectTemplateFile, "with-file-template"): "/etc/file-template",

		"vault.hashicorp.com/agent-inject-template-just-template": "just-template1",
		"vault.hashicorp.com/secret-volume-path-just-template":    "/custom/path",
		"vault.hashicorp.com/agent-inject-command-just-template":  "/tmp/smth.sh",
		"vault.hashicorp.com/agent-inject-file-just-template":     ".env",
		"vault.hashicorp.com/agent-inject-perms-just-template":    "0600",

		"vault.hashicorp.com/agent-inject-template-file-just-template-file": "just-template-file",

		"vault.hashicorp.com/agent-inject-command-bar": "pkill -HUP app",

		"vault.hashicorp.com/agent-inject-secret-baz":        "db/creds/baz",
		"vault.hashicorp.com/agent-inject-template-baz":      `[[ with secret "db/creds/baz" ]][[ range $k, $v := .Data ]][[ $k ]]: [[ $v ]]\n[[ end ]][[ end ]]`,
		"vault.hashicorp.com/agent-template-left-delim-baz":  "[[",
		"vault.hashicorp.com/agent-template-right-delim-baz": "]]",

		AnnotationAgentCacheEnable: "true",
	}

	pod := testPod(annotations)

	agentConfig := basicAgentConfig()
	err := Init(pod, agentConfig)
	if err != nil {
		t.Errorf("got error initialising pod, shouldn't have: %s", err)
	}

	agent, err := New(pod)
	if err != nil {
		t.Errorf("got error creating agent, shouldn't have: %s", err)
	}

	cfg, err := agent.newConfig(true)
	if err != nil {
		t.Errorf("got error creating Vault config, shouldn't have: %s", err)
	}

	config := &Config{}
	if err := json.Unmarshal(cfg, config); err != nil {
		t.Errorf("got error unmarshalling Vault config, shouldn't have: %s", err)
	}

	if config.ExitAfterAuth != true {
		t.Error("exit_after_auth should have been true, it wasn't")
	}

	if config.Vault.TLSSkipVerify != false {
		t.Error("tls_skip_verify should have been false, it wasn't")
	}

	if config.Vault.TLSServerName != annotations[AnnotationVaultTLSServerName] {
		t.Errorf("tls_server_name: expected %s, got %s", annotations[AnnotationVaultTLSServerName], config.Vault.TLSServerName)
	}

	if config.Vault.CACert != annotations[AnnotationVaultCACert] {
		t.Errorf("ca_cert: expected %s, got %s", annotations[AnnotationVaultCACert], config.Vault.CACert)
	}

	if config.Vault.CAPath != annotations[AnnotationVaultCAKey] {
		t.Errorf("ca_key: expected %s, got %s", annotations[AnnotationVaultCAKey], config.Vault.CAPath)
	}

	if config.Vault.ClientCert != annotations[AnnotationVaultClientCert] {
		t.Errorf("client_cert: expected %s, got %s", annotations[AnnotationVaultClientCert], config.Vault.ClientCert)
	}

	if config.Vault.ClientKey != annotations[AnnotationVaultClientKey] {
		t.Errorf("client_key: expected %s, got %s", annotations[AnnotationVaultClientKey], config.Vault.ClientKey)
	}

	if config.AutoAuth.Method.Config["role"] != annotations[AnnotationVaultRole] {
		t.Errorf("auto_auth role: expected role to be %s, got %s", annotations[AnnotationVaultRole], config.AutoAuth.Method.Config["role"])
	}

	if config.AutoAuth.Method.Type != annotations[AnnotationVaultAuthType] {
		t.Errorf("auto_auth mount type: expected type to be %s, got %s", annotations[AnnotationVaultAuthType], config.AutoAuth.Method.Type)
	}

	if config.AutoAuth.Method.MountPath != annotations[AnnotationVaultAuthPath] {
		t.Errorf("auto_auth mount path: expected path to be %s, got %s", annotations[AnnotationVaultAuthPath], config.AutoAuth.Method.MountPath)
	}

	if len(config.Listener) != 0 || config.Cache != nil {
		t.Error("agent Cache should be disabled for init containers")
	}

	if len(config.Templates) != 7 {
		t.Errorf("expected 7 templates, got %d", len(config.Templates))
	}

	for _, template := range config.Templates {
		if strings.Contains(template.Destination, "foo") {
			if template.Destination != "/vault/secrets/foo" {
				t.Errorf("expected template destination to be %s, got %s", "/vault/secrets/foo", template.Destination)
			}

			if template.Contents != "template foo" {
				t.Errorf("expected template contents to be %s, got %s", "template foo", template.Contents)
			}

			if template.LeftDelim != DefaultLeftDelim || template.RightDelim != DefaultRightDelim {
				t.Errorf("expected default delimiters to be %s (left) and %s (right), got %s (left) and %s (right)", DefaultLeftDelim, DefaultRightDelim, template.LeftDelim, template.RightDelim)
			}
		} else if strings.Contains(template.Destination, "bar") {
			if template.Destination != "/vault/secrets/bar" {
				t.Errorf("expected template destination to be %s, got %s", "/vault/secrets/bar", template.Destination)
			}

			if !strings.Contains(template.Contents, "with secret \"db/creds/bar\"") {
				t.Errorf("expected template contents to contain %s, got %s", "with secret \"db/creds/bar\"", template.Contents)
			}
			if !strings.Contains(template.Command, "pkill -HUP app") {
				t.Errorf("expected command contents to contain %s, got %s", "pkill -HUP app", template.Command)
			}
		} else if strings.Contains(template.Destination, "different-path") {
			if template.Destination != "/etc/container_environment/different-path" {
				t.Errorf("expected template destination to be %s, got %s", "/etc/container_environment", template.Destination)
			}
		} else if strings.Contains(template.Destination, "with-file-template") {
			if template.Source != "/etc/file-template" {
				t.Errorf("expected template file path to be %s, got %s", "/etc/file-template", template.Source)
			}
			if template.Contents != "" {
				t.Errorf("expected template contents to be empty, got %s", template.Contents)
			}
		} else if template.Contents == "just-template1" {
			if template.Destination != "/custom/path/.env" {
				t.Errorf("expected template destination to be %s, got %s", "/custom/path/.env", template.Destination)
			}
			if template.Perms != "0600" {
				t.Errorf("expected template perms to be %s, got %s", "0600", template.Perms)
			}
			if template.Command != "/tmp/smth.sh" {
				t.Errorf("expected template command to be %s, got %s", "/tmp/smth.sh", template.Command)
			}
		} else if template.Source == "just-template-file" {
			if template.Destination != "/vault/secrets/just-template-file" {
				t.Errorf("expected template destination to be %s, got %s", "/vault/secrets/just-template-file", template.Destination)
			}
		} else if strings.Contains(template.Destination, "baz") {
			if template.LeftDelim != "[[" || template.RightDelim != "]]" {
				t.Errorf("expected default delimiters to be %s (left) and %s (right), got %s (left) and %s (right)", "[[", "]]", template.LeftDelim, template.RightDelim)
			}
		} else {
			t.Error("shouldn't have got here")
		}
	}
}

func TestFilePathAndName(t *testing.T) {
	tests := []struct {
		name        string
		annotations map[string]string
		destination string
	}{
		{
			"just secret",
			map[string]string{
				"vault.hashicorp.com/agent-inject-secret-foo": "db/creds/foo",
			},
			secretVolumePath + "/foo",
		},
		{
			"with relative file path",
			map[string]string{
				"vault.hashicorp.com/agent-inject-secret-foo": "db/creds/foo",
				"vault.hashicorp.com/agent-inject-file-foo":   "nested/foofile",
			},
			secretVolumePath + "/nested/foofile",
		},
		{
			"with absolute file path",
			map[string]string{
				"vault.hashicorp.com/agent-inject-secret-foo": "db/creds/foo",
				"vault.hashicorp.com/agent-inject-file-foo":   "/special/volume/foofile",
			},
			secretVolumePath + "/special/volume/foofile",
		},
		{
			"with global volume mount set, long file name",
			map[string]string{
				"vault.hashicorp.com/agent-inject-secret-foo": "db/creds/foo",
				"vault.hashicorp.com/agent-inject-file-foo":   "foofile_name_is_very_very_very_long",
				"vault.hashicorp.com/secret-volume-path":      "/new/mount/path",
			},
			"/new/mount/path/foofile_name_is_very_very_very_long",
		},
		{
			"with global volume mount set, absolute file path",
			map[string]string{
				"vault.hashicorp.com/agent-inject-secret-foo": "db/creds/foo",
				"vault.hashicorp.com/agent-inject-file-foo":   "/special/foofile",
				"vault.hashicorp.com/secret-volume-path":      "/new/mount/path",
			},
			"/new/mount/path/special/foofile",
		},
		{
			"with secret volume mount set, relative file path",
			map[string]string{
				"vault.hashicorp.com/agent-inject-secret-foo": "db/creds/foo",
				"vault.hashicorp.com/agent-inject-file-foo":   "nested/foofile",
				"vault.hashicorp.com/secret-volume-path-foo":  "/new/mount/path",
			},
			"/new/mount/path/nested/foofile",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pod := testPod(tt.annotations)

			agentConfig := basicAgentConfig()
			err := Init(pod, agentConfig)
			if err != nil {
				t.Errorf("got error initialising pod, shouldn't have: %s", err)
			}

			agent, err := New(pod)
			if err != nil {
				t.Errorf("got error creating agent, shouldn't have: %s", err)
			}
			cfg, err := agent.newConfig(true)
			if err != nil {
				t.Errorf("got error creating Vault config, shouldn't have: %s", err)
			}

			config := &Config{}
			if err := json.Unmarshal(cfg, config); err != nil {
				t.Errorf("got error unmarshalling Vault config, shouldn't have: %s", err)
			}
			if config.Templates[0].Destination != tt.destination {
				t.Errorf("wrong destination: %s != %s", config.Templates[0].Destination, tt.destination)
			}
		})
	}
}

func TestFilePermission(t *testing.T) {
	tests := []struct {
		name        string
		annotations map[string]string
		permission  string
	}{
		{
			"just secret",
			map[string]string{
				"vault.hashicorp.com/agent-inject-secret-foo": "db/creds/foo",
				"vault.hashicorp.com/agent-inject-perms-foo":  "0600",
			},
			"0600",
		},
		{
			"just secret without permission",
			map[string]string{
				"vault.hashicorp.com/agent-inject-secret-foo": "db/creds/foo",
			},
			"",
		},
		{
			"with relative file path",
			map[string]string{
				"vault.hashicorp.com/agent-inject-secret-foo": "db/creds/foo",
				"vault.hashicorp.com/agent-inject-file-foo":   "nested/foofile",
				"vault.hashicorp.com/agent-inject-perms-foo":  "0600",
			},
			"0600",
		},
		{
			"with relative file path without permission",
			map[string]string{
				"vault.hashicorp.com/agent-inject-secret-foo": "db/creds/foo",
				"vault.hashicorp.com/agent-inject-file-foo":   "nested/foofile",
			},
			"",
		},
		{
			"with absolute file path",
			map[string]string{
				"vault.hashicorp.com/agent-inject-secret-foo": "db/creds/foo",
				"vault.hashicorp.com/agent-inject-file-foo":   "/special/volume/foofile",
				"vault.hashicorp.com/agent-inject-perms-foo":  "0600",
			},
			"0600",
		},
		{
			"with absolute file path without permission",
			map[string]string{
				"vault.hashicorp.com/agent-inject-secret-foo": "db/creds/foo",
				"vault.hashicorp.com/agent-inject-file-foo":   "/special/volume/foofile",
			},
			"",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pod := testPod(tt.annotations)

			agentConfig := basicAgentConfig()
			err := Init(pod, agentConfig)
			if err != nil {
				t.Errorf("got error initialising pod, shouldn't have: %s", err)
			}

			agent, err := New(pod)
			if err != nil {
				t.Errorf("got error creating agent, shouldn't have: %s", err)
			}
			cfg, err := agent.newConfig(true)
			if err != nil {
				t.Errorf("got error creating Vault config, shouldn't have: %s", err)
			}

			config := &Config{}
			if err := json.Unmarshal(cfg, config); err != nil {
				t.Errorf("got error unmarshalling Vault config, shouldn't have: %s", err)
			}
			if config.Templates[0].Perms != tt.permission {
				t.Errorf("wrong permission: %s != %s", config.Templates[0].Perms, tt.permission)
			}
		})
	}
}

func TestErrMissingKey(t *testing.T) {
	tests := []struct {
		name          string
		annotations   map[string]string
		errMissingKey bool
	}{
		{
			"just secret",
			map[string]string{
				"vault.hashicorp.com/agent-inject-secret-foo":  "db/creds/foo",
				"vault.hashicorp.com/error-on-missing-key-foo": "true",
			},
			true,
		},
		{
			"just secret without error on missing key",
			map[string]string{
				"vault.hashicorp.com/agent-inject-secret-foo": "db/creds/foo",
			},
			false,
		},
		{
			"with false error on missing key",
			map[string]string{
				"vault.hashicorp.com/agent-inject-secret-foo":  "db/creds/foo",
				"vault.hashicorp.com/error-on-missing-key-foo": "false",
			},
			false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pod := testPod(tt.annotations)

			agentConfig := basicAgentConfig()
			err := Init(pod, agentConfig)
			if err != nil {
				t.Errorf("got error initialising pod, shouldn't have: %s", err)
			}

			agent, err := New(pod)
			if err != nil {
				t.Errorf("got error creating agent, shouldn't have: %s", err)
			}
			cfg, err := agent.newConfig(true)
			if err != nil {
				t.Errorf("got error creating Vault config, shouldn't have: %s", err)
			}

			config := &Config{}
			if err := json.Unmarshal(cfg, config); err != nil {
				t.Errorf("got error unmarshalling Vault config, shouldn't have: %s", err)
			}
			if config.Templates[0].ErrMissingKey != tt.errMissingKey {
				t.Errorf("wrong permission: %v != %v", config.Templates[0].ErrMissingKey, tt.errMissingKey)
			}
		})
	}
}

func TestConfigVaultAgentCacheNotEnabledByDefault(t *testing.T) {
	annotations := map[string]string{}

	pod := testPod(annotations)

	agentConfig := basicAgentConfig()
	err := Init(pod, agentConfig)
	if err != nil {
		t.Errorf("got error initialising pod, shouldn't have: %s", err)
	}

	agent, err := New(pod)
	if err != nil {
		t.Errorf("got error creating agent, shouldn't have: %s", err)
	}

	cfg, err := agent.newConfig(false)
	if err != nil {
		t.Errorf("got error creating Vault config, shouldn't have: %s", err)
	}

	config := &Config{}
	if err := json.Unmarshal(cfg, config); err != nil {
		t.Errorf("got error unmarshalling Vault config, shouldn't have: %s", err)
	}

	if len(config.Listener) != 0 || config.Cache != nil {
		t.Error("agent Cache should be not be enabled by default")
	}
}

func TestConfigVaultAgentCache(t *testing.T) {
	annotations := map[string]string{
		AnnotationAgentCacheEnable:           "true",
		AnnotationAgentCacheUseAutoAuthToken: "force",
		AnnotationAgentCacheListenerPort:     "8100",
	}

	pod := testPod(annotations)

	agentConfig := basicAgentConfig()
	err := Init(pod, agentConfig)
	if err != nil {
		t.Errorf("got error initialising pod, shouldn't have: %s", err)
	}

	agent, err := New(pod)
	if err != nil {
		t.Errorf("got error creating agent, shouldn't have: %s", err)
	}

	cfg, err := agent.newConfig(false)
	if err != nil {
		t.Errorf("got error creating Vault config, shouldn't have: %s", err)
	}

	config := &Config{}
	if err := json.Unmarshal(cfg, config); err != nil {
		t.Errorf("got error unmarshalling Vault config, shouldn't have: %s", err)
	}

	if len(config.Listener) == 0 || config.Cache == nil {
		t.Error("agent Cache should be enabled")
	}

	if config.Cache.UseAutoAuthToken != "force" {
		t.Errorf("agent Cache use_auto_auth_token should be 'force', got %s instead", config.Cache.UseAutoAuthToken)
	}

	if config.Listener[0].Type != "tcp" {
		t.Errorf("agent Cache listener type should be tcp, got %s instead", config.Listener[0].Type)
	}

	if config.Listener[0].Address != "127.0.0.1:8100" {
		t.Errorf("agent Cache listener address should be 127.0.0.1:8100, got %s", config.Listener[0].Address)
	}

	if !config.Listener[0].TLSDisable {
		t.Error("agent Cache listener TLS should be disabled")
	}
}

func TestConfigVaultAgentCache_persistent(t *testing.T) {
	tests := []struct {
		name              string
		annotations       map[string]string
		expectedInitCache bool
		expectedCache     *Cache
		expectedListeners []*Listener
	}{
		{
			name: "cache defaults",
			annotations: map[string]string{
				AnnotationAgentCacheEnable: "true",
			},
			expectedInitCache: true,
			expectedCache: &Cache{
				UseAutoAuthToken: "true",
				Persist: &CachePersist{
					Type: "kubernetes",
					Path: "/vault/agent-cache",
				},
			},
			expectedListeners: []*Listener{
				{
					Type:       "tcp",
					Address:    "127.0.0.1:8200",
					TLSDisable: true,
				},
			},
		},
		{
			name: "exit on err",
			annotations: map[string]string{
				AnnotationAgentCacheEnable:    "true",
				AnnotationAgentCacheExitOnErr: "true",
			},
			expectedInitCache: true,
			expectedCache: &Cache{
				UseAutoAuthToken: "true",
				Persist: &CachePersist{
					Type:      "kubernetes",
					Path:      "/vault/agent-cache",
					ExitOnErr: true,
				},
			},
			expectedListeners: []*Listener{
				{
					Type:       "tcp",
					Address:    "127.0.0.1:8200",
					TLSDisable: true,
				},
			},
		},
		{
			name: "just memory cache when only sidecar",
			annotations: map[string]string{
				AnnotationAgentCacheEnable: "true",
				AnnotationAgentPrePopulate: "false",
			},
			expectedInitCache: false,
			expectedCache: &Cache{
				UseAutoAuthToken: "true",
			},
			expectedListeners: []*Listener{
				{
					Type:       "tcp",
					Address:    "127.0.0.1:8200",
					TLSDisable: true,
				},
			},
		},
		{
			name: "no cache at all with only init container",
			annotations: map[string]string{
				AnnotationAgentCacheEnable:     "true",
				AnnotationAgentPrePopulateOnly: "true",
			},
			expectedInitCache: false,
			expectedCache:     nil,
			expectedListeners: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pod := testPod(tt.annotations)

			agentConfig := basicAgentConfig()
			err := Init(pod, agentConfig)
			require.NoError(t, err, "got error initialising pod: %s", err)

			agent, err := New(pod)
			require.NoError(t, err, "got error creating agent: %s", err)

			initCfg, err := agent.newConfig(true)
			require.NoError(t, err, "got error creating Vault config: %s", err)

			initConfig := &Config{}
			err = json.Unmarshal(initCfg, initConfig)
			require.NoError(t, err, "got error unmarshalling Vault init config: %s", err)

			if tt.expectedInitCache {
				assert.Equal(t, tt.expectedCache, initConfig.Cache)
				assert.Equal(t, tt.expectedListeners, initConfig.Listener)
			} else {
				assert.Nil(t, initConfig.Cache)
				assert.Nil(t, initConfig.Listener)
			}

			sidecarCfg, err := agent.newConfig(false)
			require.NoError(t, err, "got error creating Vault sidecar config: %s", err)

			sidecarConfig := &Config{}
			err = json.Unmarshal(sidecarCfg, sidecarConfig)
			require.NoError(t, err, "got error unmarshalling Vault sidecar config: %s", err)

			assert.Equal(t, tt.expectedCache, sidecarConfig.Cache)
			assert.Equal(t, tt.expectedListeners, sidecarConfig.Listener)
		})
	}
}

func TestConfigVaultAgentTemplateConfig(t *testing.T) {
	tests := []struct {
		name                   string
		annotations            map[string]string
		expectedTemplateConfig *TemplateConfig
	}{
		{
			"exit_on_retry_failure true",
			map[string]string{
				AnnotationTemplateConfigExitOnRetryFailure: "true",
			},
			&TemplateConfig{
				ExitOnRetryFailure:    true,
				MaxConnectionsPerHost: 0,
			},
		},
		{
			"exit_on_retry_failure false",
			map[string]string{
				AnnotationTemplateConfigExitOnRetryFailure: "false",
			},
			&TemplateConfig{
				ExitOnRetryFailure:    false,
				MaxConnectionsPerHost: 0,
			},
		},
		{
			"static_secret_render_interval 10s",
			map[string]string{
				AnnotationTemplateConfigStaticSecretRenderInterval: "10s",
			},
			&TemplateConfig{
				ExitOnRetryFailure:         true,
				StaticSecretRenderInterval: "10s",
				MaxConnectionsPerHost:      0,
			},
		},
		{
			"max_connections_per_host 100",
			map[string]string{
				AnnotationTemplateConfigMaxConnectionsPerHost: "100",
			},
			&TemplateConfig{
				ExitOnRetryFailure:    true,
				MaxConnectionsPerHost: 100,
			},
		},
		{
			"lease_renewal_threshold 0.75",
			map[string]string{
				AnnotationTemplateConfigLeaseRenewalThreshold: "0.75",
			},
			&TemplateConfig{
				ExitOnRetryFailure:    true,
				MaxConnectionsPerHost: 0,
				LeaseRenewalThreshold: 0.75,
			},
		},
		{
			"template_config_empty",
			map[string]string{},
			&TemplateConfig{
				ExitOnRetryFailure:    true,
				MaxConnectionsPerHost: 0,
				LeaseRenewalThreshold: 0,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pod := testPod(tt.annotations)

			agentConfig := basicAgentConfig()
			err := Init(pod, agentConfig)
			require.NoError(t, err)

			agent, err := New(pod)
			require.NoError(t, err)
			cfg, err := agent.newConfig(true)
			require.NoError(t, err)

			config := &Config{}
			err = json.Unmarshal(cfg, config)
			require.NoError(t, err)

			assert.Equal(t, tt.expectedTemplateConfig, config.TemplateConfig)
		})
	}
}

func TestInjectTokenSink(t *testing.T) {
	tokenHelperSink := &Sink{
		Type: "file",
		Config: map[string]interface{}{
			"path": TokenFile,
		},
	}
	injectTokenSink := &Sink{
		Type: "file",
		Config: map[string]interface{}{
			"path": secretVolumePath + "/token",
		},
	}

	tests := []struct {
		name          string
		annotations   map[string]string
		expectedSinks []*Sink
	}{
		{
			"token true",
			map[string]string{
				AnnotationAgentInjectToken: "true",
			},
			[]*Sink{tokenHelperSink, injectTokenSink},
		},
		{
			"token false",
			map[string]string{
				AnnotationAgentInjectToken: "false",
			},
			[]*Sink{tokenHelperSink},
		},
		{
			"custom secret volume path",
			map[string]string{
				AnnotationAgentInjectToken:      "true",
				AnnotationVaultSecretVolumePath: "/new/secrets",
			},
			[]*Sink{
				tokenHelperSink,
				{
					Type: "file",
					Config: map[string]interface{}{
						"path": "/new/secrets/token",
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pod := testPod(tt.annotations)

			agentConfig := basicAgentConfig()
			err := Init(pod, agentConfig)
			require.NoError(t, err)

			agent, err := New(pod)
			require.NoError(t, err)
			cfg, err := agent.newConfig(true)
			require.NoError(t, err)

			config := &Config{}
			err = json.Unmarshal(cfg, config)
			require.NoError(t, err)

			assert.Equal(t, tt.expectedSinks, config.AutoAuth.Sinks)
		})
	}
}

func TestConfigAgentQuit(t *testing.T) {
	tests := []struct {
		name                   string
		annotations            map[string]string
		expectedAgentAPIConfig *AgentAPI
		expectedAddress        string
		expectedCache          *Cache
	}{
		{
			"enable_quit true",
			map[string]string{
				AnnotationAgentEnableQuit: "true",
			},
			&AgentAPI{EnableQuit: true},
			fmt.Sprintf("127.0.0.1:%s", DefaultAgentCacheListenerPort),
			&Cache{},
		},
		{
			"enable_quit true with custom port",
			map[string]string{
				AnnotationAgentEnableQuit:        "true",
				AnnotationAgentCacheListenerPort: "1234",
			},
			&AgentAPI{EnableQuit: true},
			fmt.Sprintf("127.0.0.1:%s", "1234"),
			&Cache{},
		},
		{
			"enable_quit false with no cache listener",
			nil,
			nil,
			fmt.Sprintf("127.0.0.1:%s", DefaultAgentCacheListenerPort),
			nil,
		},
		{
			"enable_quit true with existing cache listener",
			map[string]string{
				AnnotationAgentCacheEnable: "true",
				AnnotationAgentEnableQuit:  "true",
			},
			&AgentAPI{EnableQuit: true},
			fmt.Sprintf("127.0.0.1:%s", DefaultAgentCacheListenerPort),
			&Cache{
				UseAutoAuthToken: "true",
				Persist: &CachePersist{
					Type: "kubernetes",
					Path: "/vault/agent-cache",
				},
			},
		},
		{
			"enable_quit false with existing cache listener",
			map[string]string{
				AnnotationAgentCacheEnable: "true",
				AnnotationAgentEnableQuit:  "false",
			},
			nil,
			fmt.Sprintf("127.0.0.1:%s", DefaultAgentCacheListenerPort),
			&Cache{
				UseAutoAuthToken: "true",
				Persist: &CachePersist{
					Type: "kubernetes",
					Path: "/vault/agent-cache",
				},
			},
		},
		{
			"everything empty",
			map[string]string{},
			nil,
			DefaultAgentCacheListenerPort,
			nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pod := testPod(tt.annotations)

			agentConfig := basicAgentConfig()
			err := Init(pod, agentConfig)
			require.NoError(t, err)

			agent, err := New(pod)
			require.NoError(t, err)
			// create sidecar config
			cfg, err := agent.newConfig(false)
			require.NoError(t, err)

			config := &Config{}
			err = json.Unmarshal(cfg, config)
			require.NoError(t, err)

			if tt.expectedAgentAPIConfig != nil {
				require.NotEmpty(t, config.Listener)
				require.NotNil(t, config.Listener[0].AgentAPI)
				assert.Equal(t, tt.expectedAgentAPIConfig, config.Listener[0].AgentAPI)
				assert.Equal(t, tt.expectedAddress, config.Listener[0].Address)
			} else {
				if len(config.Listener) > 0 {
					assert.Nil(t, config.Listener[0].AgentAPI)
					assert.Equal(t, tt.expectedAddress, config.Listener[0].Address)
				}
			}
			assert.Equal(t, tt.expectedCache, config.Cache)
		})
	}
}

func TestConfigTelemetry(t *testing.T) {
	tests := []struct {
		name              string
		annotations       map[string]string
		expectedTelemetry *Telemetry
	}{
		{
			"annotations that exercise all of the annotations",
			map[string]string{
				"vault.hashicorp.com/agent-telemetry-usage_gauge_period":                     "10m",
				"vault.hashicorp.com/agent-telemetry-maximum_gauge_cardinality":              "500",
				"vault.hashicorp.com/agent-telemetry-disable_hostname":                       "false",
				"vault.hashicorp.com/agent-telemetry-enable_hostname_label":                  "false",
				"vault.hashicorp.com/agent-telemetry-lease_metrics_epsilon":                  "1h",
				"vault.hashicorp.com/agent-telemetry-num_lease_metrics_buckets":              "168",
				"vault.hashicorp.com/agent-telemetry-add_lease_metrics_namespace_labels":     "false",
				"vault.hashicorp.com/agent-telemetry-filter_default":                         "true",
				"vault.hashicorp.com/agent-telemetry-statsite_address":                       "https://foo.com",
				"vault.hashicorp.com/agent-telemetry-statsd_address":                         "https://foo.com",
				"vault.hashicorp.com/agent-telemetry-circonus_api_token":                     "foo",
				"vault.hashicorp.com/agent-telemetry-circonus_api_app":                       "nomad",
				"vault.hashicorp.com/agent-telemetry-circonus_api_url":                       "https://api.circonus.com/v2",
				"vault.hashicorp.com/agent-telemetry-circonus_submission_interval":           "10s",
				"vault.hashicorp.com/agent-telemetry-circonus_submission_url":                "https://api.circonus.com/v2",
				"vault.hashicorp.com/agent-telemetry-circonus_check_id":                      "foo",
				"vault.hashicorp.com/agent-telemetry-circonus_check_force_metric_activation": "false",
				"vault.hashicorp.com/agent-telemetry-circonus_check_instance_id":             "foo:bar",
				"vault.hashicorp.com/agent-telemetry-circonus_check_search_tag":              "foo:bar",
				"vault.hashicorp.com/agent-telemetry-circonus_check_display_name":            "foo",
				"vault.hashicorp.com/agent-telemetry-circonus_check_tags":                    "foo,bar",
				"vault.hashicorp.com/agent-telemetry-circonus_broker_id":                     "foo",
				"vault.hashicorp.com/agent-telemetry-circonus_broker_select_tag":             "foo:bar",
				"vault.hashicorp.com/agent-telemetry-dogstatsd_addr":                         "https://foo.com",
				"vault.hashicorp.com/agent-telemetry-dogstatsd_tags":                         `["foo:bar", "foo:baz"]`,
				"vault.hashicorp.com/agent-telemetry-prometheus_retention_time":              "24h",
				"vault.hashicorp.com/agent-telemetry-stackdriver_project_id":                 "foo",
				"vault.hashicorp.com/agent-telemetry-stackdriver_location":                   "useast-1",
				"vault.hashicorp.com/agent-telemetry-stackdriver_namespace":                  "foo",
				"vault.hashicorp.com/agent-telemetry-stackdriver_debug_logs":                 "false",
				"vault.hashicorp.com/agent-telemetry-prefix_filter":                          `["+vault.token", "-vault.expire", "+vault.expire.num_leases"]`,
			},
			&Telemetry{
				UsageGaugePeriod:                   "10m",
				MaximumGaugeCardinality:            500,
				DisableHostname:                    false,
				EnableHostnameLabel:                false,
				LeaseMetricsEpsilon:                "1h",
				NumLeaseMetricsBuckets:             168,
				AddLeaseMetricsNamespaceLabels:     false,
				FilterDefault:                      true,
				PrefixFilter:                       []string{"+vault.token", "-vault.expire", "+vault.expire.num_leases"},
				StatsiteAddress:                    "https://foo.com",
				StatsdAddress:                      "https://foo.com",
				CirconusApiToken:                   "foo",
				CirconusApiApp:                     "nomad",
				CirconusApiURL:                     "https://api.circonus.com/v2",
				CirconusSubmissionInterval:         "10s",
				CirconusSubmissionURL:              "https://api.circonus.com/v2",
				CirconusCheckID:                    "foo",
				CirconusCheckForceMetricActivation: false,
				CirconusCheckInstanceID:            "foo:bar",
				CirconusCheckSearchTag:             "foo:bar",
				CirconusCheckDisplayName:           "foo",
				CirconusCheckTags:                  "foo,bar",
				CirconusBrokerID:                   "foo",
				CirconusBrokerSelectTag:            "foo:bar",
				DogstatsdAddr:                      "https://foo.com",
				DogstatsdTags:                      []string{"foo:bar", "foo:baz"},
				PrometheusRetentionTime:            "24h",
				StackdriverProjectID:               "foo",
				StackdriverLocation:                "useast-1",
				StackdriverNamespace:               "foo",
				StackdriverDebugLogs:               false,
			},
		},
		{
			"everything empty",
			map[string]string{},
			nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pod := testPod(tt.annotations)

			agentConfig := basicAgentConfig()
			err := Init(pod, agentConfig)
			require.NoError(t, err)

			agent, err := New(pod)
			require.NoError(t, err)
			// create sidecar config
			cfg, err := agent.newConfig(false)
			require.NoError(t, err)

			config := &Config{}
			err = json.Unmarshal(cfg, config)
			require.NoError(t, err)

			require.Equal(t, tt.expectedTelemetry, config.Telemetry)
		})
	}
}
