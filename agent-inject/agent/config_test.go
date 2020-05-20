package agent

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/mattbaird/jsonpatch"
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
		"vault.hashicorp.com/agent-inject-secret-foo":   "db/creds/foo",
		"vault.hashicorp.com/agent-inject-template-foo": "template foo",
		"vault.hashicorp.com/agent-inject-secret-bar":   "db/creds/bar",

		// render this secret at a different path
		"vault.hashicorp.com/agent-inject-secret-different-path":                "different-path",
		fmt.Sprintf("%s-%s", AnnotationVaultSecretVolumePath, "different-path"): "/etc/container_environment",

		"vault.hashicorp.com/agent-inject-command-bar": "pkill -HUP app",

		AnnotationAgentCacheEnable: "true",
	}

	pod := testPod(annotations)
	var patches []*jsonpatch.JsonPatchOperation

	err := Init(pod, AgentConfig{"foobar-image", "http://foobar:8200", "test", "test", true, "1000", "100"})
	if err != nil {
		t.Errorf("got error initialising pod, shouldn't have: %s", err)
	}

	agent, err := New(pod, patches)
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

	if config.AutoAuth.Method.Type != "kubernetes" {
		t.Error("expected auto_auth method to be kubernetes, it wasn't")
	}

	if config.AutoAuth.Method.Config["role"] != annotations[AnnotationVaultRole] {
		t.Errorf("auto_auth role: expected role to be %s, got %s", annotations[AnnotationVaultRole], config.AutoAuth.Method.Config["role"])
	}

	if config.AutoAuth.Method.MountPath != annotations[AnnotationVaultAuthPath] {
		t.Errorf("auto_auth mount path: expected path to be %s, got %s", annotations[AnnotationVaultAuthPath], config.AutoAuth.Method.MountPath)
	}

	if len(config.Listener) != 0 || config.Cache != nil {
		t.Error("agent Cache should be disabled for init containers")
	}

	if len(config.Templates) != 3 {
		t.Errorf("expected 3 template, got %d", len(config.Templates))
	}

	for _, template := range config.Templates {
		if strings.Contains(template.Destination, "foo") {
			if template.Destination != "/vault/secrets/foo" {
				t.Errorf("expected template destination to be %s, got %s", "/vault/secrets/foo", template.Destination)
			}

			if template.Contents != "template foo" {
				t.Errorf("expected template contents to be %s, got %s", "template foo", template.Contents)
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
		} else {
			t.Error("shouldn't have got here")
		}
	}
}

func TestConfigVaultAgentCacheNotEnabledByDefault(t *testing.T) {
	annotations := map[string]string{}

	pod := testPod(annotations)
	var patches []*jsonpatch.JsonPatchOperation

	err := Init(pod, AgentConfig{"foobar-image", "http://foobar:8200", "test", "test", true, "1000", "100"})
	if err != nil {
		t.Errorf("got error initialising pod, shouldn't have: %s", err)
	}

	agent, err := New(pod, patches)
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
	var patches []*jsonpatch.JsonPatchOperation

	err := Init(pod, AgentConfig{"foobar-image", "http://foobar:8200", "test", "test", true, "1000", "100"})
	if err != nil {
		t.Errorf("got error initialising pod, shouldn't have: %s", err)
	}

	agent, err := New(pod, patches)
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

	if config.Cache.UseAuthAuthToken != "force" {
		t.Errorf("agent Cache use_auto_auth_token should be 'force', got %s instead", config.Cache.UseAuthAuthToken)
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
