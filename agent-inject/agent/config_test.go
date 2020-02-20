package agent

import (
	"encoding/json"
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
		"vault.hashicorp.com/agent-inject-secret-foo":   "db/creds/foo",
		"vault.hashicorp.com/agent-inject-template-foo": "template foo",
		"vault.hashicorp.com/agent-inject-secret-bar":   "db/creds/bar",
		"vault.hashicorp.com/agent-inject-command-bar":  "pkill -HUP app",
	}

	pod := testPod(annotations)
	var patches []*jsonpatch.JsonPatchOperation

	agent, err := New(pod, patches)
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

	if len(config.Templates) != 2 {
		t.Errorf("expected 2 template, got %d", len(config.Templates))
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
		} else {
			t.Error("shouldn't have got here")
		}
	}
}
