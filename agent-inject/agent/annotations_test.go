package agent

import (
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"

	"github.com/mattbaird/jsonpatch"
)

func TestInitCanSet(t *testing.T) {
	annotations := make(map[string]string)
	pod := testPod(annotations)

	err := Init(pod, AgentConfig{"foobar-image", "http://foobar:8200", "test", "test", true, "1000", "100", false})
	if err != nil {
		t.Errorf("got error, shouldn't have: %s", err)
	}

	tests := []struct {
		annotationKey   string
		annotationValue string
	}{
		{annotationKey: AnnotationVaultService, annotationValue: "http://foobar:8200"},
		{annotationKey: AnnotationAgentImage, annotationValue: "foobar-image"},
		{annotationKey: AnnotationAgentRequestNamespace, annotationValue: "test"},
		{annotationKey: AnnotationAgentRevokeOnShutdown, annotationValue: "true"},
	}

	for _, tt := range tests {
		raw, ok := pod.Annotations[tt.annotationKey]
		if !ok {
			t.Errorf("Default annotation %s not set, it should be.", tt.annotationKey)
		}

		if raw != tt.annotationValue {
			t.Errorf("Default annotation confiured value incorrect, wanted %s, got %s", tt.annotationValue, raw)

		}
	}
}

func TestInitDefaults(t *testing.T) {
	annotations := make(map[string]string)
	pod := testPod(annotations)

	err := Init(pod, AgentConfig{"", "http://foobar:8200", "test", "test", true, "", "", false})
	if err != nil {
		t.Errorf("got error, shouldn't have: %s", err)
	}

	tests := []struct {
		annotationKey   string
		annotationValue string
	}{
		{annotationKey: AnnotationAgentImage, annotationValue: DefaultVaultImage},
		{annotationKey: AnnotationAgentRunAsUser, annotationValue: strconv.Itoa(DefaultAgentRunAsUser)},
		{annotationKey: AnnotationAgentRunAsGroup, annotationValue: strconv.Itoa(DefaultAgentRunAsGroup)},
	}

	for _, tt := range tests {
		raw, ok := pod.Annotations[tt.annotationKey]
		if !ok {
			t.Errorf("Default annotation %s not set, it should be.", tt.annotationKey)
		}

		if raw != tt.annotationValue {
			t.Errorf("Default annotation value incorrect, wanted %s, got %s", tt.annotationValue, raw)
		}
	}
}

func TestInitError(t *testing.T) {
	annotations := make(map[string]string)
	pod := testPod(annotations)

	err := Init(pod, AgentConfig{"image", "", "authPath", "namespace", true, "1000", "100", false})
	if err == nil {
		t.Error("expected error no address, got none")
	}

	errMsg := "address for Vault required"
	if !strings.Contains(err.Error(), errMsg) {
		t.Errorf("expected '%s' error, got %s", errMsg, err)
	}

	err = Init(pod, AgentConfig{"image", "address", "", "namespace", true, "1000", "100", false})
	if err == nil {
		t.Error("expected error no authPath, got none")
	}

	errMsg = "Vault Auth Path required"
	if !strings.Contains(err.Error(), errMsg) {
		t.Errorf("expected '%s' error, got %s", errMsg, err)
	}

	err = Init(pod, AgentConfig{"image", "address", "authPath", "", true, "1000", "100", false})
	if err == nil {
		t.Error("expected error for no namespace, got none")
	}

	errMsg = "kubernetes namespace required"
	if !strings.Contains(err.Error(), errMsg) {
		t.Errorf("expected '%s' error, got %s", errMsg, err)
	}
}

func TestSecretAnnotationsWithPreserveCaseSensitivityFlagOff(t *testing.T) {
	tests := []struct {
		key          string
		value        string
		expectedKey  string
		expectedPath string
	}{
		{"vault.hashicorp.com/agent-inject-secret-foobar", "test1", "foobar", "test1"},
		{"vault.hashicorp.com/agent-inject-secret-FOOBAR", "test2", "foobar", "test2"},
		{"vault.hashicorp.com/agent-inject-secret-foobar-2_3", "test3", "foobar-2_3", "test3"},
		{"vault.hashicorp.com/agent-inject-secret-server.crt", "creds/tls/somecert", "server.crt", "creds/tls/somecert"},
		{"vault.hashicorp.com/agent-inject-secret", "test4", "", ""},
		{"vault.hashicorp.com/agent-inject-secret-", "test5", "", ""},
		// explicitly turn on preserve case sensitivity flag
		{"vault.hashicorp.com/agent-inject-secret-FOOBAR_EXPLICIT", "test2", "FOOBAR_EXPLICIT", "test2"},
	}

	for _, tt := range tests {
		annotation := map[string]string{
			tt.key: tt.value,
			fmt.Sprintf("%s-%s", AnnotationPreserveSecretCase, "FOOBAR_EXPLICIT"): "true",
		}
		pod := testPod(annotation)
		var patches []*jsonpatch.JsonPatchOperation

		err := Init(pod, AgentConfig{"", "http://foobar:8200", "test", "test", true, "1000", "100", false})
		if err != nil {
			t.Errorf("got error, shouldn't have: %s", err)
		}

		agent, err := New(pod, patches)
		if err != nil {
			t.Errorf("got error, shouldn't have: %s", err)
		}

		if tt.expectedKey != "" {
			if len(agent.Secrets) == 0 {
				t.Error("Secrets length was zero, it shouldn't have been")
			}
			if agent.Secrets[0].Name != tt.expectedKey {
				t.Errorf("expected %s, got %s", tt.expectedKey, agent.Secrets[0].Name)
			}

			if agent.Secrets[0].Path != tt.expectedPath {
				t.Errorf("expected %s, got %s", tt.expectedPath, agent.Secrets[0].Path)

			}
		} else if len(agent.Secrets) > 0 {
			t.Error("Secrets length was greater than zero, it shouldn't have been")
		}
	}
}

func TestSecretAnnotationsWithPreserveCaseSensitivityFlagOn(t *testing.T) {
	tests := []struct {
		key          string
		value        string
		expectedKey  string
		expectedPath string
	}{
		{"vault.hashicorp.com/agent-inject-secret-foobar", "test1", "foobar", "test1"},
		{"vault.hashicorp.com/agent-inject-secret-FOOBAR", "test2", "FOOBAR", "test2"},
	}

	for _, tt := range tests {
		annotation := map[string]string{
			tt.key:                       tt.value,
			AnnotationPreserveSecretCase: "true",
		}
		pod := testPod(annotation)
		var patches []*jsonpatch.JsonPatchOperation

		err := Init(pod, AgentConfig{"", "http://foobar:8200", "test", "test", true, "1000", "100", false})
		if err != nil {
			t.Errorf("got error, shouldn't have: %s", err)
		}

		agent, err := New(pod, patches)
		if err != nil {
			t.Errorf("got error, shouldn't have: %s", err)
		}

		if tt.expectedKey != "" {
			if len(agent.Secrets) == 0 {
				t.Error("Secrets length was zero, it shouldn't have been")
			}
			if agent.Secrets[0].Name != tt.expectedKey {
				t.Errorf("expected %s, got %s", tt.expectedKey, agent.Secrets[0].Name)
			}

			if agent.Secrets[0].Path != tt.expectedPath {
				t.Errorf("expected %s, got %s", tt.expectedPath, agent.Secrets[0].Path)

			}
		} else if len(agent.Secrets) > 0 {
			t.Error("Secrets length was greater than zero, it shouldn't have been")
		}
	}
}

func TestSecretTemplateAnnotations(t *testing.T) {
	tests := []struct {
		annotations      map[string]string
		expectedKey      string
		expectedTemplate string
	}{
		{
			map[string]string{
				"vault.hashicorp.com/agent-inject-secret-foobar":   "test1",
				"vault.hashicorp.com/agent-inject-template-foobar": "foobarTemplate",
			}, "foobar", "foobarTemplate",
		},
		{
			map[string]string{
				"vault.hashicorp.com/agent-inject-secret-foobar2":  "test2",
				"vault.hashicorp.com/agent-inject-template-foobar": "",
			}, "foobar2", "",
		},
		{
			map[string]string{
				"vault.hashicorp.com/agent-inject-secret-foobar":  "test1",
				"vault.hashicorp.com/agent-inject-templat-foobar": "foobarTemplate",
			}, "foobar", "",
		},
		{
			map[string]string{
				"vault.hashicorp.com/agent-inject-secret-foobar":    "test1",
				"vault.hashicorp.com/agent-inject-template-foobar2": "foobarTemplate",
			}, "foobar", "",
		},
		{
			map[string]string{
				"vault.hashicorp.com/agent-inject-secret-foobar2":  "test1",
				"vault.hashicorp.com/agent-inject-template-foobar": "foobarTemplate",
			}, "foobar2", "",
		},
		{
			map[string]string{
				"vault.hashicorp.com/agent-inject-secret-foobar2":  "test1",
				"vault.hashicorp.com/agent-inject-TEMPLATE-foobar": "foobarTemplate",
			}, "foobar2", "foobarTemplate",
		},
	}

	for _, tt := range tests {
		pod := testPod(tt.annotations)
		var patches []*jsonpatch.JsonPatchOperation

		err := Init(pod, AgentConfig{"", "http://foobar:8200", "test", "test", true, "1000", "100", false})
		if err != nil {
			t.Errorf("got error, shouldn't have: %s", err)
		}

		agent, err := New(pod, patches)
		if err != nil {
			t.Errorf("got error, shouldn't have: %s", err)
		}

		if len(agent.Secrets) == 0 {
			t.Error("Secrets length was zero, it shouldn't have been")
		}

		if agent.Secrets[0].Name != tt.expectedKey {
			t.Errorf("expected name %s, got %s", tt.expectedKey, agent.Secrets[0].Name)
		}

		if agent.Secrets[0].Name != tt.expectedKey {
			t.Errorf("expected template %s, got %s", tt.expectedTemplate, agent.Secrets[0].Template)
		}
	}
}

func TestTemplateShortcuts(t *testing.T) {
	tests := []struct {
		name            string
		annotations     map[string]string
		expectedSecrets map[string]Secret
	}{
		{
			"valid inject-token",
			map[string]string{
				AnnotationAgentInjectToken: "true",
			},
			map[string]Secret{
				"token": Secret{
					Name:      "token",
					Path:      TokenSecret,
					Template:  TokenTemplate,
					MountPath: secretVolumePath,
				},
			},
		},
		{
			"invalid inject-token",
			map[string]string{
				"vault.hashicorp.com/agent-inject-token-invalid": "true",
			},
			map[string]Secret{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pod := testPod(tt.annotations)
			err := Init(pod, AgentConfig{"", "http://foobar:8200", "test", "test", true, "1000", "100", false})
			if err != nil {
				t.Errorf("got error, shouldn't have: %s", err)
			}

			var patches []*jsonpatch.JsonPatchOperation

			agent, err := New(pod, patches)
			if err != nil {
				t.Errorf("got error, shouldn't have: %s", err)
			}

			if len(agent.Secrets) != len(tt.expectedSecrets) {
				t.Errorf("agent Secrets length was %d, expected %d", len(agent.Secrets), len(tt.expectedSecrets))
			}

			for _, s := range agent.Secrets {
				if s == nil {
					t.Error("Got a nil agent Secret")
					t.FailNow()
				}
				expectedSecret, found := tt.expectedSecrets[s.Name]
				if !found {
					t.Errorf("Unexpected agent secret name %q", s.Name)
					t.FailNow()
				}
				if !reflect.DeepEqual(expectedSecret, *s) {
					t.Errorf("expected secret %+v, got agent secret %+v", expectedSecret, *s)
				}
			}
		})
	}
}

func TestSecretCommandAnnotations(t *testing.T) {
	tests := []struct {
		annotations     map[string]string
		expectedKey     string
		expectedCommand string
	}{
		{
			map[string]string{
				"vault.hashicorp.com/agent-inject-secret-foobar":  "test1",
				"vault.hashicorp.com/agent-inject-command-foobar": "pkill -HUP nginx",
			}, "foobar", "pkill -HUP nginx",
		},
		{
			map[string]string{
				"vault.hashicorp.com/agent-inject-secret-foobar":   "test2",
				"vault.hashicorp.com/agent-inject-command-foobar2": "pkill -HUP nginx",
			}, "foobar", "",
		},
	}

	for _, tt := range tests {
		pod := testPod(tt.annotations)
		err := Init(pod, AgentConfig{"", "http://foobar:8200", "test", "test", true, "1000", "100", false})
		if err != nil {
			t.Errorf("got error, shouldn't have: %s", err)
		}

		var patches []*jsonpatch.JsonPatchOperation

		agent, err := New(pod, patches)
		if err != nil {
			t.Errorf("got error, shouldn't have: %s", err)
		}

		if len(agent.Secrets) == 0 {
			t.Error("Secrets length was zero, it shouldn't have been")
		}

		if agent.Secrets[0].Name != tt.expectedKey {
			t.Errorf("expected name %s, got %s", tt.expectedKey, agent.Secrets[0].Name)
		}

		if agent.Secrets[0].Command != tt.expectedCommand {
			t.Errorf("expected command %s, got %s", tt.expectedCommand, agent.Secrets[0].Command)
		}
	}
}

func TestCouldErrorAnnotations(t *testing.T) {
	tests := []struct {
		key   string
		value string
		valid bool
	}{
		{AnnotationAgentInject, "true", true},
		{AnnotationAgentInject, "false", true},
		{AnnotationAgentInject, "TRUE", true},
		{AnnotationAgentInject, "FALSE", true},
		{AnnotationAgentInject, "0", true},
		{AnnotationAgentInject, "1", true},
		{AnnotationAgentInject, "t", true},
		{AnnotationAgentInject, "f", true},
		{AnnotationAgentInject, "tRuE", false},
		{AnnotationAgentInject, "fAlSe", false},
		{AnnotationAgentInject, "", false},

		{AnnotationAgentPrePopulate, "true", true},
		{AnnotationAgentPrePopulate, "false", true},
		{AnnotationAgentPrePopulate, "TRUE", true},
		{AnnotationAgentPrePopulate, "FALSE", true},
		{AnnotationAgentPrePopulate, "0", true},
		{AnnotationAgentPrePopulate, "1", true},
		{AnnotationAgentPrePopulate, "t", true},
		{AnnotationAgentPrePopulate, "f", true},
		{AnnotationAgentPrePopulate, "tRuE", false},
		{AnnotationAgentPrePopulate, "fAlSe", false},
		{AnnotationAgentPrePopulate, "", false},

		{AnnotationAgentPrePopulateOnly, "true", true},
		{AnnotationAgentPrePopulateOnly, "false", true},
		{AnnotationAgentPrePopulateOnly, "TRUE", true},
		{AnnotationAgentPrePopulateOnly, "FALSE", true},
		{AnnotationAgentPrePopulateOnly, "0", true},
		{AnnotationAgentPrePopulateOnly, "1", true},
		{AnnotationAgentPrePopulateOnly, "t", true},
		{AnnotationAgentPrePopulateOnly, "f", true},
		{AnnotationAgentPrePopulateOnly, "tRuE", false},
		{AnnotationAgentPrePopulateOnly, "fAlSe", false},
		{AnnotationAgentPrePopulateOnly, "", false},

		{AnnotationVaultTLSSkipVerify, "true", true},
		{AnnotationVaultTLSSkipVerify, "false", true},
		{AnnotationVaultTLSSkipVerify, "TRUE", true},
		{AnnotationVaultTLSSkipVerify, "FALSE", true},
		{AnnotationVaultTLSSkipVerify, "0", true},
		{AnnotationVaultTLSSkipVerify, "1", true},
		{AnnotationVaultTLSSkipVerify, "t", true},
		{AnnotationVaultTLSSkipVerify, "f", true},
		{AnnotationVaultTLSSkipVerify, "tRuE", false},
		{AnnotationVaultTLSSkipVerify, "fAlSe", false},
		{AnnotationVaultTLSSkipVerify, "", false},

		{AnnotationAgentRevokeOnShutdown, "true", true},
		{AnnotationAgentRevokeOnShutdown, "false", true},
		{AnnotationAgentRevokeOnShutdown, "TRUE", true},
		{AnnotationAgentRevokeOnShutdown, "FALSE", true},
		{AnnotationAgentRevokeOnShutdown, "0", true},
		{AnnotationAgentRevokeOnShutdown, "1", true},
		{AnnotationAgentRevokeOnShutdown, "t", true},
		{AnnotationAgentRevokeOnShutdown, "f", true},
		{AnnotationAgentRevokeOnShutdown, "tRuE", false},
		{AnnotationAgentRevokeOnShutdown, "fAlSe", false},
		{AnnotationAgentRevokeOnShutdown, "", false},

		{AnnotationAgentRevokeGrace, "5", true},
		{AnnotationAgentRevokeGrace, "0", true},
		{AnnotationAgentRevokeGrace, "01", true},
		{AnnotationAgentRevokeGrace, "-1", false},
		{AnnotationAgentRevokeGrace, "foobar", false},
		{AnnotationAgentRunAsUser, "0", true},
		{AnnotationAgentRunAsUser, "100", true},
		{AnnotationAgentRunAsUser, "root", false},

		{AnnotationAgentRunAsGroup, "0", true},
		{AnnotationAgentRunAsGroup, "100", true},
		{AnnotationAgentRunAsGroup, "root", false},
	}

	for i, tt := range tests {
		annotations := map[string]string{tt.key: tt.value}
		pod := testPod(annotations)
		var patches []*jsonpatch.JsonPatchOperation

		err := Init(pod, AgentConfig{"", "http://foobar:8200", "test", "test", true, "1000", "100", false})
		if err != nil {
			t.Errorf("got error, shouldn't have: %s", err)
		}

		_, err = New(pod, patches)
		if err != nil && tt.valid {
			t.Errorf("[%d] got error, shouldn't have: %s", i, err)
		} else if err == nil && !tt.valid {
			t.Errorf("[%d] got no error, should have: %s", i, err)
		}
	}
}

func TestInitEmptyPod(t *testing.T) {
	var pod *corev1.Pod

	err := Init(pod, AgentConfig{"foobar-image", "http://foobar:8200", "test", "test", true, "1000", "100", false})
	if err == nil {
		t.Errorf("got no error, should have")
	}
}

func TestVaultNamespaceAnnotation(t *testing.T) {
	tests := []struct {
		key           string
		value         string
		expectedValue string
	}{
		{"", "", ""},
		{"vault.hashicorp.com/namespace", "", ""},
		{"vault.hashicorp.com/namespace", "foobar", "foobar"},
		{"vault.hashicorp.com/namespace", "fooBar", "fooBar"},
	}

	for _, tt := range tests {
		annotation := map[string]string{
			tt.key: tt.value,
		}
		pod := testPod(annotation)
		var patches []*jsonpatch.JsonPatchOperation

		err := Init(pod, AgentConfig{"foobar-image", "http://foobar:8200", "test", "test", true, "1000", "100", false})
		if err != nil {
			t.Errorf("got error, shouldn't have: %s", err)
		}

		agent, err := New(pod, patches)
		if err != nil {
			t.Errorf("got error, shouldn't have: %s", err)
		}

		if agent.Vault.Namespace != tt.expectedValue {
			t.Errorf("expected %s, got %s", tt.expectedValue, agent.Vault.Namespace)
		}
	}
}
