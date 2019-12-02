package agent

import (
	"github.com/mattbaird/jsonpatch"
	"strings"
	"testing"
)

func TestDefaultAnnotationsCanSet(t *testing.T) {
	annotations := make(map[string]string)
	pod := testPod(annotations)

	err := Init(pod, "foobar-image", "http://foobar:8200", "test")
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

func TestDefaultAnnotationsDefaults(t *testing.T) {
	annotations := make(map[string]string)
	pod := testPod(annotations)

	err := Init(pod, "", "http://foobar:8200", "test")
	if err != nil {
		t.Errorf("got error, shouldn't have: %s", err)
	}

	tests := []struct {
		annotationKey   string
		annotationValue string
	}{
		{annotationKey: AnnotationAgentImage, annotationValue: DefaultVaultImage},
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

func TestDefaultAnnotationsError(t *testing.T) {
	annotations := make(map[string]string)
	pod := testPod(annotations)

	err := Init(pod, "image", "", "namespace")
	if err == nil {
		t.Error("expected error no address, got none")
	}

	errMsg := "address for Vault required"
	if !strings.Contains(err.Error(), errMsg) {
		t.Errorf("expected '%s' error, got %s", errMsg, err)
	}

	err = Init(pod, "image", "address", "")
	if err == nil {
		t.Error("expected error for no namespace, got none")
	}

	errMsg = "kubernetes namespace required"
	if !strings.Contains(err.Error(), errMsg) {
		t.Errorf("expected '%s' error, got %s", errMsg, err)
	}
}

func TestSecretAnnotations(t *testing.T) {
	tests := []struct {
		key          string
		value        string
		expectedKey  string
		expectedPath string
	}{
		{"vault.hashicorp.com/agent-inject-secret-foobar", "test1", "foobar", "test1"},
		{"vault.hashicorp.com/agent-inject-secret-FOOBAR", "test2", "foobar", "test2"},
		{"vault.hashicorp.com/agent-inject-secret-foobar-2_3", "test3", "foobar-2_3", "test3"},
		{"vault.hashicorp.com/agent-inject-secret", "test4", "", ""},
	}

	for _, tt := range tests {
		annotation := map[string]string{
			tt.key: tt.value,
		}
		pod := testPod(annotation)
		patches := &[]jsonpatch.JsonPatchOperation{}

		agent, err := New(pod, patches)
		if err != nil {
			t.Errorf("got error, shouldn't have: %s", err)
		}

		if tt.expectedKey != "" {
			if len(agent.Secrets) == 0 {
				t.Error("Secrets length was zero, it shouldn't have been")

				if agent.Secrets[0].Name != tt.expectedKey {
					t.Errorf("expected %s, got %s", tt.expectedKey, agent.Secrets[0].Name)
				}

				if agent.Secrets[0].Path != tt.expectedPath {
					t.Errorf("expected %s, got %s", tt.expectedPath, agent.Secrets[0].Path)

				}
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
		patches := &[]jsonpatch.JsonPatchOperation{}

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
	}

	for i, tt := range tests {
		annotations := map[string]string{tt.key: tt.value}
		pod := testPod(annotations)
		patches := &[]jsonpatch.JsonPatchOperation{}

		_, err := New(pod, patches)
		if err != nil && tt.valid {
			t.Errorf("[%d] got error, shouldn't have: %s", i, err)
		} else if err == nil && !tt.valid {
			t.Errorf("[%d] got no error, should have: %s", i, err)
		}
	}
}