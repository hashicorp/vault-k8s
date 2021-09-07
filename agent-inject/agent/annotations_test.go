package agent

import (
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"

	"github.com/hashicorp/vault/sdk/helper/pointerutil"
	"github.com/mattbaird/jsonpatch"
	"github.com/stretchr/testify/require"
)

func basicAgentConfig() AgentConfig {
	return AgentConfig{
		Image:              "foobar-image",
		Address:            "http://foobar:8200",
		AuthType:           DefaultVaultAuthType,
		AuthPath:           "test",
		Namespace:          "test",
		RevokeOnShutdown:   true,
		UserID:             "100",
		GroupID:            "1000",
		SameID:             DefaultAgentRunAsSameUser,
		SetSecurityContext: DefaultAgentSetSecurityContext,
		ProxyAddress:       "http://proxy:3128",
		DefaultTemplate:    DefaultTemplateType,
		ResourceRequestCPU: DefaultResourceRequestCPU,
		ResourceRequestMem: DefaultResourceRequestMem,
		ResourceLimitCPU:   DefaultResourceLimitCPU,
		ResourceLimitMem:   DefaultResourceLimitMem,
		ExitOnRetryFailure: DefaultTemplateConfigExitOnRetryFailure,
	}
}

func TestInitCanSet(t *testing.T) {
	annotations := make(map[string]string)
	pod := testPod(annotations)

	agentConfig := basicAgentConfig()
	err := Init(pod, agentConfig)
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
		{annotationKey: AnnotationProxyAddress, annotationValue: "http://proxy:3128"},
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

	agentConfig := basicAgentConfig()
	agentConfig.Image = ""
	agentConfig.UserID = ""
	agentConfig.GroupID = ""
	agentConfig.ProxyAddress = ""

	err := Init(pod, agentConfig)
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

	agentConfig := basicAgentConfig()
	agentConfig.Address = ""

	err := Init(pod, agentConfig)
	if err == nil {
		t.Error("expected error no address, got none")
	}

	errMsg := "address for Vault required"
	if !strings.Contains(err.Error(), errMsg) {
		t.Errorf("expected '%s' error, got %s", errMsg, err)
	}

	agentConfig.Address = "address"
	agentConfig.AuthPath = ""
	err = Init(pod, agentConfig)
	if err == nil {
		t.Error("expected error no authPath, got none")
	}

	errMsg = "Vault Auth Path required"
	if !strings.Contains(err.Error(), errMsg) {
		t.Errorf("expected '%s' error, got %s", errMsg, err)
	}

	agentConfig.AuthPath = "authPath"
	agentConfig.Namespace = ""
	err = Init(pod, agentConfig)
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

		agentConfig := basicAgentConfig()
		err := Init(pod, agentConfig)
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
			t.Errorf("Secrets length was greater than zero, it shouldn't have been: %s", tt.key)
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

		agentConfig := basicAgentConfig()
		err := Init(pod, agentConfig)
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

func TestSecretLocationFileAnnotations(t *testing.T) {
	tests := []struct {
		name             string
		annotations      map[string]string
		expectedName     string
		expectedFilename string
		expectedLocation string
	}{
		{
			"simple name",
			map[string]string{
				"vault.hashicorp.com/agent-inject-secret-foobar": "vault/test1",
				"vault.hashicorp.com/agent-inject-file-foobar":   "foobar_simple_name",
			},
			"foobar",
			"foobar_simple_name",
			"vault/test1",
		},
		{
			"absolute file path",
			map[string]string{
				"vault.hashicorp.com/agent-inject-secret-foobar": "vault/test1",
				"vault.hashicorp.com/agent-inject-file-foobar":   "/some/path/foobar_simple_name",
			},
			"foobar",
			"/some/path/foobar_simple_name",
			"vault/test1",
		},
		{
			"long file name",
			map[string]string{
				"vault.hashicorp.com/agent-inject-secret-foobar": "vault/test2",
				"vault.hashicorp.com/agent-inject-file-foobar":   "this_is_very_long_and/would_fail_in_kubernetes/if_in_annotation",
			},
			"foobar",
			"this_is_very_long_and/would_fail_in_kubernetes/if_in_annotation",
			"vault/test2",
		},
		{
			"file doesn't match secret annotation",
			map[string]string{
				"vault.hashicorp.com/agent-inject-secret-foobar":         "vault/test2",
				"vault.hashicorp.com/agent-inject-file-notcorresponding": "this_is_very_long_and/would_fail_in_kubernetes/if_in_annotation",
			},
			"foobar",
			"",
			"vault/test2",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pod := testPod(tt.annotations)
			var patches []*jsonpatch.JsonPatchOperation

			agentConfig := basicAgentConfig()
			err := Init(pod, agentConfig)
			if err != nil {
				t.Errorf("got error, shouldn't have: %s", err)
			}

			agent, err := New(pod, patches)
			if err != nil {
				t.Errorf("got error, shouldn't have: %s", err)
			}

			if tt.expectedName != "" {
				if len(agent.Secrets) == 0 {
					t.Error("Secrets length was zero, it shouldn't have been")
				}

				if agent.Secrets[0].Name != tt.expectedName {
					t.Errorf("expected name %s, got %s", tt.expectedName, agent.Secrets[0].Name)
				}

				if agent.Secrets[0].FilePathAndName != tt.expectedFilename {
					t.Errorf("expected file %s, got %s", tt.expectedFilename, agent.Secrets[0].Name)
				}

				if agent.Secrets[0].Path != tt.expectedLocation {
					t.Errorf("expected path %s, got %s", tt.expectedLocation, agent.Secrets[0].Path)
				}
			} else if len(agent.Secrets) > 0 {
				t.Errorf("Secrets length was greater than zero, it shouldn't have been")
			}
		})
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
			}, "foobar2", "",
		},
	}

	for _, tt := range tests {
		pod := testPod(tt.annotations)
		var patches []*jsonpatch.JsonPatchOperation

		agentConfig := basicAgentConfig()
		err := Init(pod, agentConfig)
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

		if agent.Secrets[0].Template != tt.expectedTemplate {
			t.Errorf("expected template %s, got %s", tt.expectedTemplate, agent.Secrets[0].Template)
		}
	}
}

func TestSecretMixedTemplatesAnnotations(t *testing.T) {
	tests := []struct {
		annotations     map[string]string
		expectedSecrets map[string]Secret
	}{
		{
			map[string]string{
				"vault.hashicorp.com/agent-inject-secret-foobar":        "test1",
				"vault.hashicorp.com/agent-inject-template-foobar":      "",
				"vault.hashicorp.com/agent-inject-template-file-foobar": "/etc/config.tmpl",
				"vault.hashicorp.com/agent-inject-secret-test2":         "test2",
				"vault.hashicorp.com/agent-inject-template-test2":       "foobarTemplate",
				"vault.hashicorp.com/agent-inject-template-file-test2":  "",
			},
			map[string]Secret{
				"foobar": Secret{
					Name:         "foobar",
					Path:         "test1",
					Template:     "",
					TemplateFile: "/etc/config.tmpl",
					MountPath:    secretVolumePath,
				},
				"test2": Secret{
					Name:         "test2",
					Path:         "test2",
					Template:     "foobarTemplate",
					TemplateFile: "",
					MountPath:    secretVolumePath,
				},
			},
		},
	}
	for _, tt := range tests {
		pod := testPod(tt.annotations)
		agentConfig := basicAgentConfig()
		err := Init(pod, agentConfig)
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
	}
}

func TestSecretTemplateFileAnnotations(t *testing.T) {
	tests := []struct {
		annotations          map[string]string
		expectedKey          string
		expectedTemplate     string
		expectedTemplateFile string
	}{
		{
			map[string]string{
				"vault.hashicorp.com/agent-inject-secret-foobar":        "test1",
				"vault.hashicorp.com/agent-inject-template-foobar":      "foobarTemplate",
				"vault.hashicorp.com/agent-inject-template-file-foobar": "/etc/config.tmpl",
			}, "foobar", "foobarTemplate", "",
		},
		{
			map[string]string{
				"vault.hashicorp.com/agent-inject-secret-foobar":        "test1",
				"vault.hashicorp.com/agent-inject-template-foobar":      "",
				"vault.hashicorp.com/agent-inject-template-file-foobar": "/etc/config.tmpl",
			}, "foobar", "", "/etc/config.tmpl",
		},
	}

	for _, tt := range tests {
		pod := testPod(tt.annotations)
		var patches []*jsonpatch.JsonPatchOperation

		agentConfig := basicAgentConfig()
		err := Init(pod, agentConfig)
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

		if agent.Secrets[0].Template != tt.expectedTemplate {
			t.Errorf("expected template %s, got %s", tt.expectedTemplate, agent.Secrets[0].Template)
		}

		if agent.Secrets[0].TemplateFile != tt.expectedTemplateFile {
			t.Errorf("expected template file path %s, got %s", tt.expectedTemplateFile, agent.Secrets[0].TemplateFile)
		}

	}
}

func TestSecretPermissionAnnotations(t *testing.T) {
	tests := []struct {
		annotations        map[string]string
		expectedKey        string
		expectedPermission string
	}{
		{
			map[string]string{
				"vault.hashicorp.com/agent-inject-secret-foobar": "test1",
				"vault.hashicorp.com/agent-inject-perms-foobar":  "0600",
			}, "foobar", "0600",
		},
		{
			map[string]string{
				"vault.hashicorp.com/agent-inject-secret-foobar": "test2",
				"vault.hashicorp.com/agent-inject-perms-foobar2": "0600",
			}, "foobar", "",
		},
	}

	for _, tt := range tests {
		pod := testPod(tt.annotations)
		agentConfig := basicAgentConfig()
		err := Init(pod, agentConfig)
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

		if agent.Secrets[0].FilePermission != tt.expectedPermission {
			t.Errorf("expected permission %s, got %s", tt.expectedPermission, agent.Secrets[0].Command)
		}
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
		agentConfig := basicAgentConfig()
		err := Init(pod, agentConfig)
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

		{AnnotationAgentSetSecurityContext, "true", true},
		{AnnotationAgentSetSecurityContext, "false", true},
		{AnnotationAgentSetSecurityContext, "secure", false},
		{AnnotationAgentSetSecurityContext, "", false},

		{AnnotationAgentCacheEnable, "true", true},
		{AnnotationAgentCacheEnable, "false", true},
		{AnnotationAgentCacheEnable, "TRUE", true},
		{AnnotationAgentCacheEnable, "FALSE", true},
		{AnnotationAgentCacheEnable, "0", true},
		{AnnotationAgentCacheEnable, "1", true},
		{AnnotationAgentCacheEnable, "t", true},
		{AnnotationAgentCacheEnable, "f", true},
		{AnnotationAgentCacheEnable, "tRuE", false},
		{AnnotationAgentCacheEnable, "fAlSe", false},
		{AnnotationAgentCacheEnable, "", false},
	}

	for i, tt := range tests {
		annotations := map[string]string{tt.key: tt.value}
		pod := testPod(annotations)
		var patches []*jsonpatch.JsonPatchOperation
		agentConfig := basicAgentConfig()
		err := Init(pod, agentConfig)
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
	agentConfig := basicAgentConfig()
	err := Init(pod, agentConfig)
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

		agentConfig := basicAgentConfig()
		err := Init(pod, agentConfig)
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

func Test_runAsSameID(t *testing.T) {

	tests := []struct {
		name           string
		runAsSameUser  string
		appSCC         *corev1.SecurityContext
		expectedResult bool
		expectedErr    bool
		expectedUserID int64
	}{
		{
			name:           "false with no app SCC",
			runAsSameUser:  "false",
			appSCC:         nil,
			expectedResult: false,
			expectedErr:    false,
			expectedUserID: DefaultAgentRunAsUser,
		},
		{
			name:          "true with app SCC",
			runAsSameUser: "true",
			appSCC: &corev1.SecurityContext{
				RunAsUser: pointerutil.Int64Ptr(123456),
			},
			expectedResult: true,
			expectedErr:    false,
			expectedUserID: 123456,
		},
		{
			name:          "false with app SCC",
			runAsSameUser: "false",
			appSCC: &corev1.SecurityContext{
				RunAsUser: pointerutil.Int64Ptr(123456),
			},
			expectedResult: false,
			expectedErr:    false,
			expectedUserID: DefaultAgentRunAsUser,
		},
		{
			name:           "true with no app SCC",
			runAsSameUser:  "true",
			appSCC:         nil,
			expectedResult: false,
			expectedErr:    true,
			expectedUserID: DefaultAgentRunAsUser,
		},
		{
			name:           "annotation not set",
			runAsSameUser:  "",
			appSCC:         nil,
			expectedResult: false,
			expectedErr:    false,
			expectedUserID: DefaultAgentRunAsUser,
		},
		{
			name:           "invalid annotation set",
			runAsSameUser:  "rooooooot",
			appSCC:         nil,
			expectedResult: false,
			expectedErr:    true,
			expectedUserID: DefaultAgentRunAsUser,
		},
		{
			name:          "true with app SCC as root user",
			runAsSameUser: "true",
			appSCC: &corev1.SecurityContext{
				RunAsUser: pointerutil.Int64Ptr(0),
			},
			expectedResult: false,
			expectedErr:    true,
			expectedUserID: DefaultAgentRunAsUser,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			annotations := map[string]string{}
			if len(tt.runAsSameUser) > 0 {
				annotations[AnnotationAgentRunAsSameUser] = tt.runAsSameUser
			}
			pod := testPod(annotations)
			pod.Spec.Containers[0].SecurityContext = tt.appSCC

			agent := &Agent{
				Annotations: annotations,
				RunAsUser:   DefaultAgentRunAsUser,
			}
			result, err := agent.runAsSameID(pod)
			require.Equal(t, tt.expectedResult, result)
			require.Equal(t, tt.expectedErr, err != nil)
			require.Equal(t, tt.expectedUserID, agent.RunAsUser)
		})
	}
}

func TestAuthConfigAnnotations(t *testing.T) {
	tests := []struct {
		annotations        map[string]string
		expectedAuthConfig map[string]interface{}
	}{
		{
			map[string]string{
				"vault.hashicorp.com/role": "backwardscompat",
			},
			map[string]interface{}{
				"role":       "backwardscompat",
				"token_path": "serviceaccount/somewhere/token",
			},
		},
		{
			map[string]string{
				"vault.hashicorp.com/role":             "backwardscompat",
				"vault.hashicorp.com/auth-config-role": "lowerprio",
			},
			map[string]interface{}{
				"role":       "backwardscompat",
				"token_path": "serviceaccount/somewhere/token",
			},
		},
		{
			map[string]string{
				"vault.hashicorp.com/auth-config-name":                                "foo",
				"vault.hashicorp.com/auth-config-ca-cert":                             "bar",
				"vault.hashicorp.com/auth-config-client_cert":                         "baz",
				"vault.hashicorp.com/auth-config-credential_poll_interval":            "1",
				"vault.hashicorp.com/auth-config-remove_secret_id_file_after_reading": "false",
			},
			map[string]interface{}{
				"name":                                "foo",
				"ca_cert":                             "bar", // param name dashes converted to underscores for ease
				"client_cert":                         "baz",
				"credential_poll_interval":            "1",     // string->int conversion left up to consuming app HCL parser
				"remove_secret_id_file_after_reading": "false", // string->bool, same as above
				"token_path":                          "serviceaccount/somewhere/token",
			},
		},
	}

	for _, tt := range tests {
		pod := testPod(tt.annotations)
		var patches []*jsonpatch.JsonPatchOperation

		agentConfig := basicAgentConfig()
		err := Init(pod, agentConfig)
		if err != nil {
			t.Errorf("got error, shouldn't have: %s", err)
		}

		agent, err := New(pod, patches)
		if err != nil {
			t.Errorf("got error, shouldn't have: %s", err)
		}

		require.Equal(t, agent.Vault.AuthConfig, tt.expectedAuthConfig, "expected AuthConfig %v, got %v", tt.expectedAuthConfig, agent.Vault.AuthConfig)
	}
}

func TestDefaultTemplateOverride(t *testing.T) {
	tests := []struct {
		annotations   map[string]string
		expectedValue string
		expectedErr   bool
	}{
		{
			map[string]string{
				"vault.hashicorp.com/agent-inject-default-template": "json",
			},
			"json",
			false,
		},
		{
			map[string]string{
				"vault.hashicorp.com/agent-inject-default-template": "JSON",
			},
			"json",
			false,
		},
		{
			map[string]string{
				"vault.hashicorp.com/agent-inject-default-template": "map",
			},
			"map",
			false,
		},
		{
			map[string]string{
				"vault.hashicorp.com/agent-inject-default-template": "MAP",
			},
			"map",
			false,
		},
		{
			map[string]string{
				"vault.hashicorp.com/agent-inject-default-template": "foobar",
			},
			"",
			true,
		},
		{
			map[string]string{
				"vault.hashicorp.com/agent-inject-default-template": "jsn",
			},
			"",
			true,
		},
		{
			map[string]string{
				"vault.hashicorp.com/agent-inject-default-template": "",
			},
			"",
			true,
		},
	}

	for _, tt := range tests {
		pod := testPod(tt.annotations)
		var patches []*jsonpatch.JsonPatchOperation

		agentConfig := basicAgentConfig()
		err := Init(pod, agentConfig)
		if err != nil {
			t.Errorf("got error, shouldn't have: %s", err)
		}

		agent, err := New(pod, patches)
		if err != nil && !tt.expectedErr {
			t.Errorf("got error, shouldn't have: %s", err)
		} else if err == nil && tt.expectedErr {
			t.Error("got no error, should have")
		}

		if !tt.expectedErr {
			require.Equal(t, agent.DefaultTemplate, tt.expectedValue,
				"expected %v, got %v", tt.expectedValue, agent.DefaultTemplate)
		}
	}
}
