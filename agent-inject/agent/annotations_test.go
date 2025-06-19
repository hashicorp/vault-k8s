// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package agent

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"

	"github.com/hashicorp/vault-k8s/agent-inject/internal"

	jsonpatch "github.com/evanphx/json-patch"
	"github.com/hashicorp/vault/sdk/helper/pointerutil"
	"github.com/stretchr/testify/assert"
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
		{annotationKey: AnnotationAgentShareProcessNamespace, annotationValue: ""},
	}

	for _, tt := range tests {
		raw, ok := pod.Annotations[tt.annotationKey]
		if tt.annotationValue == "" && !ok {
			// okay, we expected it not to be set
			continue
		} else if tt.annotationValue == "" && ok {
			t.Errorf("Default annotation value incorrect, wanted unset, got %s", raw)
		} else if !ok {
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

		agentConfig := basicAgentConfig()
		err := Init(pod, agentConfig)
		if err != nil {
			t.Errorf("got error, shouldn't have: %s", err)
		}

		agent, err := New(pod)
		if err != nil {
			t.Errorf("got error, shouldn't have: %s", err)
		}

		if tt.expectedKey != "" {
			if len(agent.Secrets) == 0 {
				t.Errorf("Secrets length was zero, it shouldn't have been: %s", tt.key)

				continue
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

		agentConfig := basicAgentConfig()
		err := Init(pod, agentConfig)
		if err != nil {
			t.Errorf("got error, shouldn't have: %s", err)
		}

		agent, err := New(pod)
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

			agentConfig := basicAgentConfig()
			err := Init(pod, agentConfig)
			if err != nil {
				t.Errorf("got error, shouldn't have: %s", err)
			}

			agent, err := New(pod)
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
		annotations             map[string]string
		expectedSecretTemplates map[string]string
	}{
		{
			map[string]string{
				"vault.hashicorp.com/agent-inject-secret-foobar":   "test1",
				"vault.hashicorp.com/agent-inject-template-foobar": "foobarTemplate",
			},
			map[string]string{
				"foobar": "foobarTemplate",
			},
		},
		{
			map[string]string{
				"vault.hashicorp.com/agent-inject-secret-foobar2":  "test2",
				"vault.hashicorp.com/agent-inject-template-foobar": "",
			},
			map[string]string{
				"foobar2": "",
			},
		},
		{
			map[string]string{
				"vault.hashicorp.com/agent-inject-secret-foobar":  "test1",
				"vault.hashicorp.com/agent-inject-templat-foobar": "foobarTemplate",
			},
			map[string]string{
				"foobar": "",
			},
		},
		{
			map[string]string{
				"vault.hashicorp.com/agent-inject-secret-foobar":    "test1",
				"vault.hashicorp.com/agent-inject-template-foobar2": "foobarTemplate",
			},
			map[string]string{
				"foobar":  "",
				"foobar2": "foobarTemplate",
			},
		},
		{
			map[string]string{
				"vault.hashicorp.com/agent-inject-secret-foobar2":  "test1",
				"vault.hashicorp.com/agent-inject-template-foobar": "foobarTemplate",
			},
			map[string]string{
				"foobar2": "",
				"foobar":  "foobarTemplate",
			},
		},
		{
			map[string]string{
				"vault.hashicorp.com/agent-inject-secret-foobar2":  "test1",
				"vault.hashicorp.com/agent-inject-TEMPLATE-foobar": "foobarTemplate",
			},
			map[string]string{
				"foobar2": "",
			},
		},
	}

	for i, tt := range tests {
		t.Run(fmt.Sprintf("TestSecretTemplateAnnotations#%d", i), func(t *testing.T) {
			pod := testPod(tt.annotations)

			agentConfig := basicAgentConfig()
			err := Init(pod, agentConfig)
			if err != nil {
				t.Errorf("got error, shouldn't have: %s", err)
			}

			agent, err := New(pod)
			if err != nil {
				t.Errorf("got error, shouldn't have: %s", err)
			}

			if len(agent.Secrets) != len(tt.expectedSecretTemplates) {
				t.Errorf("agent Secrets length was %d, expected %d", len(agent.Secrets), len(tt.expectedSecretTemplates))
			}

			for _, secret := range agent.Secrets {
				expectedTemplate, ok := tt.expectedSecretTemplates[secret.Name]
				if !ok {
					t.Errorf("secret %s with template %s was not expected", secret.Name, secret.Template)
				}

				if secret.Template != expectedTemplate {
					t.Errorf("expected template %s, got %s", expectedTemplate, secret.Template)
				}
			}
		})
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

				"vault.hashicorp.com/agent-inject-secret-test2":        "test2",
				"vault.hashicorp.com/agent-inject-template-test2":      "foobarTemplate",
				"vault.hashicorp.com/agent-inject-template-file-test2": "",

				"vault.hashicorp.com/agent-inject-template-only-template":           "onlyTemplate",
				"vault.hashicorp.com/agent-inject-template-file-only-template-file": "onlyTemplateFile",

				"vault.hashicorp.com/agent-inject-secret-barfoo":        "test1",
				"vault.hashicorp.com/agent-inject-template-barfoo":      "",
				"vault.hashicorp.com/agent-template-left-delim-barfoo":  "${",
				"vault.hashicorp.com/agent-template-right-delim-barfoo": "}",
				"vault.hashicorp.com/agent-inject-template-file-barfoo": "/etc/config.tmpl",

				"vault.hashicorp.com/agent-inject-secret-test3":        "test3",
				"vault.hashicorp.com/agent-inject-template-test3":      "foobarTemplate3",
				"vault.hashicorp.com/agent-inject-template-file-test3": "",
				"vault.hashicorp.com/agent-template-left-delim-test3":  "",
				"vault.hashicorp.com/agent-template-right-delim-test3": "",

				"vault.hashicorp.com/agent-inject-template-only-template-2":      "onlyTemplate2",
				"vault.hashicorp.com/agent-template-left-delim-only-template-2":  "${",
				"vault.hashicorp.com/agent-template-right-delim-only-template-2": "}",

				"vault.hashicorp.com/agent-inject-template-file-only-template-file-2": "onlyTemplateFile2",
				"vault.hashicorp.com/agent-template-left-delim-only-template-file-2":  "${",
				"vault.hashicorp.com/agent-template-right-delim-only-template-file-2": "}",
			},
			map[string]Secret{
				"foobar": {
					Name:           "foobar",
					RawName:        "foobar",
					Path:           "test1",
					Template:       "",
					LeftDelimiter:  "",
					RightDelimiter: "",
					TemplateFile:   "/etc/config.tmpl",
					MountPath:      secretVolumePath,
				},
				"test2": {
					Name:           "test2",
					RawName:        "test2",
					Path:           "test2",
					Template:       "foobarTemplate",
					LeftDelimiter:  "",
					RightDelimiter: "",
					TemplateFile:   "",
					MountPath:      secretVolumePath,
				},
				"only-template": {
					Name:           "only-template",
					RawName:        "only-template",
					Path:           "",
					Template:       "onlyTemplate",
					LeftDelimiter:  "",
					RightDelimiter: "",
					TemplateFile:   "",
					MountPath:      secretVolumePath,
				},
				"only-template-file": {
					Name:           "only-template-file",
					RawName:        "only-template-file",
					Path:           "",
					Template:       "",
					LeftDelimiter:  "",
					RightDelimiter: "",
					TemplateFile:   "onlyTemplateFile",
					MountPath:      secretVolumePath,
				},
				"barfoo": {
					Name:           "barfoo",
					RawName:        "barfoo",
					Path:           "test1",
					Template:       "",
					LeftDelimiter:  "${",
					RightDelimiter: "}",
					TemplateFile:   "/etc/config.tmpl",
					MountPath:      secretVolumePath,
				},
				"test3": {
					Name:           "test3",
					RawName:        "test3",
					Path:           "test3",
					Template:       "foobarTemplate3",
					LeftDelimiter:  "",
					RightDelimiter: "",
					TemplateFile:   "",
					MountPath:      secretVolumePath,
				},
				"only-template-2": {
					Name:           "only-template-2",
					RawName:        "only-template-2",
					Path:           "",
					Template:       "onlyTemplate2",
					LeftDelimiter:  "${",
					RightDelimiter: "}",
					TemplateFile:   "",
					MountPath:      secretVolumePath,
				},
				"only-template-file-2": {
					Name:           "only-template-file-2",
					RawName:        "only-template-file-2",
					Path:           "",
					Template:       "",
					LeftDelimiter:  "${",
					RightDelimiter: "}",
					TemplateFile:   "onlyTemplateFile2",
					MountPath:      secretVolumePath,
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

		agent, err := New(pod)
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

		agentConfig := basicAgentConfig()
		err := Init(pod, agentConfig)
		if err != nil {
			t.Errorf("got error, shouldn't have: %s", err)
		}

		agent, err := New(pod)
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

		agent, err := New(pod)
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

		agent, err := New(pod)
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

func TestSecretErrorOnMissingKeyAnnotations(t *testing.T) {
	tests := []struct {
		name        string
		annotations map[string]string
		expectedKey string
		expected    bool
		invalid     bool
	}{
		{
			name: "force error",
			annotations: map[string]string{
				"vault.hashicorp.com/agent-inject-secret-foobar":  "test1",
				"vault.hashicorp.com/error-on-missing-key-foobar": "True",
			},
			expectedKey: "foobar",
			expected:    true,
		},
		{
			name: "ignore error",
			annotations: map[string]string{
				"vault.hashicorp.com/agent-inject-secret-foobar":  "test2",
				"vault.hashicorp.com/error-on-missing-key-foobar": "false",
			},
			expectedKey: "foobar",
			expected:    false,
		},
		{
			name: "default value",
			annotations: map[string]string{
				"vault.hashicorp.com/agent-inject-secret-foobar": "test3",
			},
			expectedKey: "foobar",
			expected:    false,
		},
		{
			name: "bad annotation",
			annotations: map[string]string{
				"vault.hashicorp.com/agent-inject-secret-foobar":  "test4",
				"vault.hashicorp.com/error-on-missing-key-foobar": "unknown",
			},
			invalid: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pod := testPod(tt.annotations)
			err := Init(pod, basicAgentConfig())
			require.NoError(t, err)

			agent, err := New(pod)
			if err != nil {
				assert.True(t, tt.invalid)
			} else {
				require.Len(t, agent.Secrets, 1)

				assert.Equal(t, tt.expectedKey, agent.Secrets[0].Name)
				assert.Equal(t, tt.expected, agent.Secrets[0].ErrMissingKey)
			}
		})
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
		{AnnotationAgentInject, "", true},

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
		{AnnotationAgentPrePopulate, "", true},

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
		{AnnotationAgentPrePopulateOnly, "", true},

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
		{AnnotationVaultTLSSkipVerify, "", true},

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
		{AnnotationAgentRevokeOnShutdown, "", true},

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

		{AnnotationAgentShareProcessNamespace, "true", true},
		{AnnotationAgentShareProcessNamespace, "false", true},
		{AnnotationAgentShareProcessNamespace, "TRUE", true},
		{AnnotationAgentShareProcessNamespace, "FALSE", true},
		{AnnotationAgentShareProcessNamespace, "tRuE", false},
		{AnnotationAgentShareProcessNamespace, "fAlSe", false},
		{AnnotationAgentShareProcessNamespace, "", true},

		{AnnotationAgentSetSecurityContext, "true", true},
		{AnnotationAgentSetSecurityContext, "false", true},
		{AnnotationAgentSetSecurityContext, "secure", false},
		{AnnotationAgentSetSecurityContext, "", true},

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
		{AnnotationAgentCacheEnable, "", true},

		{AnnotationAgentAuthMinBackoff, "", true},
		{AnnotationAgentAuthMinBackoff, "1s", true},
		{AnnotationAgentAuthMinBackoff, "1m", true},
		{AnnotationAgentAuthMinBackoff, "x", false},

		{AnnotationAgentAuthMaxBackoff, "", true},
		{AnnotationAgentAuthMaxBackoff, "1s", true},
		{AnnotationAgentAuthMaxBackoff, "1m", true},
		{AnnotationAgentAuthMaxBackoff, "x", false},
	}

	for i, tt := range tests {
		annotations := map[string]string{tt.key: tt.value}
		pod := testPod(annotations)
		agentConfig := basicAgentConfig()
		err := Init(pod, agentConfig)
		if err != nil {
			if tt.valid {
				t.Errorf("got error, shouldn't have: %s", err)
			}
			// if !tt.valid, that is okay, we expected an error
			continue
		}

		_, err = New(pod)
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
		key                       string
		value                     string
		agentVaultNamespaceConfig string
		expectedValue             string
	}{
		{"", "", "", ""},
		{"", "", "test-namespace", "test-namespace"},
		{"vault.hashicorp.com/namespace", "", "", ""},
		{"vault.hashicorp.com/namespace", "foobar", "", "foobar"},
		{"vault.hashicorp.com/namespace", "foobar", "test-namespace", "foobar"},
		{"vault.hashicorp.com/namespace", "fooBar", "", "fooBar"},
	}

	for _, tt := range tests {
		annotation := map[string]string{
			tt.key: tt.value,
		}
		pod := testPod(annotation)

		agentConfig := basicAgentConfig()
		agentConfig.VaultNamespace = tt.agentVaultNamespaceConfig
		err := Init(pod, agentConfig)
		if err != nil {
			t.Errorf("got error, shouldn't have: %s", err)
		}

		agent, err := New(pod)
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
				"vault.hashicorp.com/auth-config-token-path": "serviceaccount/somewhere-else/token",
			},
			map[string]interface{}{
				"token_path": "serviceaccount/somewhere-else/token",
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

		agentConfig := basicAgentConfig()
		err := Init(pod, agentConfig)
		if err != nil {
			t.Errorf("got error, shouldn't have: %s", err)
		}

		agent, err := New(pod)
		if err != nil {
			t.Errorf("got error, shouldn't have: %s", err)
		}

		require.Equal(t, agent.Vault.AuthConfig, tt.expectedAuthConfig, "expected AuthConfig %v, got %v", tt.expectedAuthConfig, agent.Vault.AuthConfig)
	}
}

func TestInjectContainers(t *testing.T) {
	tests := []struct {
		name          string
		annotations   map[string]string
		expectedValue string
		ExpectedPatch jsonpatch.Patch
	}{
		{
			name:          "No InjectionContainers annotations",
			annotations:   map[string]string{},
			expectedValue: "foobar,foo1,foo2",
			ExpectedPatch: []jsonpatch.Operation{
				internal.AddOp("/spec/volumes", nil),
				internal.AddOp("/spec/volumes/-", nil),
				internal.AddOp("/spec/volumes", nil),
				internal.AddOp("/spec/containers/0/volumeMounts/-", nil),
				internal.AddOp("/spec/containers/1/volumeMounts/-", nil),
				internal.AddOp("/spec/containers/2/volumeMounts/-", nil),
				internal.AddOp("/spec/initContainers", nil),
				internal.AddOp("/spec/containers/-", nil),
				internal.AddOp("/metadata/annotations/"+internal.EscapeJSONPointer(AnnotationAgentStatus), nil),
			},
		},
		{
			name:          "InjectionContainers annotation with container name",
			annotations:   map[string]string{AnnotationAgentInjectContainers: "foo1"},
			expectedValue: "foo1",
			ExpectedPatch: []jsonpatch.Operation{
				internal.AddOp("/spec/volumes", nil),
				internal.AddOp("/spec/volumes/-", nil),
				internal.AddOp("/spec/volumes", nil),
				internal.AddOp("/spec/containers/1/volumeMounts/-", nil),
				internal.AddOp("/spec/initContainers", nil),
				internal.AddOp("/spec/containers/-", nil),
				internal.AddOp("/metadata/annotations/"+internal.EscapeJSONPointer(AnnotationAgentStatus), nil),
			},
		},
		{
			name:          "InjectionContainer annotations with multiple containers names",
			annotations:   map[string]string{AnnotationAgentInjectContainers: "foo1,foo2"},
			expectedValue: "foo1,foo2",
			ExpectedPatch: []jsonpatch.Operation{
				internal.AddOp("/spec/volumes", nil),
				internal.AddOp("/spec/volumes/-", nil),
				internal.AddOp("/spec/volumes", nil),
				internal.AddOp("/spec/containers/1/volumeMounts/-", nil),
				internal.AddOp("/spec/containers/2/volumeMounts/-", nil),
				internal.AddOp("/spec/initContainers", nil),
				internal.AddOp("/spec/containers/-", nil),
				internal.AddOp("/metadata/annotations/"+internal.EscapeJSONPointer(AnnotationAgentStatus), nil),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pod := testPod(tt.annotations)
			agentConfig := basicAgentConfig()
			err := Init(pod, agentConfig)
			if err != nil {
				t.Errorf("got error, shouldn't have: %s", err)
			}
			agent, err := New(pod)
			if err != nil {
				t.Errorf("got error, shouldn't have: %s", err)
			}
			patch, err := agent.Patch()
			if err != nil {
				t.Errorf("got error, shouldn't have: %s", err)
			}
			require.Equal(t, pod.Annotations[AnnotationAgentInjectContainers], tt.expectedValue)

			var output jsonpatch.Patch
			require.NoError(t, json.Unmarshal(patch, &output))
			for i := range tt.ExpectedPatch {
				delete(tt.ExpectedPatch[i], "value")
			}
			for i := range output {
				delete(output[i], "value")
			}
			require.Equal(t, tt.ExpectedPatch, output)
		})
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

		agentConfig := basicAgentConfig()
		err := Init(pod, agentConfig)
		if err != nil {
			t.Errorf("got error, shouldn't have: %s", err)
		}

		agent, err := New(pod)
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

func TestAuthMinMaxBackoff(t *testing.T) {
	pod := testPod(map[string]string{
		"vault.hashicorp.com/auth-min-backoff": "5s",
		"vault.hashicorp.com/auth-max-backoff": "10s",
	})
	agentConfig := basicAgentConfig()
	err := Init(pod, agentConfig)
	if err != nil {
		t.Errorf("got error, shouldn't have: %s", err)
	}

	agent, err := New(pod)
	if err != nil {
		t.Errorf("got error, shouldn't have: %s", err)
	}

	require.Equal(t, "5s", agent.Vault.AuthMinBackoff, "expected 5s, got %v", agent.Vault.AuthMinBackoff)
	require.Equal(t, "10s", agent.Vault.AuthMaxBackoff, "expected 10s, got %v", agent.Vault.AuthMaxBackoff)
}

func TestAutoAuthExitOnError(t *testing.T) {
	pod := testPod(map[string]string{
		"vault.hashicorp.com/agent-auto-auth-exit-on-err": "true",
	})
	agentConfig := basicAgentConfig()
	err := Init(pod, agentConfig)
	if err != nil {
		t.Errorf("got error, shouldn't have: %s", err)
	}

	agent, err := New(pod)
	if err != nil {
		t.Errorf("got error, shouldn't have: %s", err)
	}

	require.Equal(t, true, agent.AutoAuthExitOnError)
}

func TestDisableIdleConnections(t *testing.T) {
	tests := map[string]struct {
		annotations   map[string]string
		expectedValue []string
	}{
		"full list": {
			annotations: map[string]string{
				"vault.hashicorp.com/agent-disable-idle-connections": "auto-auth,caching,templating",
			},
			expectedValue: []string{"auto-auth", "caching", "templating"},
		},
		"one": {
			annotations: map[string]string{
				"vault.hashicorp.com/agent-disable-idle-connections": "auto-auth",
			},
			expectedValue: []string{"auto-auth"},
		},
		"none": {
			annotations:   map[string]string{},
			expectedValue: nil,
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			pod := testPod(tc.annotations)
			agentConfig := basicAgentConfig()
			err := Init(pod, agentConfig)
			require.NoError(t, err)
			agent, err := New(pod)
			require.NoError(t, err)

			assert.Equal(t, tc.expectedValue, agent.DisableIdleConnections)
		})
	}
}

func TestDisableKeepAlives(t *testing.T) {
	tests := map[string]struct {
		annotations   map[string]string
		expectedValue []string
	}{
		"full list": {
			annotations: map[string]string{
				"vault.hashicorp.com/agent-disable-keep-alives": "auto-auth,caching,templating",
			},
			expectedValue: []string{"auto-auth", "caching", "templating"},
		},
		"one": {
			annotations: map[string]string{
				"vault.hashicorp.com/agent-disable-keep-alives": "auto-auth",
			},
			expectedValue: []string{"auto-auth"},
		},
		"none": {
			annotations:   map[string]string{},
			expectedValue: nil,
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			pod := testPod(tc.annotations)
			agentConfig := basicAgentConfig()
			err := Init(pod, agentConfig)
			require.NoError(t, err)
			agent, err := New(pod)
			require.NoError(t, err)

			assert.Equal(t, tc.expectedValue, agent.DisableKeepAlives)
		})
	}
}

func TestParseTelemetryAnnotations(t *testing.T) {
	tests := map[string]struct {
		annotations    map[string]string
		expectedValues map[string]interface{}
	}{
		"prometheus": {
			annotations: map[string]string{
				"vault.hashicorp.com/agent-telemetry-prometheus_retention_time": "5s",
				"vault.hashicorp.com/agent-telemetry-disable_hostname":          "true",
			},
			expectedValues: map[string]interface{}{
				"prometheus_retention_time": "5s",
				"disable_hostname":          true,
			},
		},
		"common with some list annotations": {
			annotations: map[string]string{
				"vault.hashicorp.com/agent-telemetry-prefix_filter":             "[\"+vault.token\", \"-vault.expire\", \"+vault.expire.num_leases\"]",
				"vault.hashicorp.com/agent-telemetry-maximum_gauge_cardinality": "3",
				"vault.hashicorp.com/agent-telemetry-lease_metrics_epsilon":     "foo",
				"vault.hashicorp.com/agent-telemetry-enable_hostname_label":     "true",
			},
			expectedValues: map[string]interface{}{
				"prefix_filter":             []interface{}{"+vault.token", "-vault.expire", "+vault.expire.num_leases"},
				"maximum_gauge_cardinality": float64(3),
				"lease_metrics_epsilon":     "foo",
				"enable_hostname_label":     true,
			},
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			pod := testPod(tc.annotations)
			agentConfig := basicAgentConfig()
			err := Init(pod, agentConfig)
			require.NoError(t, err)
			agent, err := New(pod)
			require.NoError(t, err)
			require.Equal(t, true, reflect.DeepEqual(tc.expectedValues, agent.Vault.AgentTelemetryConfig))
		})
	}
}

func TestParseTemplateConfigAnnotations(t *testing.T) {
	tests := map[string]struct {
		annotations   map[string]string
		expectedValue float64
		expectedErr   bool
	}{
		"lease renewal threshold set": {
			annotations: map[string]string{
				"vault.hashicorp.com/template-lease-renewal-threshold": "0.75",
			},
			expectedValue: 0.75,
		},
		"lease renewal threshold unset": {
			annotations:   map[string]string{},
			expectedValue: 0,
		},
		"invalid lease renewal threshold": {
			annotations: map[string]string{
				"vault.hashicorp.com/template-lease-renewal-threshold": "one-third",
			},
			expectedValue: 0,
			expectedErr:   true,
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			pod := testPod(tc.annotations)
			agentConfig := basicAgentConfig()
			err := Init(pod, agentConfig)
			require.NoError(t, err)
			agent, err := New(pod)
			if tc.expectedErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tc.expectedValue, agent.VaultAgentTemplateConfig.LeaseRenewalThreshold)
			}
		})
	}
}
