// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package agent

import (
	"encoding/json"
	"fmt"
	"strconv"
	"testing"

	jsonpatch "github.com/evanphx/json-patch"
	"github.com/hashicorp/vault-k8s/agent-inject/internal"
	"github.com/hashicorp/vault/sdk/helper/pointerutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
)

func TestContainerSidecarVolume(t *testing.T) {
	annotations := map[string]string{
		AnnotationVaultRole: "foobar",
		// this will have different mount path
		fmt.Sprintf("%s-%s", AnnotationAgentInjectSecret, "secret1"):     "secrets/secret1",
		fmt.Sprintf("%s-%s", AnnotationVaultSecretVolumePath, "secret1"): "/etc/container_environment",

		// this secret will have same mount path as default mount path
		// adding this so we can make sure we don't have duplicate
		// volume mounts
		fmt.Sprintf("%s-%s", AnnotationAgentInjectSecret, "secret2"):     "secret/secret2",
		fmt.Sprintf("%s-%s", AnnotationVaultSecretVolumePath, "secret2"): "/etc/default_path",

		// Default path for all secrets
		AnnotationVaultSecretVolumePath: "/etc/default_path",

		fmt.Sprintf("%s-%s", AnnotationAgentInjectSecret, "secret3"): "secret/secret3",

		// Test adding an extra secret from Kube secrets for reference by Agent config
		fmt.Sprintf("%s", AnnotationAgentExtraSecret): "extrasecret",

		// Test copying volume mounts from an existing container in the Pod to the agent container
		fmt.Sprintf("%s", AnnotationAgentCopyVolumeMounts): "foobar",
	}

	pod := testPod(annotations)
	agentConfig := AgentConfig{
		Image:              "foobar-image",
		Address:            "http://foobar:1234",
		AuthType:           DefaultVaultAuthType,
		AuthPath:           "test",
		Namespace:          "test",
		RevokeOnShutdown:   true,
		UserID:             "1000",
		GroupID:            "100",
		SameID:             DefaultAgentRunAsSameUser,
		SetSecurityContext: DefaultAgentSetSecurityContext,
		DefaultTemplate:    "map",
		ResourceRequestCPU: DefaultResourceRequestCPU,
		ResourceRequestMem: DefaultResourceRequestMem,
		ResourceLimitCPU:   DefaultResourceLimitCPU,
		ResourceLimitMem:   DefaultResourceLimitMem,
		ExitOnRetryFailure: DefaultTemplateConfigExitOnRetryFailure,
	}

	err := Init(pod, agentConfig)
	if err != nil {
		t.Errorf("got error, shouldn't have: %s", err)
	}

	agent, err := New(pod)
	if err := agent.Validate(); err != nil {
		t.Errorf("agent validation failed, it shouldn't have: %s", err)
	}

	container, err := agent.ContainerSidecar()

	// One token volume mount, one config volume mount, two secrets volume mounts, and one mount copied from main container
	require.Equal(t, 6, len(container.VolumeMounts))

	require.Equal(
		t,
		[]corev1.VolumeMount{
			{
				Name:      agent.ServiceAccountTokenVolume.Name,
				MountPath: agent.ServiceAccountTokenVolume.MountPath,
				ReadOnly:  true,
			},
			{
				Name:      tokenVolumeNameSidecar,
				MountPath: tokenVolumePath,
				ReadOnly:  false,
			},
			{
				Name:      secretVolumeName,
				MountPath: agent.Annotations[AnnotationVaultSecretVolumePath],
				ReadOnly:  false,
			},
			{
				Name:      fmt.Sprintf("%s-custom-%d", secretVolumeName, 0),
				MountPath: "/etc/container_environment",
				ReadOnly:  false,
			},
			{
				Name:      extraSecretVolumeName,
				MountPath: extraSecretVolumePath,
				ReadOnly:  true,
			},
			{
				Name:      "tobecopied",
				MountPath: "/etc/somewhereelse",
				ReadOnly:  false,
			},
		},
		container.VolumeMounts,
	)
}

func TestContainerSidecarVolumeWithIRSA(t *testing.T) {
	annotations := map[string]string{
		AnnotationVaultRole: "foobar",
		// this will have different mount path
		fmt.Sprintf("%s-%s", AnnotationAgentInjectSecret, "secret1"):     "secrets/secret1",
		fmt.Sprintf("%s-%s", AnnotationVaultSecretVolumePath, "secret1"): "/etc/container_environment",

		// this secret will have same mount path as default mount path
		// adding this so we can make sure we don't have duplicate
		// volume mounts
		fmt.Sprintf("%s-%s", AnnotationAgentInjectSecret, "secret2"):     "secret/secret2",
		fmt.Sprintf("%s-%s", AnnotationVaultSecretVolumePath, "secret2"): "/etc/default_path",

		// Default path for all secrets
		AnnotationVaultSecretVolumePath: "/etc/default_path",

		fmt.Sprintf("%s-%s", AnnotationAgentInjectSecret, "secret3"): "secret/secret3",
	}

	pod := testPodIRSA(annotations)

	agentConfig := AgentConfig{
		Image:              "foobar-image",
		Address:            "http://foobar:1234",
		AuthType:           "aws",
		AuthPath:           "test",
		Namespace:          "test",
		RevokeOnShutdown:   true,
		UserID:             "1000",
		GroupID:            "100",
		SameID:             DefaultAgentRunAsSameUser,
		SetSecurityContext: DefaultAgentSetSecurityContext,
		DefaultTemplate:    "map",
		ResourceRequestCPU: DefaultResourceRequestCPU,
		ResourceRequestMem: DefaultResourceRequestMem,
		ResourceLimitCPU:   DefaultResourceLimitCPU,
		ResourceLimitMem:   DefaultResourceLimitMem,
		ExitOnRetryFailure: DefaultTemplateConfigExitOnRetryFailure,
	}

	err := Init(pod, agentConfig)
	if err != nil {
		t.Errorf("got error, shouldn't have: %s", err)
	}

	agent, err := New(pod)
	require.NoError(t, err)
	assert.Equal(t, "aws-iam-token", agent.AwsIamTokenAccountName)
	assert.Equal(t, "/var/run/secrets/eks.amazonaws.com/serviceaccount", agent.AwsIamTokenAccountPath)

	if err := agent.Validate(); err != nil {
		t.Errorf("agent validation failed, it shouldn't have: %s", err)
	}

	container, err := agent.ContainerSidecar()
	require.NoError(t, err)
	// One token volume mount, one config volume mount and two secrets volume mounts
	require.Equal(
		t,
		[]corev1.VolumeMount{
			{
				Name:      agent.ServiceAccountTokenVolume.Name,
				MountPath: agent.ServiceAccountTokenVolume.MountPath,
				ReadOnly:  true,
			},
			{
				Name:      tokenVolumeNameSidecar,
				MountPath: tokenVolumePath,
				ReadOnly:  false,
			},
			{
				Name:      agent.AwsIamTokenAccountName,
				MountPath: agent.AwsIamTokenAccountPath,
				ReadOnly:  true,
			},
			{
				Name:      secretVolumeName,
				MountPath: agent.Annotations[AnnotationVaultSecretVolumePath],
				ReadOnly:  false,
			},
			{
				Name:      fmt.Sprintf("%s-custom-%d", secretVolumeName, 0),
				MountPath: "/etc/container_environment",
				ReadOnly:  false,
			},
		},
		container.VolumeMounts,
	)
}

func TestContainerSidecar(t *testing.T) {
	annotations := map[string]string{
		AnnotationVaultRole: "foobar",
	}

	pod := testPod(annotations)

	agentConfig := AgentConfig{
		Image:              "foobar-image",
		Address:            "http://foobar:1234",
		AuthType:           DefaultVaultAuthType,
		AuthPath:           "test",
		Namespace:          "test",
		UserID:             "1000",
		GroupID:            "100",
		SameID:             DefaultAgentRunAsSameUser,
		SetSecurityContext: DefaultAgentSetSecurityContext,
		ProxyAddress:       "https://proxy:3128",
		DefaultTemplate:    "map",
		ResourceRequestCPU: DefaultResourceRequestCPU,
		ResourceRequestMem: DefaultResourceRequestMem,
		ResourceLimitCPU:   DefaultResourceLimitCPU,
		ResourceLimitMem:   DefaultResourceLimitMem,
		ExitOnRetryFailure: DefaultTemplateConfigExitOnRetryFailure,
	}

	err := Init(pod, agentConfig)
	if err != nil {
		t.Errorf("got error, shouldn't have: %s", err)
	}

	agent, err := New(pod)
	if err := agent.Validate(); err != nil {
		t.Errorf("agent validation failed, it shouldn't have: %s", err)
	}

	container, err := agent.ContainerSidecar()
	if err != nil {
		t.Errorf("creating container sidecar failed, it shouldn't have: %s", err)
	}

	expectedEnvs := 7
	if len(container.Env) != expectedEnvs {
		t.Errorf("wrong number of env vars, got %d, should have been %d", len(container.Env), expectedEnvs)
	}

	if container.Env[3].Name != "VAULT_LOG_LEVEL" {
		t.Errorf("env name wrong, should have been %s, got %s", "VAULT_LOG_LEVEL", container.Env[0].Name)
	}

	if container.Env[3].Value == "" {
		t.Error("env value empty, it shouldn't be")
	}

	if container.Env[4].Name != "VAULT_LOG_FORMAT" {
		t.Errorf("env name wrong, should have been %s, got %s", "VAULT_LOG_FORMAT", container.Env[1].Name)
	}

	if container.Env[5].Name != "HTTPS_PROXY" {
		t.Errorf("env name wrong, should have been %s, got %s", "HTTPS_PROXY", container.Env[2].Name)
	}

	if container.Env[4].Value == "" {
		t.Error("env value empty, it shouldn't be")
	}

	if container.Env[6].Name != "VAULT_CONFIG" {
		t.Errorf("env name wrong, should have been %s, got %s", "VAULT_CONFIG", container.Env[3].Name)
	}

	if container.Env[5].Value == "" {
		t.Error("env value empty, it shouldn't be")
	}

	if len(container.Args) != 1 {
		t.Errorf("wrong number of args, got %d, should have been %d", len(container.Args), 1)
	}

	if container.Args[0] != DefaultContainerArg {
		t.Errorf("arg value wrong, should have been %s, got %s", DefaultContainerArg, container.Args[0])
	}

	if container.Resources.Limits.Cpu().String() != DefaultResourceLimitCPU {
		t.Errorf("resource cpu limit value wrong, should have been %s, got %s", DefaultResourceLimitCPU, container.Resources.Limits.Cpu().String())
	}

	if container.Resources.Limits.Memory().String() != DefaultResourceLimitMem {
		t.Errorf("resource memory limit value wrong, should have been %s, got %s", DefaultResourceLimitMem, container.Resources.Limits.Memory().String())
	}

	if value, ok := container.Resources.Limits.StorageEphemeral().AsInt64(); !ok || value != 0 {
		t.Errorf("resource ephemeral storage limit value is wrong, should have been unset, got %s", container.Resources.Limits.StorageEphemeral().String())
	}

	if container.Resources.Requests.Cpu().String() != DefaultResourceRequestCPU {
		t.Errorf("resource cpu requests value wrong, should have been %s, got %s", DefaultResourceRequestCPU, container.Resources.Requests.Cpu().String())
	}

	if container.Resources.Requests.Memory().String() != DefaultResourceRequestMem {
		t.Errorf("resource memory requests value wrong, should have been %s, got %s", DefaultResourceRequestMem, container.Resources.Requests.Memory().String())
	}

	if value, ok := container.Resources.Requests.StorageEphemeral().AsInt64(); !ok || value != 0 {
		t.Errorf("resource ephemeral storage requests value is wrong, should have been unset, got %s", container.Resources.Requests.Memory().String())
	}

	for _, volumeMount := range container.VolumeMounts {
		if volumeMount.Name == secretVolumeName && volumeMount.MountPath != annotations[AnnotationVaultSecretVolumePath] {
			t.Errorf("secrets volume path is wrong, should have been %s, got %s", volumeMount.MountPath, annotations[AnnotationVaultSecretVolumePath])
		}
	}
}

func TestContainerSidecarRevokeHook(t *testing.T) {
	trueString := "true"
	falseString := "false"

	tests := []struct {
		revokeFlag       bool
		revokeAnnotation *string
		expectedPresence bool
	}{
		{revokeFlag: true, revokeAnnotation: nil, expectedPresence: true},
		{revokeFlag: false, revokeAnnotation: nil, expectedPresence: false},
		{revokeFlag: true, revokeAnnotation: &trueString, expectedPresence: true},
		{revokeFlag: true, revokeAnnotation: &falseString, expectedPresence: false},
		{revokeFlag: false, revokeAnnotation: &trueString, expectedPresence: true},
		{revokeFlag: false, revokeAnnotation: &falseString, expectedPresence: false},
	}

	for _, tt := range tests {
		t.Run("revoke test", func(t *testing.T) {
			var revokeAnnotation string

			annotations := map[string]string{
				AnnotationVaultRole: "foobar",
			}

			if tt.revokeAnnotation == nil {
				revokeAnnotation = "<absent>"
			} else {
				annotations[AnnotationAgentRevokeOnShutdown] = *tt.revokeAnnotation
			}

			pod := testPod(annotations)

			agentConfig := AgentConfig{
				Image:              "foobar-image",
				Address:            "http://foobar:1234",
				AuthType:           DefaultVaultAuthType,
				AuthPath:           "test",
				Namespace:          "test",
				RevokeOnShutdown:   tt.revokeFlag,
				UserID:             "1000",
				GroupID:            "100",
				SameID:             DefaultAgentRunAsSameUser,
				SetSecurityContext: DefaultAgentSetSecurityContext,
				DefaultTemplate:    "map",
				ResourceRequestCPU: DefaultResourceRequestCPU,
				ResourceRequestMem: DefaultResourceRequestMem,
				ResourceLimitCPU:   DefaultResourceLimitCPU,
				ResourceLimitMem:   DefaultResourceLimitMem,
				ExitOnRetryFailure: DefaultTemplateConfigExitOnRetryFailure,
			}

			err := Init(pod, agentConfig)
			if err != nil {
				t.Errorf("got error, shouldn't have: %s", err)
			}

			agent, err := New(pod)
			if err := agent.Validate(); err != nil {
				t.Errorf("agent validation failed, it shouldn't have: %s", err)
			}

			container, err := agent.ContainerSidecar()
			if err != nil {
				t.Errorf("creating container sidecar failed, it shouldn't have: %s", err)
			}

			if tt.expectedPresence && container.Lifecycle.PreStop == nil {
				t.Errorf("revoke flag was %t and annotation was %s but preStop hook was absent when it was expected to be present", tt.revokeFlag, revokeAnnotation)
			}

			if !tt.expectedPresence && container.Lifecycle.PreStop != nil {
				t.Errorf("revoke flag was %t and annotation was %s but preStop hook was present when it was expected to not be present", tt.revokeFlag, revokeAnnotation)
			}
		})
	}
}

func TestContainerSidecarConfigMap(t *testing.T) {
	// None of these custom configs should matter since
	// we have AnnotationAgentConfigMap set
	annotations := map[string]string{
		AnnotationAgentConfigMap:                        "foobarConfigMap",
		AnnotationVaultRole:                             "foobar",
		AnnotationAgentPrePopulate:                      "true",
		AnnotationAgentPrePopulateOnly:                  "true",
		AnnotationVaultTLSSkipVerify:                    "true",
		AnnotationVaultTLSServerName:                    "foobar.server",
		AnnotationVaultCACert:                           "ca-cert",
		AnnotationVaultCAKey:                            "ca-key",
		AnnotationVaultClientCert:                       "client-cert",
		AnnotationVaultClientKey:                        "client-key",
		AnnotationVaultSecretVolumePath:                 "/foo/bar",
		"vault.hashicorp.com/agent-inject-secret-foo":   "db/creds/foo",
		"vault.hashicorp.com/agent-inject-template-foo": "template foo",
		"vault.hashicorp.com/agent-inject-secret-bar":   "db/creds/bar",
	}

	pod := testPod(annotations)

	agentConfig := AgentConfig{
		Image:              "foobar-image",
		Address:            "http://foobar:1234",
		AuthType:           DefaultVaultAuthType,
		AuthPath:           "test",
		Namespace:          "test",
		RevokeOnShutdown:   true,
		UserID:             "1000",
		GroupID:            "100",
		SameID:             DefaultAgentRunAsSameUser,
		SetSecurityContext: DefaultAgentSetSecurityContext,
		DefaultTemplate:    "map",
		ResourceRequestCPU: DefaultResourceRequestCPU,
		ResourceRequestMem: DefaultResourceRequestMem,
		ResourceLimitCPU:   DefaultResourceLimitCPU,
		ResourceLimitMem:   DefaultResourceLimitMem,
		ExitOnRetryFailure: DefaultTemplateConfigExitOnRetryFailure,
	}

	err := Init(pod, agentConfig)
	if err != nil {
		t.Errorf("got error, shouldn't have: %s", err)
	}

	agent, err := New(pod)
	if err := agent.Validate(); err != nil {
		t.Errorf("agent validation failed, it shouldn't have: %s", err)
	}

	container, err := agent.ContainerSidecar()
	if err != nil {
		t.Errorf("creating container sidecar failed, it shouldn't have: %s", err)
	}

	expectedEnvs := 12
	if len(container.Env) != expectedEnvs {
		t.Errorf("wrong number of env vars, got %d, should have been %d", len(container.Env), expectedEnvs)
	}

	arg := fmt.Sprintf("touch %s && vault agent -config=%s/config.hcl", TokenFile, configVolumePath)
	if container.Args[0] != arg {
		t.Errorf("arg value wrong, should have been %s, got %s", arg, container.Args[0])
	}
}

func TestContainerSidecarCustomResources(t *testing.T) {
	absent := "absent"

	tests := []struct {
		name               string
		agent              Agent
		expectedLimitCPU   string
		expectedLimitMem   string
		expectedLimitEph   string
		expectedRequestCPU string
		expectedRequestMem string
		expectedRequestEph string
		expectedErr        bool
	}{
		{
			name: "valid M",
			agent: Agent{
				LimitsCPU:         "500M",
				LimitsMem:         "128M",
				LimitsEphemeral:   "128M",
				RequestsCPU:       "250M",
				RequestsMem:       "64M",
				RequestsEphemeral: "64M",
			},
			expectedLimitCPU:   "500M",
			expectedLimitMem:   "128M",
			expectedLimitEph:   "128M",
			expectedRequestCPU: "250M",
			expectedRequestMem: "64M",
			expectedRequestEph: "64M",
			expectedErr:        false,
		},
		{
			name: "valid G",
			agent: Agent{
				LimitsCPU:         "500G",
				LimitsMem:         "128G",
				LimitsEphemeral:   "128G",
				RequestsCPU:       "250G",
				RequestsMem:       "64G",
				RequestsEphemeral: "64G",
			},
			expectedLimitCPU:   "500G",
			expectedLimitMem:   "128G",
			expectedLimitEph:   "128G",
			expectedRequestCPU: "250G",
			expectedRequestMem: "64G",
			expectedRequestEph: "64G",
			expectedErr:        false,
		},
		{
			name: "valid Mi",
			agent: Agent{
				LimitsCPU:         "500Mi",
				LimitsMem:         "128Mi",
				LimitsEphemeral:   "128Mi",
				RequestsCPU:       "250Mi",
				RequestsMem:       "64Mi",
				RequestsEphemeral: "64Mi",
			},
			expectedLimitCPU:   "500Mi",
			expectedLimitMem:   "128Mi",
			expectedLimitEph:   "128Mi",
			expectedRequestCPU: "250Mi",
			expectedRequestMem: "64Mi",
			expectedRequestEph: "64Mi",
			expectedErr:        false,
		},
		{
			name: "valid Gi",
			agent: Agent{
				LimitsCPU:         "500Gi",
				LimitsMem:         "128Gi",
				LimitsEphemeral:   "128Gi",
				RequestsCPU:       "250Gi",
				RequestsMem:       "64Gi",
				RequestsEphemeral: "64Gi",
			},
			expectedLimitCPU:   "500Gi",
			expectedLimitMem:   "128Gi",
			expectedLimitEph:   "128Gi",
			expectedRequestCPU: "250Gi",
			expectedRequestMem: "64Gi",
			expectedRequestEph: "64Gi",
			expectedErr:        false,
		},
		{
			name: "valid none",
			agent: Agent{
				LimitsCPU:         "",
				LimitsMem:         "",
				LimitsEphemeral:   "",
				RequestsCPU:       "",
				RequestsMem:       "",
				RequestsEphemeral: "",
			},
			expectedLimitCPU:   absent,
			expectedLimitMem:   absent,
			expectedLimitEph:   absent,
			expectedRequestCPU: absent,
			expectedRequestMem: absent,
			expectedRequestEph: absent,
			expectedErr:        false,
		},
		{
			name: "valid 0",
			agent: Agent{
				LimitsCPU:         "0",
				LimitsMem:         "0",
				LimitsEphemeral:   "0",
				RequestsCPU:       "0",
				RequestsMem:       "0",
				RequestsEphemeral: "0",
			},
			expectedLimitCPU:   "0",
			expectedLimitMem:   "0",
			expectedLimitEph:   "0",
			expectedRequestCPU: "0",
			expectedRequestMem: "0",
			expectedRequestEph: "0",
			expectedErr:        false,
		},
		{
			name: "valid no requests",
			agent: Agent{
				LimitsCPU:         "500Mi",
				LimitsMem:         "128m",
				LimitsEphemeral:   "128m",
				RequestsCPU:       "",
				RequestsMem:       "",
				RequestsEphemeral: "",
			},
			expectedLimitCPU:   "500Mi",
			expectedLimitMem:   "128m",
			expectedLimitEph:   "128m",
			expectedRequestCPU: absent,
			expectedRequestMem: absent,
			expectedRequestEph: absent,
			expectedErr:        false,
		},
		{
			name: "valid no limits",
			agent: Agent{
				LimitsCPU:         "",
				LimitsMem:         "",
				LimitsEphemeral:   "",
				RequestsCPU:       "250Mi",
				RequestsMem:       "64m",
				RequestsEphemeral: "64m",
			},
			expectedLimitCPU:   absent,
			expectedLimitMem:   absent,
			expectedLimitEph:   absent,
			expectedRequestCPU: "250Mi",
			expectedRequestMem: "64m",
			expectedRequestEph: "64m",
			expectedErr:        false,
		},
		{
			name: "valid just cpu limit",
			agent: Agent{
				LimitsCPU:         "500Mi",
				LimitsMem:         "",
				LimitsEphemeral:   "",
				RequestsCPU:       "",
				RequestsMem:       "",
				RequestsEphemeral: "",
			},
			expectedLimitCPU:   "500Mi",
			expectedLimitMem:   absent,
			expectedLimitEph:   absent,
			expectedRequestCPU: absent,
			expectedRequestMem: absent,
			expectedRequestEph: absent,
			expectedErr:        false,
		},
		{
			name: "valid just mem limit",
			agent: Agent{
				LimitsCPU:         "",
				LimitsMem:         "128m",
				LimitsEphemeral:   "",
				RequestsCPU:       "",
				RequestsMem:       "",
				RequestsEphemeral: "",
			},
			expectedLimitCPU:   absent,
			expectedLimitMem:   "128m",
			expectedLimitEph:   absent,
			expectedRequestCPU: absent,
			expectedRequestMem: absent,
			expectedRequestEph: absent,
			expectedErr:        false,
		},
		{
			name: "valid just eph storage limit",
			agent: Agent{
				LimitsCPU:         "",
				LimitsMem:         "",
				LimitsEphemeral:   "128m",
				RequestsCPU:       "",
				RequestsMem:       "",
				RequestsEphemeral: "",
			},
			expectedLimitCPU:   absent,
			expectedLimitMem:   absent,
			expectedLimitEph:   "128m",
			expectedRequestCPU: absent,
			expectedRequestMem: absent,
			expectedRequestEph: absent,
			expectedErr:        false,
		},
		{
			name: "valid just cpu request",
			agent: Agent{
				LimitsCPU:         "",
				LimitsMem:         "",
				LimitsEphemeral:   "",
				RequestsCPU:       "500Mi",
				RequestsMem:       "",
				RequestsEphemeral: "",
			},
			expectedLimitCPU:   absent,
			expectedLimitMem:   absent,
			expectedLimitEph:   absent,
			expectedRequestCPU: "500Mi",
			expectedRequestMem: absent,
			expectedRequestEph: absent,
			expectedErr:        false,
		},
		{
			name: "valid just mem request",
			agent: Agent{
				LimitsCPU:         "",
				LimitsMem:         "",
				LimitsEphemeral:   "",
				RequestsCPU:       "",
				RequestsMem:       "128m",
				RequestsEphemeral: "",
			},
			expectedLimitCPU:   absent,
			expectedLimitMem:   absent,
			expectedLimitEph:   absent,
			expectedRequestCPU: absent,
			expectedRequestMem: "128m",
			expectedRequestEph: absent,
			expectedErr:        false,
		},
		{
			name: "valid just eph storage request",
			agent: Agent{
				LimitsCPU:         "",
				LimitsMem:         "",
				LimitsEphemeral:   "",
				RequestsCPU:       "",
				RequestsMem:       "",
				RequestsEphemeral: "128m",
			},
			expectedLimitCPU:   absent,
			expectedLimitMem:   absent,
			expectedLimitEph:   absent,
			expectedRequestCPU: absent,
			expectedRequestMem: absent,
			expectedRequestEph: "128m",
			expectedErr:        false,
		},
		{
			name: "invalid cpu Mi notation",
			agent: Agent{
				LimitsCPU:   "500mi",
				LimitsMem:   "128m",
				RequestsCPU: "250mi",
				RequestsMem: "64m",
			},
			expectedLimitCPU:   "500mi",
			expectedLimitMem:   "128m",
			expectedRequestCPU: "250mi",
			expectedRequestMem: "64m",
			expectedErr:        true,
		},
		{
			name: "invalid cpu Gi notation",
			agent: Agent{
				LimitsCPU:   "500gi",
				LimitsMem:   "128m",
				RequestsCPU: "250gi",
				RequestsMem: "64m",
			},
			expectedLimitCPU:   "500gi",
			expectedLimitMem:   "128m",
			expectedRequestCPU: "250gi",
			expectedRequestMem: "64m",
			expectedErr:        true,
		},
		{
			name: "invalid mem m notation",
			agent: Agent{
				LimitsCPU:   "500Mi",
				LimitsMem:   "128mb",
				RequestsCPU: "250Mi",
				RequestsMem: "64mb",
			},
			expectedLimitCPU:   "500Mi",
			expectedLimitMem:   "128m",
			expectedRequestCPU: "250Mi",
			expectedRequestMem: "64m",
			expectedErr:        true,
		},
		{
			name: "invalid mem g notation",
			agent: Agent{
				LimitsCPU:   "500Mi",
				LimitsMem:   "128g",
				RequestsCPU: "250Mi",
				RequestsMem: "64g",
			},
			expectedLimitCPU:   "500Mi",
			expectedLimitMem:   "128m",
			expectedRequestCPU: "250Mi",
			expectedRequestMem: "64m",
			expectedErr:        true,
		},
		{
			name: "invalid mem gi notation",
			agent: Agent{
				LimitsCPU:   "500Mi",
				LimitsMem:   "128gi",
				RequestsCPU: "250Mi",
				RequestsMem: "64gi",
			},
			expectedLimitCPU:   "500Mi",
			expectedLimitMem:   "128m",
			expectedRequestCPU: "250Mi",
			expectedRequestMem: "64m",
			expectedErr:        true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resources, err := tt.agent.parseResources()
			if !tt.expectedErr && err != nil {
				t.Errorf("got error, shouldn't have: %s", err)
			}

			if tt.expectedErr && err == nil {
				t.Errorf("got no error, should have: %s", tt.name)
			}

			if !tt.expectedErr {
				cpu, exists := resources.Limits["cpu"]
				if tt.expectedLimitCPU == absent && exists {
					t.Errorf("expected cpu limit to not exist")
				} else if tt.expectedLimitCPU != absent && cpu.String() != tt.expectedLimitCPU {
					t.Errorf("expected cpu limit mismatch: wanted %s, got %s", tt.expectedLimitCPU, cpu.String())
				}

				mem, exists := resources.Limits["memory"]
				if tt.expectedLimitMem == absent && exists {
					t.Errorf("expected mem limit to not exist")
				} else if tt.expectedLimitMem != absent && mem.String() != tt.expectedLimitMem {
					t.Errorf("expected mem limit mismatch: wanted %s, got %s", tt.expectedLimitMem, mem.String())
				}

				eph, exists := resources.Limits["ephemeral-storage"]
				if tt.expectedLimitEph == absent && exists {
					t.Errorf("expected eph storage limit to not exist")
				} else if tt.expectedLimitEph != absent && eph.String() != tt.expectedLimitEph {
					t.Errorf("expected eph storage limit mismatch: wanted %s, got %s", tt.expectedLimitEph, eph.String())
				}

				cpu, exists = resources.Requests["cpu"]
				if tt.expectedRequestCPU == absent && exists {
					t.Errorf("expected cpu request to not exist")
				} else if tt.expectedRequestCPU != absent && cpu.String() != tt.expectedRequestCPU {
					t.Errorf("expected cpu request mismatch: wanted %s, got %s", tt.expectedRequestCPU, cpu.String())
				}

				mem, exists = resources.Requests["memory"]
				if tt.expectedRequestMem == absent && exists {
					t.Errorf("expected mem limit to not exist")
				} else if tt.expectedRequestMem != absent && mem.String() != tt.expectedRequestMem {
					t.Errorf("expected mem request mismatch: wanted %s, got %s", tt.expectedRequestMem, mem.String())
				}

				eph, exists = resources.Requests["ephemeral-storage"]
				if tt.expectedRequestEph == absent && exists {
					t.Errorf("expected eph storage limit to not exist")
				} else if tt.expectedRequestEph != absent && eph.String() != tt.expectedRequestEph {
					t.Errorf("expected eph storage request mismatch: wanted %s, got %s", tt.expectedRequestMem, eph.String())
				}
			}
		})
	}
}

func TestContainerSidecarSecurityContext(t *testing.T) {
	type startupOptions struct {
		runAsUser                int64
		runAsGroup               int64
		runAsSameUser            bool
		readOnlyRoot             bool
		setSecurityContext       bool
		allowPrivilegeEscalation bool
		capabilities             []string
	}
	tests := []struct {
		name                    string
		startup                 startupOptions
		annotations             map[string]string
		appSCC                  *corev1.SecurityContext
		expectedSecurityContext *corev1.SecurityContext
	}{
		{
			name: "Runtime defaults, no annotations",
			startup: startupOptions{
				runAsUser:                DefaultAgentRunAsUser,
				runAsGroup:               DefaultAgentRunAsGroup,
				runAsSameUser:            DefaultAgentRunAsSameUser,
				setSecurityContext:       DefaultAgentSetSecurityContext,
				readOnlyRoot:             DefaultAgentReadOnlyRoot,
				allowPrivilegeEscalation: DefaultAgentAllowPrivilegeEscalation,
				capabilities:             []string{DefaultAgentDropCapabilities},
			},
			annotations: map[string]string{},
			appSCC:      nil,
			expectedSecurityContext: &corev1.SecurityContext{
				RunAsUser:              pointerutil.Int64Ptr(DefaultAgentRunAsUser),
				RunAsGroup:             pointerutil.Int64Ptr(DefaultAgentRunAsGroup),
				RunAsNonRoot:           pointerutil.BoolPtr(true),
				ReadOnlyRootFilesystem: pointerutil.BoolPtr(DefaultAgentReadOnlyRoot),
				Capabilities: &corev1.Capabilities{
					Drop: []corev1.Capability{DefaultAgentDropCapabilities},
				},
				AllowPrivilegeEscalation: pointerutil.BoolPtr(DefaultAgentAllowPrivilegeEscalation),
			},
		},
		{
			name: "Runtime defaults, non-root user and group annotations",
			startup: startupOptions{
				runAsUser:                DefaultAgentRunAsUser,
				runAsGroup:               DefaultAgentRunAsGroup,
				runAsSameUser:            DefaultAgentRunAsSameUser,
				setSecurityContext:       DefaultAgentSetSecurityContext,
				readOnlyRoot:             DefaultAgentReadOnlyRoot,
				allowPrivilegeEscalation: DefaultAgentAllowPrivilegeEscalation,
				capabilities:             []string{DefaultAgentDropCapabilities},
			},
			annotations: map[string]string{
				AnnotationAgentRunAsUser:  "1001",
				AnnotationAgentRunAsGroup: "1001",
			},
			appSCC: nil,
			expectedSecurityContext: &corev1.SecurityContext{
				RunAsUser:              pointerutil.Int64Ptr(1001),
				RunAsGroup:             pointerutil.Int64Ptr(1001),
				RunAsNonRoot:           pointerutil.BoolPtr(true),
				ReadOnlyRootFilesystem: pointerutil.BoolPtr(DefaultAgentReadOnlyRoot),
				Capabilities: &corev1.Capabilities{
					Drop: []corev1.Capability{DefaultAgentDropCapabilities},
				},
				AllowPrivilegeEscalation: pointerutil.BoolPtr(DefaultAgentAllowPrivilegeEscalation),
			},
		},
		{
			name: "Runtime defaults, root user and group annotations",
			startup: startupOptions{
				runAsUser:                DefaultAgentRunAsUser,
				runAsGroup:               DefaultAgentRunAsGroup,
				runAsSameUser:            DefaultAgentRunAsSameUser,
				setSecurityContext:       DefaultAgentSetSecurityContext,
				readOnlyRoot:             DefaultAgentReadOnlyRoot,
				allowPrivilegeEscalation: DefaultAgentAllowPrivilegeEscalation,
				capabilities:             []string{DefaultAgentDropCapabilities},
			},
			annotations: map[string]string{
				AnnotationAgentRunAsUser:  "0",
				AnnotationAgentRunAsGroup: "0",
			},
			appSCC: nil,
			expectedSecurityContext: &corev1.SecurityContext{
				RunAsUser:              pointerutil.Int64Ptr(0),
				RunAsGroup:             pointerutil.Int64Ptr(0),
				RunAsNonRoot:           pointerutil.BoolPtr(false),
				ReadOnlyRootFilesystem: pointerutil.BoolPtr(DefaultAgentReadOnlyRoot),
				Capabilities: &corev1.Capabilities{
					Drop: []corev1.Capability{DefaultAgentDropCapabilities},
				},
				AllowPrivilegeEscalation: pointerutil.BoolPtr(DefaultAgentAllowPrivilegeEscalation),
			},
		},
		{
			name: "Runtime defaults, root user and non-root group annotations",
			startup: startupOptions{
				runAsUser:                DefaultAgentRunAsUser,
				runAsGroup:               DefaultAgentRunAsGroup,
				runAsSameUser:            DefaultAgentRunAsSameUser,
				setSecurityContext:       DefaultAgentSetSecurityContext,
				readOnlyRoot:             DefaultAgentReadOnlyRoot,
				allowPrivilegeEscalation: DefaultAgentAllowPrivilegeEscalation,
				capabilities:             []string{DefaultAgentDropCapabilities},
			},
			annotations: map[string]string{
				AnnotationAgentRunAsUser:  "0",
				AnnotationAgentRunAsGroup: "100",
			},
			appSCC: nil,
			expectedSecurityContext: &corev1.SecurityContext{
				RunAsUser:              pointerutil.Int64Ptr(0),
				RunAsGroup:             pointerutil.Int64Ptr(100),
				RunAsNonRoot:           pointerutil.BoolPtr(false),
				ReadOnlyRootFilesystem: pointerutil.BoolPtr(DefaultAgentReadOnlyRoot),
				Capabilities: &corev1.Capabilities{
					Drop: []corev1.Capability{DefaultAgentDropCapabilities},
				},
				AllowPrivilegeEscalation: pointerutil.BoolPtr(DefaultAgentAllowPrivilegeEscalation),
			},
		},
		{
			name: "Runtime defaults, non-root user and root group annotations",
			startup: startupOptions{
				runAsUser:                DefaultAgentRunAsUser,
				runAsGroup:               DefaultAgentRunAsGroup,
				runAsSameUser:            DefaultAgentRunAsSameUser,
				setSecurityContext:       DefaultAgentSetSecurityContext,
				readOnlyRoot:             DefaultAgentReadOnlyRoot,
				allowPrivilegeEscalation: DefaultAgentAllowPrivilegeEscalation,
				capabilities:             []string{DefaultAgentDropCapabilities},
			},
			annotations: map[string]string{
				AnnotationAgentRunAsUser:  "100",
				AnnotationAgentRunAsGroup: "0",
			},
			appSCC: nil,
			expectedSecurityContext: &corev1.SecurityContext{
				RunAsUser:              pointerutil.Int64Ptr(100),
				RunAsGroup:             pointerutil.Int64Ptr(0),
				RunAsNonRoot:           pointerutil.BoolPtr(false),
				ReadOnlyRootFilesystem: pointerutil.BoolPtr(DefaultAgentReadOnlyRoot),
				Capabilities: &corev1.Capabilities{
					Drop: []corev1.Capability{DefaultAgentDropCapabilities},
				},
				AllowPrivilegeEscalation: pointerutil.BoolPtr(DefaultAgentAllowPrivilegeEscalation),
			},
		},
		{
			name: "Runtime no security context, no annotations",
			startup: startupOptions{
				runAsUser:                DefaultAgentRunAsUser,
				runAsGroup:               DefaultAgentRunAsGroup,
				runAsSameUser:            DefaultAgentRunAsSameUser,
				setSecurityContext:       false,
				readOnlyRoot:             DefaultAgentReadOnlyRoot,
				allowPrivilegeEscalation: DefaultAgentAllowPrivilegeEscalation,
				capabilities:             []string{DefaultAgentDropCapabilities},
			},
			annotations:             map[string]string{},
			appSCC:                  nil,
			expectedSecurityContext: nil,
		},
		{
			name: "Runtime no security context, but user annotation",
			startup: startupOptions{
				runAsUser:                DefaultAgentRunAsUser,
				runAsGroup:               DefaultAgentRunAsGroup,
				runAsSameUser:            DefaultAgentRunAsSameUser,
				setSecurityContext:       false,
				readOnlyRoot:             DefaultAgentReadOnlyRoot,
				allowPrivilegeEscalation: DefaultAgentAllowPrivilegeEscalation,
				capabilities:             []string{DefaultAgentDropCapabilities},
			},
			annotations: map[string]string{
				AnnotationAgentRunAsUser: "100",
			},
			appSCC: nil,
			expectedSecurityContext: &corev1.SecurityContext{
				RunAsUser:              pointerutil.Int64Ptr(100),
				RunAsGroup:             pointerutil.Int64Ptr(DefaultAgentRunAsGroup),
				RunAsNonRoot:           pointerutil.BoolPtr(true),
				ReadOnlyRootFilesystem: pointerutil.BoolPtr(DefaultAgentReadOnlyRoot),
				Capabilities: &corev1.Capabilities{
					Drop: []corev1.Capability{DefaultAgentDropCapabilities},
				},
				AllowPrivilegeEscalation: pointerutil.BoolPtr(DefaultAgentAllowPrivilegeEscalation),
			},
		},
		{
			name: "Runtime defaults, but user annotation with no security context",
			startup: startupOptions{
				runAsUser:                DefaultAgentRunAsUser,
				runAsGroup:               DefaultAgentRunAsGroup,
				runAsSameUser:            DefaultAgentRunAsSameUser,
				setSecurityContext:       DefaultAgentSetSecurityContext,
				readOnlyRoot:             DefaultAgentReadOnlyRoot,
				allowPrivilegeEscalation: DefaultAgentAllowPrivilegeEscalation,
				capabilities:             []string{DefaultAgentDropCapabilities},
			},
			annotations: map[string]string{
				AnnotationAgentRunAsUser:          "100",
				AnnotationAgentSetSecurityContext: "false",
			},
			appSCC:                  nil,
			expectedSecurityContext: nil,
		},
		{
			name: "Runtime sameAsUser, no annotations",
			startup: startupOptions{
				runAsUser:                DefaultAgentRunAsUser,
				runAsGroup:               DefaultAgentRunAsGroup,
				runAsSameUser:            true,
				setSecurityContext:       DefaultAgentSetSecurityContext,
				readOnlyRoot:             DefaultAgentReadOnlyRoot,
				allowPrivilegeEscalation: DefaultAgentAllowPrivilegeEscalation,
				capabilities:             []string{DefaultAgentDropCapabilities},
			},
			annotations: map[string]string{},
			appSCC: &corev1.SecurityContext{
				RunAsUser: pointerutil.Int64Ptr(123456),
			},
			expectedSecurityContext: &corev1.SecurityContext{
				RunAsUser:              pointerutil.Int64Ptr(123456),
				RunAsGroup:             pointerutil.Int64Ptr(DefaultAgentRunAsGroup),
				RunAsNonRoot:           pointerutil.BoolPtr(true),
				ReadOnlyRootFilesystem: pointerutil.BoolPtr(DefaultAgentReadOnlyRoot),
				Capabilities: &corev1.Capabilities{
					Drop: []corev1.Capability{DefaultAgentDropCapabilities},
				},
				AllowPrivilegeEscalation: pointerutil.BoolPtr(DefaultAgentAllowPrivilegeEscalation),
			},
		},
		{
			name: "Runtime defaults, sameAsUser annotation",
			startup: startupOptions{
				runAsUser:                DefaultAgentRunAsUser,
				runAsGroup:               DefaultAgentRunAsGroup,
				runAsSameUser:            DefaultAgentRunAsSameUser,
				setSecurityContext:       DefaultAgentSetSecurityContext,
				readOnlyRoot:             DefaultAgentReadOnlyRoot,
				allowPrivilegeEscalation: DefaultAgentAllowPrivilegeEscalation,
				capabilities:             []string{DefaultAgentDropCapabilities},
			},
			annotations: map[string]string{
				AnnotationAgentRunAsSameUser: "true",
			},
			appSCC: &corev1.SecurityContext{
				RunAsUser: pointerutil.Int64Ptr(123456),
			},
			expectedSecurityContext: &corev1.SecurityContext{
				RunAsUser:              pointerutil.Int64Ptr(123456),
				RunAsGroup:             pointerutil.Int64Ptr(DefaultAgentRunAsGroup),
				RunAsNonRoot:           pointerutil.BoolPtr(true),
				ReadOnlyRootFilesystem: pointerutil.BoolPtr(DefaultAgentReadOnlyRoot),
				Capabilities: &corev1.Capabilities{
					Drop: []corev1.Capability{DefaultAgentDropCapabilities},
				},
				AllowPrivilegeEscalation: pointerutil.BoolPtr(DefaultAgentAllowPrivilegeEscalation),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			agentConfig := AgentConfig{
				Image:              "foobar-image",
				Address:            "http://foobar:1234",
				AuthPath:           "test",
				Namespace:          "test",
				RevokeOnShutdown:   true,
				UserID:             strconv.FormatInt(tt.startup.runAsUser, 10),
				GroupID:            strconv.FormatInt(tt.startup.runAsGroup, 10),
				SetSecurityContext: tt.startup.setSecurityContext,
				SameID:             tt.startup.runAsSameUser,
				ProxyAddress:       "",
			}

			tt.annotations[AnnotationVaultRole] = "foobar"
			pod := testPod(tt.annotations)
			pod.Spec.Containers[0].SecurityContext = tt.appSCC

			err := Init(pod, agentConfig)
			if err != nil {
				t.Errorf("got error, shouldn't have: %s", err)
			}

			agent, err := New(pod)
			if err := agent.Validate(); err != nil {
				t.Errorf("agent validation failed, it shouldn't have: %s", err)
			}

			container, err := agent.ContainerSidecar()
			if err != nil {
				t.Errorf("got error, shouldn't have: %s", err)
			}

			require.Equal(t, tt.expectedSecurityContext, container.SecurityContext)
		})
	}
}

func TestContainerCache(t *testing.T) {
	cacheMount := []corev1.VolumeMount{
		{
			Name:      cacheVolumeName,
			MountPath: cacheVolumePath,
			ReadOnly:  false,
		},
	}
	cacheVolumePatch := []jsonpatch.Operation{
		internal.AddOp("/spec/volumes", []v1.Volume{
			{
				Name: "vault-agent-cache",
				VolumeSource: v1.VolumeSource{
					EmptyDir: &v1.EmptyDirVolumeSource{
						Medium: "Memory",
					},
				},
			},
		}),
	}

	tests := []struct {
		name                   string
		annotations            map[string]string
		expectCacheVolAndMount bool
	}{
		{
			"cache enabled",
			map[string]string{
				AnnotationVaultRole:        "role",
				AnnotationAgentCacheEnable: "true",
			},
			true,
		},
		{
			"cache disabled",
			map[string]string{
				AnnotationVaultRole:        "role",
				AnnotationAgentCacheEnable: "false",
			},
			false,
		},
		{
			"only init container",
			map[string]string{
				AnnotationVaultRole:            "role",
				AnnotationAgentCacheEnable:     "true",
				AnnotationAgentPrePopulateOnly: "true",
			},
			false,
		},
		{
			"only sidecar container",
			map[string]string{
				AnnotationVaultRole:        "role",
				AnnotationAgentCacheEnable: "true",
				AnnotationAgentPrePopulate: "false",
			},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pod := testPod(tt.annotations)
			agentConfig := AgentConfig{
				Image:              "foobar-image",
				Address:            "http://foobar:1234",
				AuthType:           DefaultVaultAuthType,
				AuthPath:           "test",
				Namespace:          "test",
				RevokeOnShutdown:   true,
				UserID:             "1000",
				GroupID:            "100",
				SameID:             DefaultAgentRunAsSameUser,
				SetSecurityContext: DefaultAgentSetSecurityContext,
				DefaultTemplate:    "map",
				ResourceRequestCPU: DefaultResourceRequestCPU,
				ResourceRequestMem: DefaultResourceRequestMem,
				ResourceLimitCPU:   DefaultResourceLimitCPU,
				ResourceLimitMem:   DefaultResourceLimitMem,
				ExitOnRetryFailure: DefaultTemplateConfigExitOnRetryFailure,
			}

			err := Init(pod, agentConfig)
			require.NoError(t, err)

			agent, err := New(pod)
			require.NoError(t, err)
			err = agent.Validate()
			require.NoError(t, err)

			init, err := agent.ContainerInitSidecar()
			require.NoError(t, err)

			sidecar, err := agent.ContainerSidecar()
			require.NoError(t, err)

			patch, err := agent.Patch()
			require.NoError(t, err)
			var patches jsonpatch.Patch
			require.NoError(t, json.Unmarshal(patch, &patches))

			if tt.expectCacheVolAndMount {
				assert.Subset(t, init.VolumeMounts, cacheMount)
				assert.Subset(t, sidecar.VolumeMounts, cacheMount)
				assert.Subset(t, patches, cacheVolumePatch)
			} else {
				assert.NotSubset(t, init.VolumeMounts, cacheMount)
				assert.NotSubset(t, sidecar.VolumeMounts, cacheMount)
				assert.NotSubset(t, patches, cacheVolumePatch)
			}
		})
	}
}

func TestAgentJsonPatch(t *testing.T) {
	baseContainer := corev1.Container{
		Name:    "vault-agent",
		Image:   "foobar-image",
		Command: []string{"/bin/sh", "-ec"},
		Args:    []string{`echo ${VAULT_CONFIG?} | base64 -d > /home/vault/config.json && vault agent -config=/home/vault/config.json`},
		Env: append(
			baseContainerEnvVars,
			corev1.EnvVar{Name: "VAULT_LOG_LEVEL", Value: "info"},
			corev1.EnvVar{Name: "VAULT_LOG_FORMAT", Value: "standard"},
			corev1.EnvVar{Name: "VAULT_CONFIG", Value: "eyJhdXRvX2F1dGgiOnsibWV0aG9kIjp7InR5cGUiOiJrdWJlcm5ldGVzIiwibW91bnRfcGF0aCI6InRlc3QiLCJjb25maWciOnsicm9sZSI6InJvbGUiLCJ0b2tlbl9wYXRoIjoic2VydmljZWFjY291bnQvc29tZXdoZXJlL3Rva2VuIn19LCJzaW5rIjpbeyJ0eXBlIjoiZmlsZSIsImNvbmZpZyI6eyJwYXRoIjoiL2hvbWUvdmF1bHQvLnZhdWx0LXRva2VuIn19XX0sImV4aXRfYWZ0ZXJfYXV0aCI6ZmFsc2UsInBpZF9maWxlIjoiL2hvbWUvdmF1bHQvLnBpZCIsInZhdWx0Ijp7ImFkZHJlc3MiOiJodHRwOi8vZm9vYmFyOjEyMzQifSwidGVtcGxhdGVfY29uZmlnIjp7ImV4aXRfb25fcmV0cnlfZmFpbHVyZSI6dHJ1ZX19"},
		),
		Resources: v1.ResourceRequirements{
			Limits:   v1.ResourceList{"cpu": resource.MustParse("500m"), "memory": resource.MustParse("128Mi")},
			Requests: v1.ResourceList{"cpu": resource.MustParse("250m"), "memory": resource.MustParse("64Mi")},
		},
		VolumeMounts: []v1.VolumeMount{
			{Name: "foobar", ReadOnly: true, MountPath: "serviceaccount/somewhere"},
			{Name: "home-sidecar", MountPath: "/home/vault"},
			{Name: "vault-secrets", MountPath: "/vault/secrets"},
		},
		Lifecycle: &v1.Lifecycle{
			PreStop: &v1.LifecycleHandler{
				Exec: &v1.ExecAction{
					Command: []string{"/bin/sh", "-c", "/bin/sleep 5 && /bin/vault token revoke -address=http://foobar:1234 -self"},
				},
			},
		},
		SecurityContext: &v1.SecurityContext{
			Capabilities: &v1.Capabilities{
				Drop: []v1.Capability{"ALL"},
			},
			RunAsGroup:               optional[int64](100),
			RunAsUser:                optional[int64](1000),
			RunAsNonRoot:             optional[bool](true),
			ReadOnlyRootFilesystem:   optional[bool](true),
			AllowPrivilegeEscalation: optional[bool](false),
		},
	}

	baseInitContainer := baseContainer
	baseInitContainer.Name = "vault-agent-init"
	baseInitContainer.Env = append(
		baseContainerEnvVars,
		corev1.EnvVar{Name: "VAULT_LOG_LEVEL", Value: "info"},
		corev1.EnvVar{Name: "VAULT_LOG_FORMAT", Value: "standard"},
		corev1.EnvVar{Name: "VAULT_CONFIG", Value: "eyJhdXRvX2F1dGgiOnsibWV0aG9kIjp7InR5cGUiOiJrdWJlcm5ldGVzIiwibW91bnRfcGF0aCI6InRlc3QiLCJjb25maWciOnsicm9sZSI6InJvbGUiLCJ0b2tlbl9wYXRoIjoic2VydmljZWFjY291bnQvc29tZXdoZXJlL3Rva2VuIn19LCJzaW5rIjpbeyJ0eXBlIjoiZmlsZSIsImNvbmZpZyI6eyJwYXRoIjoiL2hvbWUvdmF1bHQvLnZhdWx0LXRva2VuIn19XX0sImV4aXRfYWZ0ZXJfYXV0aCI6dHJ1ZSwicGlkX2ZpbGUiOiIvaG9tZS92YXVsdC8ucGlkIiwidmF1bHQiOnsiYWRkcmVzcyI6Imh0dHA6Ly9mb29iYXI6MTIzNCJ9LCJ0ZW1wbGF0ZV9jb25maWciOnsiZXhpdF9vbl9yZXRyeV9mYWlsdXJlIjp0cnVlfX0="},
	)
	baseInitContainer.VolumeMounts = []v1.VolumeMount{
		{Name: "home-init", MountPath: "/home/vault"},
		{Name: "foobar", ReadOnly: true, MountPath: "serviceaccount/somewhere"},
		{Name: "vault-secrets", MountPath: "/vault/secrets"},
	}
	baseInitContainer.Lifecycle = nil

	differentName := baseContainer
	differentName.Name = "different-name"

	differentNameInit := baseInitContainer
	differentNameInit.Name = "different-name-init"

	tests := []struct {
		name          string
		jsonPatch     string
		jsonInitPatch string
		expectedValue corev1.Container
		init          bool
		expectErr     bool
	}{
		{
			"null patch",
			"null",
			"null",
			baseContainer,
			false,
			false,
		},
		{
			"null patch (init)",
			"null",
			"null",
			baseInitContainer,
			true,
			false,
		},
		{
			"empty patch",
			"",
			"",
			baseContainer,
			false,
			false,
		},
		{
			"empty list",
			"[]",
			"[]",
			baseContainer,
			false,
			false,
		},
		{
			"invalid JSON",
			`abc`,
			`abc`,
			baseContainer,
			false,
			true,
		},
		{
			"invalid operation",
			`[{"op": "invalid"}]`,
			`[{"op": "invalid"}]`,
			baseContainer,
			false,
			true,
		},
		{
			"set different name",
			`[{"op": "replace", "path": "/name", "value": "different-name"}]`,
			"",
			differentName,
			false,
			false,
		},
		{
			"set different name (init)",
			"",
			`[{"op": "replace", "path": "/name", "value": "different-name-init"}]`,
			differentNameInit,
			true,
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pod := testPod(map[string]string{
				AnnotationVaultRole:          "role",
				AnnotationAgentJsonPatch:     tt.jsonPatch,
				AnnotationAgentInitJsonPatch: tt.jsonInitPatch,
			})
			agentConfig := AgentConfig{
				Image:              "foobar-image",
				Address:            "http://foobar:1234",
				AuthType:           DefaultVaultAuthType,
				AuthPath:           "test",
				Namespace:          "test",
				RevokeOnShutdown:   true,
				UserID:             "1000",
				GroupID:            "100",
				SameID:             DefaultAgentRunAsSameUser,
				SetSecurityContext: DefaultAgentSetSecurityContext,
				DefaultTemplate:    "map",
				ResourceRequestCPU: DefaultResourceRequestCPU,
				ResourceRequestMem: DefaultResourceRequestMem,
				ResourceLimitCPU:   DefaultResourceLimitCPU,
				ResourceLimitMem:   DefaultResourceLimitMem,
				ExitOnRetryFailure: DefaultTemplateConfigExitOnRetryFailure,
			}

			err := Init(pod, agentConfig)
			if tt.expectErr && err != nil {
				return
			}
			require.NoError(t, err)

			agent, err := New(pod)
			if tt.expectErr && err != nil {
				return
			}
			require.NoError(t, err)
			err = agent.Validate()
			if tt.expectErr && err != nil {
				return
			}
			require.NoError(t, err)

			var sidecar corev1.Container
			if tt.init {
				sidecar, err = agent.ContainerInitSidecar()
			} else {
				sidecar, err = agent.ContainerSidecar()
			}

			if tt.expectErr && err != nil {
				// ok
			} else if tt.expectErr && err == nil {
				t.Error("Expected an error but got none")
			} else if err != nil {
				t.Error(err)
			} else {
				require.Equal(t, tt.expectedValue, sidecar)
			}
		})
	}
}

func optional[T any](x T) *T {
	return &x
}
