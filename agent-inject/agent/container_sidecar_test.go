package agent

import (
	"fmt"
	"strconv"
	"testing"

	"github.com/hashicorp/vault/sdk/helper/pointerutil"
	"github.com/mattbaird/jsonpatch"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
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
	var patches []*jsonpatch.JsonPatchOperation

	err := Init(pod, AgentConfig{"foobar-image", "http://foobar:1234", "test", "test", true, "1000", "100", DefaultAgentRunAsSameUser, DefaultAgentSetSecurityContext})
	if err != nil {
		t.Errorf("got error, shouldn't have: %s", err)
	}

	agent, err := New(pod, patches)
	if err := agent.Validate(); err != nil {
		t.Errorf("agent validation failed, it shouldn't have: %s", err)
	}

	container, err := agent.ContainerSidecar()

	// One token volume mount, one config volume mount, two secrets volume mounts, and one mount copied from main container
	require.Equal(t, 6, len(container.VolumeMounts))

	require.Equal(
		t,
		[]corev1.VolumeMount{
			corev1.VolumeMount{
				Name:      agent.ServiceAccountName,
				MountPath: agent.ServiceAccountPath,
				ReadOnly:  true,
			},
			corev1.VolumeMount{
				Name:      tokenVolumeNameSidecar,
				MountPath: tokenVolumePath,
				ReadOnly:  false,
			},
			corev1.VolumeMount{
				Name:      secretVolumeName,
				MountPath: agent.Annotations[AnnotationVaultSecretVolumePath],
				ReadOnly:  false,
			},
			corev1.VolumeMount{
				Name:      fmt.Sprintf("%s-custom-%d", secretVolumeName, 0),
				MountPath: "/etc/container_environment",
				ReadOnly:  false,
			},
			corev1.VolumeMount{
				Name:      extraSecretVolumeName,
				MountPath: extraSecretVolumePath,
				ReadOnly:  true,
			},
			corev1.VolumeMount{
				Name:      "tobecopied",
				MountPath: "/etc/somewhereelse",
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
	var patches []*jsonpatch.JsonPatchOperation

	err := Init(pod, AgentConfig{"foobar-image", "http://foobar:1234", "test", "test", false, "1000", "100", DefaultAgentRunAsSameUser, DefaultAgentSetSecurityContext})
	if err != nil {
		t.Errorf("got error, shouldn't have: %s", err)
	}

	agent, err := New(pod, patches)
	if err := agent.Validate(); err != nil {
		t.Errorf("agent validation failed, it shouldn't have: %s", err)
	}

	container, err := agent.ContainerSidecar()
	if err != nil {
		t.Errorf("creating container sidecar failed, it shouldn't have: %s", err)
	}

	expectedEnvs := 2
	if len(container.Env) != expectedEnvs {
		t.Errorf("wrong number of env vars, got %d, should have been %d", len(container.Env), expectedEnvs)
	}

	if container.Env[0].Name != "VAULT_LOG_LEVEL" {
		t.Errorf("env name wrong, should have been %s, got %s", "VAULT_LOG_LEVEL", container.Env[0].Name)
	}

	if container.Env[0].Value == "" {
		t.Error("env value empty, it shouldn't be")
	}

	if container.Env[1].Name != "VAULT_CONFIG" {
		t.Errorf("env name wrong, should have been %s, got %s", "VAULT_CONFIG", container.Env[1].Name)
	}

	if container.Env[1].Value == "" {
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

	if container.Resources.Requests.Cpu().String() != DefaultResourceRequestCPU {
		t.Errorf("resource cpu requests value wrong, should have been %s, got %s", DefaultResourceRequestCPU, container.Resources.Requests.Cpu().String())
	}

	if container.Resources.Requests.Memory().String() != DefaultResourceRequestMem {
		t.Errorf("resource memory requests value wrong, should have been %s, got %s", DefaultResourceLimitMem, container.Resources.Requests.Memory().String())
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
			var patches []*jsonpatch.JsonPatchOperation

			err := Init(pod, AgentConfig{"foobar-image", "http://foobar:1234", "test", "test", tt.revokeFlag, "1000", "100", DefaultAgentRunAsSameUser, DefaultAgentSetSecurityContext})
			if err != nil {
				t.Errorf("got error, shouldn't have: %s", err)
			}

			agent, err := New(pod, patches)
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
	var patches []*jsonpatch.JsonPatchOperation

	err := Init(pod, AgentConfig{"foobar-image", "http://foobar:1234", "test", "test", true, "1000", "100", DefaultAgentRunAsSameUser, DefaultAgentSetSecurityContext})
	if err != nil {
		t.Errorf("got error, shouldn't have: %s", err)
	}

	agent, err := New(pod, patches)
	if err := agent.Validate(); err != nil {
		t.Errorf("agent validation failed, it shouldn't have: %s", err)
	}

	container, err := agent.ContainerSidecar()
	if err != nil {
		t.Errorf("creating container sidecar failed, it shouldn't have: %s", err)
	}

	expectedEnvs := 1
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
		expectedRequestCPU string
		expectedRequestMem string
		expectedErr        bool
	}{
		{
			name: "valid M",
			agent: Agent{
				LimitsCPU:   "500M",
				LimitsMem:   "128M",
				RequestsCPU: "250M",
				RequestsMem: "64M",
			},
			expectedLimitCPU:   "500M",
			expectedLimitMem:   "128M",
			expectedRequestCPU: "250M",
			expectedRequestMem: "64M",
			expectedErr:        false,
		},
		{
			name: "valid G",
			agent: Agent{
				LimitsCPU:   "500G",
				LimitsMem:   "128G",
				RequestsCPU: "250G",
				RequestsMem: "64G",
			},
			expectedLimitCPU:   "500G",
			expectedLimitMem:   "128G",
			expectedRequestCPU: "250G",
			expectedRequestMem: "64G",
			expectedErr:        false,
		},
		{
			name: "valid Mi",
			agent: Agent{
				LimitsCPU:   "500Mi",
				LimitsMem:   "128Mi",
				RequestsCPU: "250Mi",
				RequestsMem: "64Mi",
			},
			expectedLimitCPU:   "500Mi",
			expectedLimitMem:   "128Mi",
			expectedRequestCPU: "250Mi",
			expectedRequestMem: "64Mi",
			expectedErr:        false,
		},
		{
			name: "valid Gi",
			agent: Agent{
				LimitsCPU:   "500Gi",
				LimitsMem:   "128Gi",
				RequestsCPU: "250Gi",
				RequestsMem: "64Gi",
			},
			expectedLimitCPU:   "500Gi",
			expectedLimitMem:   "128Gi",
			expectedRequestCPU: "250Gi",
			expectedRequestMem: "64Gi",
			expectedErr:        false,
		},
		{
			name: "valid none",
			agent: Agent{
				LimitsCPU:   "",
				LimitsMem:   "",
				RequestsCPU: "",
				RequestsMem: "",
			},
			expectedLimitCPU:   absent,
			expectedLimitMem:   absent,
			expectedRequestCPU: absent,
			expectedRequestMem: absent,
			expectedErr:        false,
		},
		{
			name: "valid 0",
			agent: Agent{
				LimitsCPU:   "0",
				LimitsMem:   "0",
				RequestsCPU: "0",
				RequestsMem: "0",
			},
			expectedLimitCPU:   "0",
			expectedLimitMem:   "0",
			expectedRequestCPU: "0",
			expectedRequestMem: "0",
			expectedErr:        false,
		},
		{
			name: "valid no requests",
			agent: Agent{
				LimitsCPU:   "500Mi",
				LimitsMem:   "128m",
				RequestsCPU: "",
				RequestsMem: "",
			},
			expectedLimitCPU:   "500Mi",
			expectedLimitMem:   "128m",
			expectedRequestCPU: absent,
			expectedRequestMem: absent,
			expectedErr:        false,
		},
		{
			name: "valid no limits",
			agent: Agent{
				LimitsCPU:   "",
				LimitsMem:   "",
				RequestsCPU: "250Mi",
				RequestsMem: "64m",
			},
			expectedLimitCPU:   absent,
			expectedLimitMem:   absent,
			expectedRequestCPU: "250Mi",
			expectedRequestMem: "64m",
			expectedErr:        false,
		},
		{
			name: "valid just cpu limit",
			agent: Agent{
				LimitsCPU:   "500Mi",
				LimitsMem:   "",
				RequestsCPU: "",
				RequestsMem: "",
			},
			expectedLimitCPU:   "500Mi",
			expectedLimitMem:   absent,
			expectedRequestCPU: absent,
			expectedRequestMem: absent,
			expectedErr:        false,
		},
		{
			name: "valid just mem limit",
			agent: Agent{
				LimitsCPU:   "",
				LimitsMem:   "128m",
				RequestsCPU: "",
				RequestsMem: "",
			},
			expectedLimitCPU:   absent,
			expectedLimitMem:   "128m",
			expectedRequestCPU: absent,
			expectedRequestMem: absent,
			expectedErr:        false,
		},
		{
			name: "valid just cpu request",
			agent: Agent{
				LimitsCPU:   "",
				LimitsMem:   "",
				RequestsCPU: "500Mi",
				RequestsMem: "",
			},
			expectedLimitCPU:   absent,
			expectedLimitMem:   absent,
			expectedRequestCPU: "500Mi",
			expectedRequestMem: absent,
			expectedErr:        false,
		},
		{
			name: "valid just mem request",
			agent: Agent{
				LimitsCPU:   "",
				LimitsMem:   "",
				RequestsCPU: "",
				RequestsMem: "128m",
			},
			expectedLimitCPU:   absent,
			expectedLimitMem:   absent,
			expectedRequestCPU: absent,
			expectedRequestMem: "128m",
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
			}

			tt.annotations[AnnotationVaultRole] = "foobar"
			pod := testPod(tt.annotations)
			pod.Spec.Containers[0].SecurityContext = tt.appSCC
			var patches []*jsonpatch.JsonPatchOperation

			err := Init(pod, agentConfig)
			if err != nil {
				t.Errorf("got error, shouldn't have: %s", err)
			}

			agent, err := New(pod, patches)
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
