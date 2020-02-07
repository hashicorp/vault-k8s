package agent

import (
	"fmt"
	"testing"

	"github.com/mattbaird/jsonpatch"
)

func TestContainerSidecar(t *testing.T) {
	annotations := map[string]string{
		AnnotationVaultRole: "foobar",
	}

	pod := testPod(annotations)
	var patches []*jsonpatch.JsonPatchOperation

	err := Init(pod, "foobar-image", "http://foobar:1234", "test", "test")
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

	if len(container.Env) != 1 {
		t.Errorf("wrong number of env vars, got %d, should have been %d", len(container.Env), 1)
	}

	if container.Env[0].Name != "VAULT_CONFIG" {
		t.Errorf("env name wrong, should have been %s, got %s", "VAULT_CONFIG", container.Env[0].Name)
	}

	if container.Env[0].Value == "" {
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

	err := Init(pod, "foobar-image", "http://foobar:1234", "test", "test")
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

	if len(container.Env) != 0 {
		t.Errorf("wrong number of env vars, got %d, should have been %d", len(container.Env), 0)
	}

	arg := fmt.Sprintf("vault agent -config=%s/config.hcl", configVolumePath)
	if container.Args[0] != arg {
		t.Errorf("arg value wrong, should have been %s, got %s", arg, container.Args[0])
	}

	if len(container.VolumeMounts) != 3 {
		t.Errorf("volume mounts wrong, should have been %d, got %d", 3, len(container.VolumeMounts))
	}
}

func TestContainerSidecarCustomResources(t *testing.T) {
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
			expectedRequestCPU: "0",
			expectedRequestMem: "0",
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
			expectedLimitCPU:   "0",
			expectedLimitMem:   "0",
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
			expectedLimitMem:   "0",
			expectedRequestCPU: "0",
			expectedRequestMem: "0",
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
			expectedLimitCPU:   "0",
			expectedLimitMem:   "128m",
			expectedRequestCPU: "0",
			expectedRequestMem: "0",
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
			expectedLimitCPU:   "0",
			expectedLimitMem:   "0",
			expectedRequestCPU: "500Mi",
			expectedRequestMem: "0",
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
			expectedLimitCPU:   "0",
			expectedLimitMem:   "0",
			expectedRequestCPU: "0",
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
				if resources.Limits.Cpu().String() != tt.expectedLimitCPU {
					t.Errorf("expected cpu limit mismatch: wanted %s, got %s", tt.expectedLimitCPU, resources.Limits.Cpu().String())
				}

				if resources.Limits.Memory().String() != tt.expectedLimitMem {
					t.Errorf("expected mem limit mismatch: wanted %s, got %s", tt.expectedLimitMem, resources.Limits.Memory().String())
				}

				if resources.Requests.Cpu().String() != tt.expectedRequestCPU {
					t.Errorf("%s expected cpu request mismatch: wanted %s, got %s", tt.name, tt.expectedLimitCPU, resources.Requests.Cpu().String())
				}

				if resources.Requests.Memory().String() != tt.expectedRequestMem {
					t.Errorf("%s expected mem request mismatch: wanted %s, got %s", tt.name, tt.expectedLimitMem, resources.Requests.Memory().String())
				}
			}
		})
	}
}
