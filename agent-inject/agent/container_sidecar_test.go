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

	err := Init(pod, "foobar-image", "http://foobar:1234", "test")
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
		"vault.hashicorp.com/agent-inject-secret-foo":   "db/creds/foo",
		"vault.hashicorp.com/agent-inject-template-foo": "template foo",
		"vault.hashicorp.com/agent-inject-secret-bar":   "db/creds/bar",
	}

	pod := testPod(annotations)
	var patches []*jsonpatch.JsonPatchOperation

	err := Init(pod, "foobar-image", "http://foobar:1234", "test")
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
		err                bool
	}{
		{"test valid M", Agent{LimitsCPU: "500M", LimitsMem: "128M", RequestsCPU: "250M", RequestsMem: "64M"}, "500M", "128M", "250M", "64M", false},
		{"test valid G", Agent{LimitsCPU: "500G", LimitsMem: "128G", RequestsCPU: "250G", RequestsMem: "64G"}, "500G", "128G", "250G", "64G", false},
		{"test valid Mi", Agent{LimitsCPU: "500Mi", LimitsMem: "128Mi", RequestsCPU: "250Mi", RequestsMem: "64Mi"}, "500Mi", "128Mi", "250Mi", "64Mi", false},
		{"test valid Gi", Agent{LimitsCPU: "500Gi", LimitsMem: "128Gi", RequestsCPU: "250Gi", RequestsMem: "64Gi"}, "500Gi", "128Gi", "250Gi", "64Gi", false},
		{"test valid none", Agent{LimitsCPU: "", LimitsMem: "", RequestsCPU: "", RequestsMem: ""}, "0", "0", "0", "0", false},
		{"test valid no requests", Agent{LimitsCPU: "500Mi", LimitsMem: "128m", RequestsCPU: "", RequestsMem: ""}, "500Mi", "128m", "0", "0", false},
		{"test valid no limits", Agent{LimitsCPU: "", LimitsMem: "", RequestsCPU: "250Mi", RequestsMem: "64m"}, "0", "0", "250Mi", "64m", false},
		{"test valid just cpu limit", Agent{LimitsCPU: "500Mi", LimitsMem: "", RequestsCPU: "", RequestsMem: ""}, "500Mi", "0", "0", "0", false},
		{"test valid just mem limit", Agent{LimitsCPU: "", LimitsMem: "128m", RequestsCPU: "", RequestsMem: ""}, "0", "128m", "0", "0", false},
		{"test valid just cpu request", Agent{LimitsCPU: "", LimitsMem: "", RequestsCPU: "500Mi", RequestsMem: ""}, "0", "0", "500Mi", "0", false},
		{"test valid just mem request", Agent{LimitsCPU: "", LimitsMem: "", RequestsCPU: "", RequestsMem: "128m"}, "0", "0", "0", "128m", false},
		{"test invalid cpu Mi notation", Agent{LimitsCPU: "500mi", LimitsMem: "128m", RequestsCPU: "250mi", RequestsMem: "64m"}, "500mi", "128m", "250mi", "64m", true},
		{"test invalid cpu Gi notation", Agent{LimitsCPU: "500gi", LimitsMem: "128m", RequestsCPU: "250gi", RequestsMem: "64m"}, "500gi", "128m", "250gi", "64m", true},
		{"test invalid mem m notation", Agent{LimitsCPU: "500Mi", LimitsMem: "128mb", RequestsCPU: "250Mi", RequestsMem: "64mb"}, "500Mi", "128m", "250Mi", "64m", true},
		{"test invalid mem g notation", Agent{LimitsCPU: "500Mi", LimitsMem: "128g", RequestsCPU: "250Mi", RequestsMem: "64g"}, "500Mi", "128m", "250Mi", "64m", true},
		{"test invalid mem gi notation", Agent{LimitsCPU: "500Mi", LimitsMem: "128gi", RequestsCPU: "250Mi", RequestsMem: "64gi"}, "500Mi", "128m", "250Mi", "64m", true},
	}

	for _, tt := range tests {
		resources, err := tt.agent.parseResources()
		if !tt.err && err != nil {
			t.Errorf("got error, shouldn't have: %s", err)
		}

		if tt.err && err == nil {
			t.Errorf("got no error, should have: %s", tt.name)
		}

		if !tt.err {
			if resources.Limits.Cpu().String() != tt.expectedLimitCPU {
				huh := resources.Limits.Cpu().String() != tt.expectedLimitCPU
				t.Errorf("%t", huh)
				t.Errorf("expected cpu limit mistmatch: wanted %s, got %s", tt.expectedLimitCPU, resources.Limits.Cpu().String())
			}

			if resources.Limits.Memory().String() != tt.expectedLimitMem {
				t.Errorf("expected mem limit mistmatch: wanted %s, got %s", tt.expectedLimitMem, resources.Limits.Memory().String())
			}

			if resources.Requests.Cpu().String() != tt.expectedRequestCPU {
				t.Errorf("%s expected cpu request mistmatch: wanted %s, got %s", tt.name, tt.expectedLimitCPU, resources.Requests.Cpu().String())
			}

			if resources.Requests.Memory().String() != tt.expectedRequestMem {
				t.Errorf("%s expected mem request mistmatch: wanted %s, got %s", tt.name, tt.expectedLimitMem, resources.Requests.Memory().String())
			}
		}
	}
}
