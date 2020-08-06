package agent

import (
	"testing"

	"github.com/hashicorp/vault/sdk/helper/strutil"
)

func TestContainerEnvs(t *testing.T) {

	tests := []struct {
		agent        Agent
		expectedEnvs []string
	}{
		{Agent{}, []string{"VAULT_CONFIG", "NAMESPACE"}},
		{Agent{ConfigMapName: "foobar"}, []string{"NAMESPACE"}},
		{Agent{Vault: Vault{ClientMaxRetries: "0"}}, []string{"VAULT_CONFIG", "VAULT_MAX_RETRIES", "NAMESPACE"}},
		{Agent{Vault: Vault{ClientTimeout: "5s"}}, []string{"VAULT_CONFIG", "VAULT_CLIENT_TIMEOUT", "NAMESPACE"}},
		{Agent{Vault: Vault{ClientMaxRetries: "0", ClientTimeout: "5s"}}, []string{"VAULT_CONFIG", "VAULT_MAX_RETRIES", "VAULT_CLIENT_TIMEOUT", "NAMESPACE"}},
		{Agent{ConfigMapName: "foobar", Vault: Vault{ClientMaxRetries: "0", ClientTimeout: "5s", LogLevel: "info"}}, []string{"VAULT_MAX_RETRIES", "VAULT_CLIENT_TIMEOUT", "VAULT_LOG_LEVEL", "NAMESPACE"}},
	}

	for _, tt := range tests {
		envs, err := tt.agent.ContainerEnvVars(true)
		if err != nil {
			t.Errorf("got error, shouldn't have: %s", err)
		}

		if len(envs) != len(tt.expectedEnvs) {
			t.Errorf("number of envs mismatch, wanted %d, got %d", len(tt.expectedEnvs), len(envs))
		}

		for _, env := range envs {
			if !strutil.StrListContains(tt.expectedEnvs, env.Name) {
				t.Errorf("unexpected env found %s", env.Name)
			}
		}
	}
}
