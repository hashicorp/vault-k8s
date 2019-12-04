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
		{Agent{}, []string{"VAULT_CONFIG"}},
		{Agent{ConfigMapName: "foobar"}, []string{}},
		{Agent{Vault: Vault{ClientMaxRetries: "0"}}, []string{"VAULT_CONFIG", "VAULT_MAX_RETRIES"}},
		{Agent{Vault: Vault{ClientTimeout: "5s"}}, []string{"VAULT_CONFIG", "VAULT_CLIENT_TIMEOUT"}},
		{Agent{Vault: Vault{ClientMaxRetries: "0", ClientTimeout: "5s"}}, []string{"VAULT_CONFIG", "VAULT_MAX_RETRIES", "VAULT_CLIENT_TIMEOUT"}},
		{Agent{ConfigMapName: "foobar", Vault: Vault{ClientMaxRetries: "0", ClientTimeout: "5s"}}, []string{"VAULT_MAX_RETRIES", "VAULT_CLIENT_TIMEOUT"}},
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
