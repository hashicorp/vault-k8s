package agent

import (
	corev1 "k8s.io/api/core/v1"
)

// ContainerEnvVars adds the applicable environment vars
// for the Vault Agent sidecar.
func (a *Agent) ContainerEnvVars(init bool) ([]corev1.EnvVar, error) {
	var envs []corev1.EnvVar

	if a.Vault.ClientTimeout != "" {
		envs = append(envs, corev1.EnvVar{
			Name:  "VAULT_CLIENT_TIMEOUT",
			Value: a.Vault.ClientTimeout,
		})
	}

	if a.Vault.ClientMaxRetries != "" {
		envs = append(envs, corev1.EnvVar{
			Name:  "VAULT_MAX_RETRIES",
			Value: a.Vault.ClientMaxRetries,
		})
	}

	if a.Vault.LogLevel != "" {
		envs = append(envs, corev1.EnvVar{
			Name:  "VAULT_LOG_LEVEL",
			Value: a.Vault.LogLevel,
		})
	}

	return envs, nil
}
