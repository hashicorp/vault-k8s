package agent

import (
	"encoding/base64"
	"log"

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

	if a.ConfigMapName == "" {
		config, err := a.newConfig(init)
		if err != nil {
			return envs, err
		}

		b64Config := base64.StdEncoding.EncodeToString(config)
		envs = append(envs, corev1.EnvVar{
			Name:  "VAULT_CONFIG",
			Value: b64Config,
		})

		// Add IRSA AWS Env variables for vault containers
		if a.Pod != nil {
			envMap := a.getEnvsFromContainer(a.Pod)
			if len(envMap) == 0 || len(envMap) >= 2 {
				for k, v := range envMap {
					envs = append(envs, corev1.EnvVar{
						Name:  k,
						Value: v,
					})
				}
			} else {
				log.Println("WARN: Could not find 'AWS ROLE/ AWS_WEB_IDENTITY_TOKEN_FILE' env variables")
			}
		}
	}

	return envs, nil
}
