package agent

import (
	"encoding/base64"

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

	if a.Vault.LogFormat != "" {
		envs = append(envs, corev1.EnvVar{
			Name:  "VAULT_LOG_FORMAT",
			Value: a.Vault.LogFormat,
		})
	}

	if a.Vault.ProxyAddress != "" {
		envs = append(envs, corev1.EnvVar{
			Name:  "HTTPS_PROXY",
			Value: a.Vault.ProxyAddress,
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
	}

	// Add IRSA AWS Env variables for vault containers
	if a.Vault.AuthType == "aws" {
		envMap := a.getAwsEnvsFromContainer(a.Pod)
		for k, v := range envMap {
			envs = append(envs, corev1.EnvVar{
				Name:  k,
				Value: v,
			})
		}
		if a.Vault.AuthConfig["region"] != nil {
			if r, ok := a.Vault.AuthConfig["region"].(string); ok {
				envs = append(envs, corev1.EnvVar{
					Name:  "AWS_REGION",
					Value: r,
				})
			}
		}
	}

	return envs, nil
}
