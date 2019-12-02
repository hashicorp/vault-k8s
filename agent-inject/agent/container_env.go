package agent

import (
	corev1 "k8s.io/api/core/v1"
)

// ContainerEnvVars adds the applicable environment vars
// for the Vault Agent sidecar.
func (a *Agent) ContainerEnvVars(init bool) ([]corev1.EnvVar, error) {
	var envs []corev1.EnvVar
	var config []byte
	var err error

	if a.ConfigMapName == "" {
		config, err = a.newConfig(init)
		if err != nil {
			return envs, err
		}

		b64Config := base64Encode(config)
		envs = append(envs, corev1.EnvVar{
			Name:  "VAULT_CONFIG",
			Value: b64Config,
		})
	}

	return envs, nil
}