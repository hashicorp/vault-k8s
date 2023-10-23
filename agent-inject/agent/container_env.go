// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package agent

import (
	"encoding/base64"
	"strconv"

	corev1 "k8s.io/api/core/v1"
)

var baseContainerEnvVars []corev1.EnvVar = []corev1.EnvVar{
	corev1.EnvVar{
		Name: "NAMESPACE",
		ValueFrom: &corev1.EnvVarSource{
			FieldRef: &corev1.ObjectFieldSelector{
				FieldPath: "metadata.namespace",
			},
		},
	},
	corev1.EnvVar{
		Name: "HOST_IP",
		ValueFrom: &corev1.EnvVarSource{
			FieldRef: &corev1.ObjectFieldSelector{
				FieldPath: "status.hostIP",
			},
		},
	},
	corev1.EnvVar{
		Name: "POD_IP",
		ValueFrom: &corev1.EnvVarSource{
			FieldRef: &corev1.ObjectFieldSelector{
				FieldPath: "status.podIP",
			},
		},
	},
}

// ContainerEnvVars adds the applicable environment vars
// for the Vault Agent sidecar.
func (a *Agent) ContainerEnvVars(init bool) ([]corev1.EnvVar, error) {
	envs := baseContainerEnvVars

	if a.Vault.GoMaxProcs != "" {
		envs = append(envs, corev1.EnvVar{
			Name:  "GOMAXPROCS",
			Value: a.Vault.GoMaxProcs,
		})
	}

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
	} else {
		// set up environment variables to access Vault since "vault" section may not be present in the config
		if a.Vault.Address != "" {
			envs = append(envs, corev1.EnvVar{
				Name:  "VAULT_ADDR",
				Value: a.Vault.Address,
			})
		}
		if a.Vault.CACert != "" {
			envs = append(envs, corev1.EnvVar{
				Name:  "VAULT_CACERT",
				Value: a.Vault.CACert,
			})
		}
		if a.Vault.CAKey != "" {
			envs = append(envs, corev1.EnvVar{
				Name:  "VAULT_CAPATH",
				Value: a.Vault.CAKey,
			})
		}
		if a.Vault.ClientCert != "" {
			envs = append(envs, corev1.EnvVar{
				Name:  "VAULT_CLIENT_CERT",
				Value: a.Vault.ClientCert,
			})
		}
		if a.Vault.ClientKey != "" {
			envs = append(envs, corev1.EnvVar{
				Name:  "VAULT_CLIENT_KEY",
				Value: a.Vault.ClientKey,
			})
		}
		envs = append(envs, corev1.EnvVar{
			Name:  "VAULT_SKIP_VERIFY",
			Value: strconv.FormatBool(a.Vault.TLSSkipVerify),
		})
		if a.Vault.TLSServerName != "" {
			envs = append(envs, corev1.EnvVar{
				Name:  "VAULT_TLS_SERVER_NAME",
				Value: a.Vault.TLSServerName,
			})
		}
	}

	if a.Vault.CACertBytes != "" {
		envs = append(envs, corev1.EnvVar{
			Name:  "VAULT_CACERT_BYTES",
			Value: decodeIfBase64(a.Vault.CACertBytes),
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

func decodeIfBase64(s string) string {
	decoded, err := base64.StdEncoding.DecodeString(s)
	if err == nil {
		return string(decoded)
	}

	return s
}
