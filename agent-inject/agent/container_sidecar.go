package agent

import (
	"fmt"

	"github.com/hashicorp/vault/sdk/helper/pointerutil"
	corev1 "k8s.io/api/core/v1"
)

const (
	DefaultContainerArg = "echo ${VAULT_CONFIG?} | base64 -d > /tmp/config.json && vault agent -config=/tmp/config.json"
)

// ContainerSidecar creates a new container to be added
// to the pod being mutated.
func (a *Agent) ContainerSidecar() (corev1.Container, error) {
	volumeMounts := []corev1.VolumeMount{
		{
			Name:      secretVolumeName,
			MountPath: secretVolumePath,
			ReadOnly:  false,
		},
		{
			Name:      a.ServiceAccountName,
			MountPath: a.ServiceAccountPath,
			ReadOnly:  true,
		},
	}

	arg := DefaultContainerArg

	if a.ConfigMapName != "" {
		volumeMounts = append(volumeMounts, corev1.VolumeMount{
			Name:      configVolumeName,
			MountPath: configVolumePath,
			ReadOnly:  true,
		})
		arg = fmt.Sprintf("vault agent -config=%s/config.hcl", configVolumePath)
	}

	if a.Vault.TLSSecret != "" {
		volumeMounts = append(volumeMounts, corev1.VolumeMount{
			Name:      tlsSecretVolumeName,
			MountPath: tlsSecretVolumePath,
			ReadOnly:  true,
		})
	}

	envs, err := a.ContainerEnvVars(false)
	if err != nil {
		return corev1.Container{}, err
	}

	return corev1.Container{
		Name:  "vault-agent",
		Image: a.ImageName,
		Env:   envs,
		SecurityContext: &corev1.SecurityContext{
			RunAsUser:    pointerutil.Int64Ptr(100),
			RunAsGroup:   pointerutil.Int64Ptr(1000),
			RunAsNonRoot: pointerutil.BoolPtr(true),
		},
		VolumeMounts: volumeMounts,
		Command:      []string{"/bin/sh", "-ec"},
		Args:         []string{arg},
	}, nil
}
