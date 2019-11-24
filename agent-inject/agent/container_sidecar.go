package agent

import (
	"fmt"
	corev1 "k8s.io/api/core/v1"
)

const (
	DefaultContainerArg = "echo ${VAULT_CONFIG?} | base64 -d > /tmp/config.json && vault agent -config=/tmp/config.json"
)

// ContainerInitSidecar creates a new container to be added
// to the pod being mutated.
func (a *Agent) ContainerSidecar() (corev1.Container, error) {
	runAsUser := int64(100)
	runAsGroup := int64(1000)
	runAsNonRoot := true

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

	init := false
	envs, err := a.ContainerEnvVars(init)
	if err != nil {
		return corev1.Container{}, err
	}

	return corev1.Container{
		Name:  "vault-agent",
		Image: a.ImageName,
		Env:   envs,
		SecurityContext: &corev1.SecurityContext{
			RunAsUser:    &runAsUser,
			RunAsGroup:   &runAsGroup,
			RunAsNonRoot: &runAsNonRoot,
		},
		VolumeMounts: volumeMounts,
		Command:      []string{"/bin/sh", "-ec"},
		Args:         []string{arg},
	}, nil
}
