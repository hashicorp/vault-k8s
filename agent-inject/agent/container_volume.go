package agent

import (
	corev1 "k8s.io/api/core/v1"
)

const (
	configVolumeName    = "vault-config"
	configVolumePath    = "/vault/configs"
	secretVolumeName    = "vault-secrets"
	secretVolumePath    = "/vault"
	tlsSecretVolumeName = "vault-tls-secrets"
	tlsSecretVolumePath = "/vault/tls"
)

// ContainerVolume returns the volume data to add to the pod. This volume
// is used for shared data between containers.
func (a *Agent) ContainerVolume() corev1.Volume {
	return corev1.Volume{
		Name: secretVolumeName,
		VolumeSource: corev1.VolumeSource{
			EmptyDir: &corev1.EmptyDirVolumeSource{
				Medium: "Memory",
			},
		},
	}
}

// ContainerConfigMapVolume returns a volume to mount a config map
// if the user supplied any.
func (a *Agent) ContainerConfigMapVolume() corev1.Volume {
	return corev1.Volume{
		Name: configVolumeName,
		VolumeSource: corev1.VolumeSource{
			ConfigMap: &corev1.ConfigMapVolumeSource{
				LocalObjectReference: corev1.LocalObjectReference{
					Name: a.ConfigMapName,
				},
			},
		},
	}
}

// ContainerTLSSecretVolume returns a volume to mount TLS secrets
// if the user supplied any.
func (a *Agent) ContainerTLSSecretVolume() corev1.Volume {
	return corev1.Volume{
		Name: tlsSecretVolumeName,
		VolumeSource: corev1.VolumeSource{
			Secret: &corev1.SecretVolumeSource{
				SecretName: a.Vault.TLSSecret,
			},
		},
	}
}

// ContainerVolumeMount mounts the shared memory volume where secrets
// will be rendered.
func (a *Agent) ContainerVolumeMount() corev1.VolumeMount {
	return corev1.VolumeMount{
		Name:      secretVolumeName,
		MountPath: secretVolumePath,
		ReadOnly:  false,
		
	}
}
