package agent

import (
	"fmt"

	"github.com/hashicorp/vault/sdk/helper/strutil"
	corev1 "k8s.io/api/core/v1"
)

const (
	tokenVolumeName     = "home"
	tokenVolumePath     = "/home/vault"
	configVolumeName    = "vault-config"
	configVolumePath    = "/vault/configs"
	secretVolumeName    = "vault-secrets"
	tlsSecretVolumeName = "vault-tls-secrets"
	tlsSecretVolumePath = "/vault/tls"
	secretVolumePath    = "/vault/secrets"
)

func (a *Agent) getUniqueMountPaths() []string {
	var mountPaths []string

	for _, secret := range a.Secrets {
		if !strutil.StrListContains(mountPaths, secret.MountPath) && secret.MountPath != a.Annotations[AnnotationVaultSecretVolumePath] {
			mountPaths = append(mountPaths, secret.MountPath)
		}
	}
	return mountPaths
}

// ContainerVolume returns the volume data to add to the pod. This volumes
// are used for shared data between containers.
func (a *Agent) ContainerVolumes() []corev1.Volume {
	containerVolumes := []corev1.Volume{
		{
			Name: secretVolumeName,
			VolumeSource: corev1.VolumeSource{
				EmptyDir: &corev1.EmptyDirVolumeSource{
					Medium: "Memory",
				},
			},
		},
	}
	for index := range a.getUniqueMountPaths() {
		containerVolumes = append(
			containerVolumes,
			corev1.Volume{
				Name: fmt.Sprintf("%s-custom-%d", secretVolumeName, index),
				VolumeSource: corev1.VolumeSource{
					EmptyDir: &corev1.EmptyDirVolumeSource{
						Medium: "Memory",
					},
				},
			},
		)
	}
	return containerVolumes
}

// ContainerTokenVolume returns a volume to mount the
// home directory where the token sink will write to.
func (a *Agent) ContainerTokenVolume() corev1.Volume {
	return corev1.Volume{
		Name: tokenVolumeName,
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

// ContainerVolumeMounts mounts the shared memory volume where secrets
// will be rendered.
func (a *Agent) ContainerVolumeMounts() []corev1.VolumeMount {
	volumeMounts := []corev1.VolumeMount{
		{
			Name:      secretVolumeName,
			MountPath: a.Annotations[AnnotationVaultSecretVolumePath],
			ReadOnly:  false,
		},
	}
	for index, mountPath := range a.getUniqueMountPaths() {
		volumeMounts = append(
			volumeMounts,
			corev1.VolumeMount{
				Name:      fmt.Sprintf("%s-custom-%d", secretVolumeName, index),
				MountPath: mountPath,
				ReadOnly:  false,
			},
		)
	}
	return volumeMounts
}
