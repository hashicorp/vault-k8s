// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package agent

import (
	"fmt"

	"github.com/hashicorp/vault/sdk/helper/strutil"
	corev1 "k8s.io/api/core/v1"
)

const (
	tokenVolumeNameInit    = "home-init"
	tokenVolumeNameSidecar = "home-sidecar"
	tokenVolumePath        = "/home/vault"
	configVolumeName       = "vault-config"
	configVolumePath       = "/vault/configs"
	secretVolumeName       = "vault-secrets"
	tlsSecretVolumeName    = "vault-tls-secrets"
	tlsSecretVolumePath    = "/vault/tls"
	secretVolumePath       = "/vault/secrets"
	extraSecretVolumeName  = "extra-secrets"
	extraSecretVolumePath  = "/vault/custom"
	cacheVolumeName        = "vault-agent-cache"
	cacheVolumePath        = "/vault/agent-cache"
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
		corev1.Volume{
			Name: secretVolumeName,
			VolumeSource: corev1.VolumeSource{
				EmptyDir: &corev1.EmptyDirVolumeSource{
					Medium: "Memory",
				},
			},
		},
	}
	for index, _ := range a.getUniqueMountPaths() {
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
func (a *Agent) ContainerTokenVolume() []corev1.Volume {
	var vols []corev1.Volume
	if a.PrePopulate {
		initVol := corev1.Volume{
			Name: tokenVolumeNameInit,
			VolumeSource: corev1.VolumeSource{
				EmptyDir: &corev1.EmptyDirVolumeSource{
					Medium: "Memory",
				},
			},
		}
		vols = append(vols, initVol)
	}
	if !a.PrePopulateOnly {
		sidecarVol := corev1.Volume{
			Name: tokenVolumeNameSidecar,
			VolumeSource: corev1.VolumeSource{
				EmptyDir: &corev1.EmptyDirVolumeSource{
					Medium: "Memory",
				},
			},
		}
		vols = append(vols, sidecarVol)
	}

	if a.ServiceAccountTokenVolume.Audience != "" {
		v := a.createProjectedVolumes()
		vols = append(vols, v)
	}

	return vols
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

// ContainerExtraSecretVolume returns a volume to mount a Kube secret
// if the user supplied one.
func (a *Agent) ContainerExtraSecretVolume() corev1.Volume {
	return corev1.Volume{
		Name: extraSecretVolumeName,
		VolumeSource: corev1.VolumeSource{
			Secret: &corev1.SecretVolumeSource{
				SecretName: a.ExtraSecret,
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
		corev1.VolumeMount{
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

func (a *Agent) cacheVolume() corev1.Volume {
	return corev1.Volume{
		Name: cacheVolumeName,
		VolumeSource: corev1.VolumeSource{
			EmptyDir: &corev1.EmptyDirVolumeSource{
				Medium: "Memory",
			},
		},
	}
}

func (a *Agent) cacheVolumeMount() corev1.VolumeMount {
	return corev1.VolumeMount{
		Name:      cacheVolumeName,
		MountPath: cacheVolumePath,
		ReadOnly:  false,
	}
}
