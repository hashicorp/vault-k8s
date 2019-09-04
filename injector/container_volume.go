package injector

import (
	corev1 "k8s.io/api/core/v1"
)

// volumeName is the name of the volume that is created to store the
// Consul Connect injection data.
const volumeName = "vault-secrets"

// containerVolume returns the volume data to add to the pod. This volume
// is used for shared data between containers.
func (h *Handler) containerVolume() corev1.Volume {
	return corev1.Volume{
		Name: volumeName,
		VolumeSource: corev1.VolumeSource{
			EmptyDir: &corev1.EmptyDirVolumeSource{
				Medium: "Memory",
			},
		},
	}
}
