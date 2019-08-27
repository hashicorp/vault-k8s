package inject

import (
	corev1 "k8s.io/api/core/v1"
)

func (h *Handler) containerSidecar(pod *corev1.Pod) (corev1.Container, error) {

	// Render the command
	return corev1.Container{
		Name:  "vault-agent-sidecar",
		Image: h.ImageAgent,
		Env: []corev1.EnvVar{
			{
				Name: "HOST_IP",
				ValueFrom: &corev1.EnvVarSource{
					FieldRef: &corev1.ObjectFieldSelector{FieldPath: "status.hostIP"},
				},
			},
		},
		VolumeMounts: []corev1.VolumeMount{
			corev1.VolumeMount{
				Name:      volumeName,
				MountPath: "/vault/inject",
			},
		},
		Lifecycle: &corev1.Lifecycle{
			PreStop: &corev1.Handler{
				Exec: &corev1.ExecAction{
					Command: []string{
						"/bin/sh",
						"-ec",
					},
				},
			},
		},
		Command: []string{
			"vault-k8s",
		},
	}, nil
}
