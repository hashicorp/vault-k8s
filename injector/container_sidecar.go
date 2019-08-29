package injector

import (
	corev1 "k8s.io/api/core/v1"
)

func (h *Handler) containerSidecar(pod *corev1.Pod) (corev1.Container, error) {
	return corev1.Container{
		Name:  "sidecar-nginx",
		Image: h.ImageAgent,
		Env: []corev1.EnvVar{
			{
				Name: "HOST_IP",
				ValueFrom: &corev1.EnvVarSource{
					FieldRef: &corev1.ObjectFieldSelector{FieldPath: "status.hostIP"},
				},
			},
		},
		Ports: []corev1.ContainerPort{
			{
				ContainerPort: 80,
			},
		},
		VolumeMounts: []corev1.VolumeMount{
			{
				Name:      "nginx-conf",
				MountPath: "/etc/nginx",
			},
		},
	}, nil
}
