package inject

import (
	corev1 "k8s.io/api/core/v1"
)

func (h *Handler) containerEnvVars(pod *corev1.Pod) []corev1.EnvVar {
	var result []corev1.EnvVar
	return result
}
