package injector

import (
	//"fmt"
	//"strconv"
	//"strings"

	"fmt"
	corev1 "k8s.io/api/core/v1"
	"strings"
)

func (h *Handler) getSecretAnnotations(pod *corev1.Pod) []corev1.EnvVar {
	var envs []corev1.EnvVar
	for name, value := range pod.Annotations {
		if strings.Contains(name, "vault-agent-secret") {
			annotation := strings.Replace(
				string.ToUpper(strings.Trim(name, "vault-agent-secret")),
				"-", "_", -1,
			)

			envs = append(envs, corev1.EnvVar{
				Name:  fmt.Sprintf("VAULT_SECRET_%s", annotation),
				Value: value,
			})
		}
	}
	return envs
}

func (h *Handler) containerEnvVars(pod *corev1.Pod) []corev1.EnvVar {
	if len(pod.Annotations) < 1 {
		return []corev1.EnvVar{}
	}

	result := h.getSecretAnnotations(pod)
	result = append(result, corev1.EnvVar{
		Name:  "VAULT_ADDR",
		Value: "http://vault:8200",
	})

	return result
}
