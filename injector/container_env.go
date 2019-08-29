package injector

import (
	//"fmt"
	//"strconv"
	//"strings"

	corev1 "k8s.io/api/core/v1"
)

func (h *Handler) containerEnvVars(pod *corev1.Pod) []corev1.EnvVar {
	//raw, ok := pod.Annotations[annotationUpstreams]
	//if !ok || raw == "" {
	//	return []corev1.EnvVar{}
	//}

	var result []corev1.EnvVar
	//for _, raw := range strings.Split(raw, ",") {
	//	parts := strings.SplitN(raw, ":", 2)
	//	port, _ := portValue(pod, strings.TrimSpace(parts[1]))
	//	if port > 0 {
	//		name := strings.TrimSpace(parts[0])
	//		name = strings.ToUpper(strings.Replace(name, "-", "_", -1))
	//		portStr := strconv.Itoa(int(port))
	//
	//		result = append(result, corev1.EnvVar{
	//			Name:  fmt.Sprintf("%s_CONNECT_SERVICE_HOST", name),
	//			Value: "127.0.0.1",
	//		}, corev1.EnvVar{
	//			Name:  fmt.Sprintf("%s_CONNECT_SERVICE_PORT", name),
	//			Value: portStr,
	//		})
	//	}
	//}

	return result
}
