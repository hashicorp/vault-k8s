package agent

import (
	corev1 "k8s.io/api/core/v1"
)

//Add ISTIO_INIT_ENABLED env
func (a *Agent) createIstioInitEnv() corev1.EnvVar {
	return corev1.EnvVar{
		Name:  "ISTIO_INIT_ENABLED",
		Value: "true",
	}
}

//Add network_admin and network_raw to container
func (a *Agent) createIstioInitCapabilities() *corev1.Capabilities {
	cap := corev1.Capabilities{}
	cap.Add = append(cap.Add, "NET_ADMIN")
	cap.Add = append(cap.Add, "NET_RAW")
	return &cap
}

func (a *Agent) rewriteContainerCommand(cmd string) string {
	cmd += "&& bash /usr/local/bin/istio-init.sh"
	return cmd
}
