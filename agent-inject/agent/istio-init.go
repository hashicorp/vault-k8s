package agent

import (
	"github.com/hashicorp/vault/sdk/helper/pointerutil"
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

func (a *Agent) createIstioInitSecurityContext() *corev1.SecurityContext {
	return &corev1.SecurityContext{
		RunAsUser:    pointerutil.Int64Ptr(0),
		RunAsGroup:   pointerutil.Int64Ptr(0),
		RunAsNonRoot: pointerutil.BoolPtr(false),
		Capabilities: a.createIstioInitCapabilities(),
	}
}

func (a *Agent) rewriteContainerCommand(cmd string) string {
	cmd += "&& /usr/local/bin/istio-init.sh"
	return cmd
}
