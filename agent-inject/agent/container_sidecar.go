package agent

import (
	"fmt"
	"strings"

	"github.com/hashicorp/vault/sdk/helper/pointerutil"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
)

const (
	// https://kubernetes.io/docs/concepts/configuration/manage-compute-resources-container/#meaning-of-cpu
	DefaultResourceLimitCPU   = "500m"
	DefaultResourceLimitMem   = "128Mi"
	DefaultResourceRequestCPU = "250m"
	DefaultResourceRequestMem = "64Mi"
	DefaultContainerArg       = "echo ${VAULT_CONFIG?} | base64 -d > /home/vault/config.json && vault agent -config=/home/vault/config.json"
	DefaultRevokeGrace        = 5
	DefaultAgentLogLevel      = "info"
)

// ContainerSidecar creates a new container to be added
// to the pod being mutated.
func (a *Agent) ContainerSidecar() (corev1.Container, error) {
	volumeMounts := []corev1.VolumeMount{
		{
			Name:      a.ServiceAccountName,
			MountPath: a.ServiceAccountPath,
			ReadOnly:  true,
		},
		{
			Name:      tokenVolumeNameSidecar,
			MountPath: tokenVolumePath,
			ReadOnly:  false,
		},
	}
	volumeMounts = append(volumeMounts, a.ContainerVolumeMounts()...)

	if a.ExtraSecret != "" {
		volumeMounts = append(volumeMounts, corev1.VolumeMount{
			Name:      extraSecretVolumeName,
			MountPath: extraSecretVolumePath,
			ReadOnly:  true,
		})
	}

	if a.CopyVolumeMounts != "" {
		volumeMounts = append(volumeMounts, a.copyVolumeMounts(a.CopyVolumeMounts)...)
	}

	arg := DefaultContainerArg

	if a.ConfigMapName != "" {
		volumeMounts = append(volumeMounts, corev1.VolumeMount{
			Name:      configVolumeName,
			MountPath: configVolumePath,
			ReadOnly:  true,
		})
		arg = fmt.Sprintf("touch %s && vault agent -config=%s/config.hcl", TokenFile, configVolumePath)
	}

	if a.Vault.TLSSecret != "" {
		volumeMounts = append(volumeMounts, corev1.VolumeMount{
			Name:      tlsSecretVolumeName,
			MountPath: tlsSecretVolumePath,
			ReadOnly:  true,
		})
	}

	envs, err := a.ContainerEnvVars(false)
	if err != nil {
		return corev1.Container{}, err
	}

	resources, err := a.parseResources()
	if err != nil {
		return corev1.Container{}, err
	}

	lifecycle := a.createLifecycle()

	newContainer := corev1.Container{
		Name:         "vault-agent",
		Image:        a.ImageName,
		Env:          envs,
		Resources:    resources,
		VolumeMounts: volumeMounts,
		Lifecycle:    &lifecycle,
		Command:      []string{"/bin/sh", "-ec"},
		Args:         []string{arg},
	}
	if a.SetSecurityContext {
		newContainer.SecurityContext = a.securityContext()
	}

	return newContainer, nil
}

// Valid resource notations: https://kubernetes.io/docs/concepts/configuration/manage-compute-resources-container/#meaning-of-cpu
func (a *Agent) parseResources() (corev1.ResourceRequirements, error) {
	resources := corev1.ResourceRequirements{}
	limits := corev1.ResourceList{}
	requests := corev1.ResourceList{}

	// Limits
	if a.LimitsCPU != "" {
		cpu, err := parseQuantity(a.LimitsCPU)
		if err != nil {
			return resources, err
		}

		limits[corev1.ResourceCPU] = cpu
	}

	if a.LimitsMem != "" {
		mem, err := parseQuantity(a.LimitsMem)
		if err != nil {
			return resources, err
		}
		limits[corev1.ResourceMemory] = mem
	}

	resources.Limits = limits

	// Requests
	if a.RequestsCPU != "" {
		cpu, err := parseQuantity(a.RequestsCPU)
		if err != nil {
			return resources, err
		}
		requests[corev1.ResourceCPU] = cpu
	}

	if a.RequestsMem != "" {
		mem, err := parseQuantity(a.RequestsMem)
		if err != nil {
			return resources, err
		}
		requests[corev1.ResourceMemory] = mem
	}

	resources.Requests = requests

	return resources, nil
}

func parseQuantity(raw string) (resource.Quantity, error) {
	var q resource.Quantity
	if raw == "" {
		return q, nil
	}

	return resource.ParseQuantity(raw)
}

// This should only be run for a sidecar container
func (a *Agent) createLifecycle() corev1.Lifecycle {
	lifecycle := corev1.Lifecycle{}

	if a.RevokeOnShutdown {
		flags := a.vaultCliFlags()
		flags = append(flags, "-self")

		lifecycle.PreStop = &corev1.Handler{
			Exec: &corev1.ExecAction{
				Command: []string{"/bin/sh", "-c", fmt.Sprintf("/bin/sleep %d && /bin/vault token revoke %s", a.RevokeGrace, strings.Join(flags[:], " "))},
			},
		}
	}

	return lifecycle
}

func (a *Agent) securityContext() *corev1.SecurityContext {
	runAsNonRoot := true

	if a.RunAsUser == 0 || a.RunAsGroup == 0 {
		runAsNonRoot = false
	}
	return &corev1.SecurityContext{
		RunAsUser:              pointerutil.Int64Ptr(a.RunAsUser),
		RunAsGroup:             pointerutil.Int64Ptr(a.RunAsGroup),
		RunAsNonRoot:           pointerutil.BoolPtr(runAsNonRoot),
		ReadOnlyRootFilesystem: pointerutil.BoolPtr(DefaultAgentReadOnlyRoot),
		Capabilities: &corev1.Capabilities{
			Drop: []corev1.Capability{DefaultAgentDropCapabilities},
		},
		AllowPrivilegeEscalation: pointerutil.BoolPtr(DefaultAgentAllowPrivilegeEscalation),
	}
}
