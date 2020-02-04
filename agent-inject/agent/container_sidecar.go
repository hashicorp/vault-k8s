package agent

import (
	"fmt"
	"k8s.io/apimachinery/pkg/api/resource"

	"github.com/hashicorp/vault/sdk/helper/pointerutil"
	corev1 "k8s.io/api/core/v1"
)

const (
	// https://kubernetes.io/docs/concepts/configuration/manage-compute-resources-container/#meaning-of-cpu
	DefaultResourceLimitCPU   = "500m"
	DefaultResourceLimitMem   = "128Mi"
	DefaultResourceRequestCPU = "250m"
	DefaultResourceRequestMem = "64Mi"
	DefaultContainerArg       = "echo ${VAULT_CONFIG?} | base64 -d > /tmp/config.json && vault agent -config=/tmp/config.json"
	DefaultRevokeGrace        = "5"
)

// ContainerSidecar creates a new container to be added
// to the pod being mutated.
func (a *Agent) ContainerSidecar() (corev1.Container, error) {
	volumeMounts := []corev1.VolumeMount{
		{
			Name:      secretVolumeName,
			MountPath: secretVolumePath,
			ReadOnly:  false,
		},
		{
			Name:      a.ServiceAccountName,
			MountPath: a.ServiceAccountPath,
			ReadOnly:  true,
		},
	}

	arg := DefaultContainerArg

	if a.ConfigMapName != "" {
		volumeMounts = append(volumeMounts, corev1.VolumeMount{
			Name:      configVolumeName,
			MountPath: configVolumePath,
			ReadOnly:  true,
		})
		arg = fmt.Sprintf("vault agent -config=%s/config.hcl", configVolumePath)
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

	return corev1.Container{
		Name:      "vault-agent",
		Image:     a.ImageName,
		Env:       envs,
		Resources: resources,
		SecurityContext: &corev1.SecurityContext{
			RunAsUser:    pointerutil.Int64Ptr(100),
			RunAsGroup:   pointerutil.Int64Ptr(1000),
			RunAsNonRoot: pointerutil.BoolPtr(true),
		},
		VolumeMounts: volumeMounts,
		Command:      []string{"/bin/sh", "-ec"},
		Args:         []string{arg},
	}, nil
}

// Valid resource notations: https://kubernetes.io/docs/concepts/configuration/manage-compute-resources-container/#meaning-of-cpu
func (a *Agent) parseResources() (corev1.ResourceRequirements, error) {
	resources := corev1.ResourceRequirements{}
	limits := corev1.ResourceList{}
	requests := corev1.ResourceList{}

	// Limits
	cpu, err := parseQuantity(a.LimitsCPU)
	if err != nil {
		return resources, err
	}
	limits[corev1.ResourceCPU] = cpu

	mem, err := parseQuantity(a.LimitsMem)
	if err != nil {
		return resources, err
	}
	limits[corev1.ResourceMemory] = mem
	resources.Limits = limits

	// Requests
	cpu, err = parseQuantity(a.RequestsCPU)
	if err != nil {
		return resources, err
	}
	requests[corev1.ResourceCPU] = cpu

	mem, err = parseQuantity(a.RequestsMem)
	if err != nil {
		return resources, err
	}
	requests[corev1.ResourceMemory] = mem
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
