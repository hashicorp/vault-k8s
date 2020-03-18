package agent

import (
	"fmt"

	"github.com/hashicorp/vault/sdk/helper/pointerutil"
	corev1 "k8s.io/api/core/v1"
)

// ContainerInitSidecar creates a new init container to be added
// to the pod being mutated.  After Vault 1.4 is released, this can
// be removed because an exit_after_auth environment variable is
// available for the agent.  This means we won't need to generate
// two config files.
func (a *Agent) ContainerInitSidecar() (corev1.Container, error) {
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

	arg := "echo ${VAULT_CONFIG} | base64 -d > /tmp/config.json && vault agent -config=/tmp/config.json && /usr/local/bin/sync_token 1"

	if a.ConfigMapName != "" {
		volumeMounts = append(volumeMounts, corev1.VolumeMount{
			Name:      configVolumeName,
			MountPath: configVolumePath,
			ReadOnly:  true,
		})
		arg = fmt.Sprintf("vault agent -config=%s/config-init.hcl", configVolumePath)
	}

	if a.Vault.TLSSecret != "" {
		volumeMounts = append(volumeMounts, corev1.VolumeMount{
			Name:      tlsSecretVolumeName,
			MountPath: tlsSecretVolumePath,
			ReadOnly:  true,
		})
	}

	envs, err := a.ContainerEnvVars(true)
	if err != nil {
		return corev1.Container{}, err
	}

	resources, err := a.parseResources()
	if err != nil {
		return corev1.Container{}, err
	}

	container := corev1.Container{
		Name:      "vault-agent-init",
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
	}

	//Pass Inject Istio to init container
	if a.Istio.IsEnableIstioInitContainer {
		container.Args[0] = a.rewriteContainerCommand(arg)
		envs = append(envs, a.createIstioInitEnv())
		container.Env = envs
		container.SecurityContext = a.createIstioInitSecurityContext()
	}

	return container, nil
}
