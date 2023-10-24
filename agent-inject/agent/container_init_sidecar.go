// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package agent

import (
	"encoding/json"
	"fmt"

	jsonpatch "github.com/evanphx/json-patch"
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
			Name:      tokenVolumeNameInit,
			MountPath: tokenVolumePath,
			ReadOnly:  false,
		},
		{
			Name:      a.ServiceAccountTokenVolume.Name,
			MountPath: a.ServiceAccountTokenVolume.MountPath,
			ReadOnly:  true,
		},
	}
	if a.AwsIamTokenAccountName != "" && a.AwsIamTokenAccountPath != "" {
		volumeMounts = append(volumeMounts, corev1.VolumeMount{
			Name:      a.AwsIamTokenAccountName,
			MountPath: a.AwsIamTokenAccountPath,
			ReadOnly:  true,
		})
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
		arg = fmt.Sprintf("touch %s && vault agent -config=%s/config-init.hcl", TokenFile, configVolumePath)
	}

	if a.Vault.TLSSecret != "" {
		volumeMounts = append(volumeMounts, corev1.VolumeMount{
			Name:      tlsSecretVolumeName,
			MountPath: tlsSecretVolumePath,
			ReadOnly:  true,
		})
	}

	if a.VaultAgentCache.Persist {
		volumeMounts = append(volumeMounts, a.cacheVolumeMount())
	}

	envs, err := a.ContainerEnvVars(true)
	if err != nil {
		return corev1.Container{}, err
	}

	resources, err := a.parseResources()
	if err != nil {
		return corev1.Container{}, err
	}

	newContainer := corev1.Container{
		Name:         "vault-agent-init",
		Image:        a.ImageName,
		Env:          envs,
		Resources:    resources,
		VolumeMounts: volumeMounts,
		Command:      []string{"/bin/sh", "-ec"},
		Args:         []string{arg},
	}
	if a.SetSecurityContext {
		newContainer.SecurityContext = a.securityContext()
	}

	// apply any JSON patch requested
	if a.InitJsonPatch == "" {
		return newContainer, nil
	}

	containerJson, err := json.Marshal(newContainer)
	if err != nil {
		return newContainer, err
	}
	patch, err := jsonpatch.DecodePatch([]byte(a.InitJsonPatch))
	if err != nil {
		return newContainer, fmt.Errorf("failed to decode JSON patch: %w", err)
	}
	newContainerJson, err := patch.Apply(containerJson)
	if err != nil {
		return newContainer, fmt.Errorf("failed to apply JSON patch: %w", err)
	}
	newContainer = corev1.Container{}
	err = json.Unmarshal(newContainerJson, &newContainer)
	if err != nil {
		return newContainer, err
	}
	return newContainer, nil
}
