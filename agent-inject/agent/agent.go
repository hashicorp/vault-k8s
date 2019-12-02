package agent

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/mattbaird/jsonpatch"
	corev1 "k8s.io/api/core/v1"
)

const (
	DefaultVaultImage = "vault:1.3.1	"
)

type Agent struct {
	Annotations        map[string]string
	ImageName          string
	Inject             bool
	Namespace          string
	Patches            *[]jsonpatch.JsonPatchOperation
	Pod                *corev1.Pod
	PrePopulate        bool
	PrePopulateOnly    bool
	Secrets            []*Secret
	ServiceAccountName string
	ServiceAccountPath string
	Status             string
	ConfigMapName      string
	Vault              Vault
}

type Secret struct {
	Name     string
	Path     string
	Template string
}

type Vault struct {
	Address          string
	CACert           string
	CAKey            string
	ClientCert       string
	ClientKey        string
	ClientMaxRetries string
	ClientTimeout    string
	Role             string
	TLSSecret        string
	TLSSkipVerify    bool
	TLSServerName    string
}

func New(pod *corev1.Pod, patches *[]jsonpatch.JsonPatchOperation) (Agent, error) {
	saName, saPath := serviceaccount(pod)

	agent := Agent{
		Annotations:        pod.Annotations,
		ConfigMapName:      pod.Annotations[AnnotationAgentConfigMap],
		ImageName:          pod.Annotations[AnnotationAgentImage],
		Namespace:          pod.Annotations[AnnotationAgentRequestNamespace],
		Patches:            patches,
		Pod:                pod,
		Secrets:            secrets(pod.Annotations),
		ServiceAccountName: saName,
		ServiceAccountPath: saPath,
		Status:             pod.Annotations[AnnotationAgentStatus],
		Vault: Vault{
			Address:          pod.Annotations[AnnotationVaultService],
			CACert:           pod.Annotations[AnnotationVaultCACert],
			CAKey:            pod.Annotations[AnnotationVaultCAKey],
			ClientCert:       pod.Annotations[AnnotationVaultClientCert],
			ClientKey:        pod.Annotations[AnnotationVaultClientKey],
			ClientMaxRetries: pod.Annotations[AnnotationVaultClientMaxRetries],
			ClientTimeout:    pod.Annotations[AnnotationVaultClientTimeout],
			Role:             pod.Annotations[AnnotationVaultRole],
			TLSSecret:        pod.Annotations[AnnotationVaultTLSSecret],
			TLSServerName:    pod.Annotations[AnnotationVaultTLSServerName],
		},
	}

	var err error
	agent.Inject, err = agent.inject()
	if err != nil {
		return agent, err
	}

	agent.PrePopulate, err = agent.prePopulate()
	if err != nil {
		return agent, err
	}

	agent.PrePopulateOnly, err = agent.prePopulateOnly()
	if err != nil {
		return agent, err
	}

	agent.Vault.TLSSkipVerify, err = agent.tlsSkipVerify()
	if err != nil {
		return agent, err
	}

	return agent, nil
}

// ShouldInject checks whether the pod in question should be injected
// with Vault Agent containers.
func ShouldInject(pod *corev1.Pod) (bool, error) {
	raw, ok := pod.Annotations[AnnotationAgentInject]
	if !ok {
		return false, nil
	}

	inject, err := strconv.ParseBool(raw)
	if err != nil {
		return false, err
	}

	if !inject {
		return false, nil
	}

	raw, ok = pod.Annotations[AnnotationAgentStatus]
	if !ok {
		return true, nil
	}

	if raw == "injected" {
		return false, nil
	}

	return true, nil
}

// Patch creates the necessary pod patches to inject the Vault Agent
// containers.
func (a *Agent) Patch() ([]byte, error) {
	var patches []byte

	// Add our volume that will be shared by the containers
	// for passing data in the pod.
	*a.Patches = append(*a.Patches, addVolumes(
		a.Pod.Spec.Volumes,
		[]corev1.Volume{a.ContainerVolume()},
		"/spec/volumes")...)

	// Add ConfigMap if one was provided
	if a.ConfigMapName != "" {
		*a.Patches = append(*a.Patches, addVolumes(
			a.Pod.Spec.Volumes,
			[]corev1.Volume{a.ContainerConfigMapVolume()},
			"/spec/volumes")...)
	}

	// Add TLS Secret if one was provided
	if a.Vault.TLSSecret != "" {
		*a.Patches = append(*a.Patches, addVolumes(
			a.Pod.Spec.Volumes,
			[]corev1.Volume{a.ContainerTLSSecretVolume()},
			"/spec/volumes")...)
	}

	//Add Volume Mounts
	for i, container := range a.Pod.Spec.Containers {
		*a.Patches = append(*a.Patches, addVolumeMounts(
			container.VolumeMounts,
			[]corev1.VolumeMount{a.ContainerVolumeMount()},
			fmt.Sprintf("/spec/containers/%d/volumeMounts", i))...)
	}

	// Init Container
	if a.PrePopulate {
		container, err := a.ContainerInitSidecar()
		if err != nil {
			return patches, err
		}
		*a.Patches = append(*a.Patches, addContainers(
			a.Pod.Spec.InitContainers,
			[]corev1.Container{container},
			"/spec/initContainers")...)
	}

	// Sidecar Container
	if !a.PrePopulateOnly {
		container, err := a.ContainerSidecar()
		if err != nil {
			return patches, err
		}
		*a.Patches = append(*a.Patches, addContainers(
			a.Pod.Spec.Containers,
			[]corev1.Container{container},
			"/spec/containers")...)
	}

	// Add annotations so that we know we're injected
	*a.Patches = append(*a.Patches, updateAnnotations(
		a.Pod.Annotations,
		map[string]string{AnnotationAgentStatus: "injected"})...)

	// Generate the patch
	if len(*a.Patches) > 0 {
		var err error
		patches, err = json.Marshal(a.Patches)
		if err != nil {
			return patches, err
		}
	}
	return patches, nil
}

func serviceaccount(pod *corev1.Pod) (string, string) {
	var serviceAccountName, serviceAccountPath string
	for _, container := range pod.Spec.Containers {
		for _, volumes := range container.VolumeMounts {
			if strings.Contains(volumes.MountPath, "serviceaccount") {
				serviceAccountName = volumes.Name
				serviceAccountPath = volumes.MountPath
			}
		}
	}

	return serviceAccountName, serviceAccountPath
}

// Validate the instance of Agent to ensure we have everything needed
// for basic functionality.
func (a *Agent) Validate() error {
	if a.Namespace == "" {
		return errors.New("namespace missing from request")
	}

	if a.ServiceAccountName == "" || a.ServiceAccountPath == "" {
		return errors.New("no service account name or path found")
	}

	if a.ImageName == "" {
		return errors.New("no Vault image found")
	}

	if a.ConfigMapName == "" {
		if a.Vault.Role == "" {
			return errors.New("no Vault role found")
		}

		if a.Vault.Address == "" {
			return errors.New("no Vault address found")
		}
	}
	return nil
}
