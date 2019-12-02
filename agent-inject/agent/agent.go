package agent

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/hashicorp/vault-k8s/agent-inject/patch"
	"github.com/mattbaird/jsonpatch"
	corev1 "k8s.io/api/core/v1"
	"log"
	"strconv"
	"strings"
)

const (
	DefaultVaultImage = "vault:1.3.0"
)

type Agent struct {
	Annotations        map[string]string
	ImageName          string
	Inject             bool
	Log                log.Logger
	Namespace          string
	Patches            *[]jsonpatch.JsonPatchOperation
	Pod                *corev1.Pod
	PrePopulate        bool
	PrePopulateOnly    bool
	Secrets            []Secret
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
		Patches:            patches,
		Pod:                pod,
		ServiceAccountName: saName,
		ServiceAccountPath: saPath,
	}

	err := agent.parse()
	if err != nil {
		return agent, fmt.Errorf("error parsing agent sidecar: %s", err)
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
	*a.Patches = append(*a.Patches, patch.AddVolume(
		a.Pod.Spec.Volumes,
		[]corev1.Volume{a.ContainerVolume()},
		"/spec/volumes")...)

	// Add ConfigMap if one was provided
	if a.ConfigMapName != "" {
		*a.Patches = append(*a.Patches, patch.AddVolume(
			a.Pod.Spec.Volumes,
			[]corev1.Volume{a.ContainerConfigMapVolume()},
			"/spec/volumes")...)
	}

	// Add TLS Secret if one was provided
	if a.Vault.TLSSecret != "" {
		*a.Patches = append(*a.Patches, patch.AddVolume(
			a.Pod.Spec.Volumes,
			[]corev1.Volume{a.ContainerTLSSecretVolume()},
			"/spec/volumes")...)
	}

	//Add Volume Mounts
	for i, container := range a.Pod.Spec.Containers {
		*a.Patches = append(*a.Patches, patch.AddVolumeMount(
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
		*a.Patches = append(*a.Patches, patch.AddContainer(
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
		*a.Patches = append(*a.Patches, patch.AddContainer(
			a.Pod.Spec.Containers,
			[]corev1.Container{container},
			"/spec/containers")...)
	}

	// Add annotations so that we know we're injected
	*a.Patches = append(*a.Patches, patch.UpdateAnnotation(
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

func (a *Agent) parse() error {
	a.Namespace = a.namespace()
	a.Status = a.status()
	a.ImageName = a.image()
	a.Secrets = a.secrets()
	a.ConfigMapName = a.configMap()
	a.Vault.Role = a.role()
	a.Vault.Address = a.address()
	a.Vault.CACert = a.caCert()
	a.Vault.CAKey = a.caKey()
	a.Vault.ClientCert = a.clientCert()
	a.Vault.ClientKey = a.clientKey()
	a.Vault.ClientMaxRetries = a.clientMaxRetries()
	a.Vault.ClientTimeout = a.clientTimeout()
	a.Vault.TLSServerName = a.tlsServerName()
	a.Vault.TLSSecret = a.tlsSecret()

	var err error
	a.Inject, err = a.inject()
	if err != nil {
		return err
	}

	a.PrePopulate, err = a.prePopulate()
	if err != nil {
		return err
	}

	a.PrePopulateOnly, err = a.prePopulateOnly()
	if err != nil {
		return err
	}

	a.Vault.TLSSkipVerify, err = a.tlsSkipVerify()
	if err != nil {
		return err
	}

	return nil
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
