package agent

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/mattbaird/jsonpatch"
	corev1 "k8s.io/api/core/v1"
)

// TODO swap out 'github.com/mattbaird/jsonpatch' for 'github.com/evanphx/json-patch'

const (
	DefaultVaultImage    = "vault:1.3.1"
	DefaultVaultAuthPath = "auth/kubernetes"
)

// Agent is the top level structure holding all the
// configurations for the Vault Agent container.
type Agent struct {
	// Annotations are the current pod annotations used to
	// configure the Vault Agent container.
	Annotations map[string]string

	// ImageName is the name of the Vault image to use for the
	// sidecar container.
	ImageName string

	// Inject is the flag used to determine if a container should be requested
	// in a pod request.
	Inject bool

	// LimitsCPU is the upper CPU limit the sidecar container is allowed to consume.
	LimitsCPU string

	// LimitsMem is the upper memory limit the sidecar container is allowed to consume.
	LimitsMem string

	// Namespace is the Kubernetes namespace the request originated from.
	Namespace string

	// Patches are all the mutations we will make to the pod request.
	Patches []*jsonpatch.JsonPatchOperation

	// Pod is the original Kubernetes pod spec.
	Pod *corev1.Pod

	// PrePopulate controls whether an init container is added to the request.
	PrePopulate bool

	// PrePopulateOnly controls whether an init container is the _only_ container
	//added to the request.
	PrePopulateOnly bool

	// RequestsCPU is the requested minimum CPU amount required  when being scheduled to deploy.
	RequestsCPU string

	// RequestsMem is the requested minimum memory amount required when being scheduled to deploy.
	RequestsMem string

	// Secrets are all the templates, the path in Vault where the secret can be
	//found, and the unique name of the secret which will be used for the filename.
	Secrets []*Secret

	// ServiceAccountName is the Kubernetes service account name for the pod.
	// This is used when we mount the service account to the  Vault Agent container(s).
	ServiceAccountName string

	// ServiceAccountPath is the path on disk where the service account JWT
	// can be located.  This is used when we mount the service account to the
	// Vault Agent container(s).
	ServiceAccountPath string

	// Status is the current injection status.  The only status considered is "injected",
	// which prevents further mutations.  A user can patch this annotation to force a new
	// mutation.
	Status string

	// ConfigMapName is the name of the configmap a user wants to mount to Vault Agent
	// container(s).
	ConfigMapName string

	// Vault is the structure holding all the Vault specific configurations.
	Vault Vault

	//IstioInjection contain config value of Istio
	Istio IstioInjection

	// Pluton is the structure holding all the Pluton specific configurations.
	InjectPluton   bool
	Pluton         Pluton
	PlutonEnvs     []*PlutonEnv
	MainEntrypoint string
	MainConfig     string
}

type Secret struct {
	// Name of the secret used as the filename for the rendered secret file.
	Name string

	// Path in Vault where the secret desired can be found.
	Path string

	// Template is the optional custom template to use when rendering the secret.
	Template string
}

type Vault struct {
	// Address is the Vault service address.
	Address string

	// AuthPath is the Mount Path of Vault Kubernetes Auth Method.
	AuthPath string

	// CACert is the name of the Certificate Authority certificate
	// to use when validating Vault's server certificates.
	CACert string

	// CAKey is the name of the Certificate Authority key
	// to use when validating Vault's server certificates.
	CAKey string

	// ClientCert is the name of the client certificate to use when communicating
	// with Vault over TLS.
	ClientCert string

	// ClientKey is the name of the client key to use when communicating
	// with Vault over TLS.
	ClientKey string

	// ClientMaxRetries configures the number of retries the client should make
	// when 5-- errors are received from the Vault server.  Default is 2.
	ClientMaxRetries string

	// ClientTimeout is the max number in seconds the client should attempt to
	// make a request to the Vault server.
	ClientTimeout string

	// Role is the name of the Vault role to use for authentication.
	Role string

	// TLSSecret is the name of the secret to be mounted to the Vault Agent container
	// containing the TLS certificates required to communicate with Vault.
	TLSSecret string

	// TLSSkipVerify toggles verification of Vault's certificates.
	TLSSkipVerify bool

	// TLSServerName is the name of the Vault server to use when validating Vault's
	// TLS certificates.
	TLSServerName string

	InjectMode string
}

type IstioInjection struct {
	IsEnableIstioInitContainer bool
	InitContainerImage         string
}

type Pluton struct {
	InfluxdbUrl string
}

type PlutonEnv struct {
	Key   string
	Value string
}

// New creates a new instance of Agent by parsing all the Kubernetes annotations.
func New(pod *corev1.Pod, patches []*jsonpatch.JsonPatchOperation) (*Agent, error) {
	saName, saPath := serviceaccount(pod)

	agent := &Agent{
		Annotations:   pod.Annotations,
		ConfigMapName: pod.Annotations[AnnotationAgentConfigMap],
		ImageName:     pod.Annotations[AnnotationAgentImage],
		LimitsCPU:     pod.Annotations[AnnotationAgentLimitsCPU],
		LimitsMem:     pod.Annotations[AnnotationAgentLimitsMem],
		MainConfig:    pod.Annotations[AnnotationMainConfig],
		Namespace:     pod.Annotations[AnnotationAgentRequestNamespace],
		Patches:       patches,
		Pluton: Pluton{
			InfluxdbUrl: pod.Annotations[AnnotationPlutonInfluxUrl],
		},
		PlutonEnvs:         plutonEnvs(pod.Annotations),
		Pod:                pod,
		RequestsCPU:        pod.Annotations[AnnotationAgentRequestsCPU],
		RequestsMem:        pod.Annotations[AnnotationAgentRequestsMem],
		Secrets:            secrets(pod.Annotations),
		ServiceAccountName: saName,
		ServiceAccountPath: saPath,
		Status:             pod.Annotations[AnnotationAgentStatus],
		Vault: Vault{
			Address:          pod.Annotations[AnnotationVaultService],
			AuthPath:         pod.Annotations[AnnotationVaultAuthPath],
			CACert:           pod.Annotations[AnnotationVaultCACert],
			CAKey:            pod.Annotations[AnnotationVaultCAKey],
			ClientCert:       pod.Annotations[AnnotationVaultClientCert],
			ClientKey:        pod.Annotations[AnnotationVaultClientKey],
			ClientMaxRetries: pod.Annotations[AnnotationVaultClientMaxRetries],
			ClientTimeout:    pod.Annotations[AnnotationVaultClientTimeout],
			Role:             pod.Annotations[AnnotationVaultRole],
			TLSSecret:        pod.Annotations[AnnotationVaultTLSSecret],
			TLSServerName:    pod.Annotations[AnnotationVaultTLSServerName],
			InjectMode:       pod.Annotations[AnnotationAgentInjectMode],
		},
		Istio: IstioInjection{},
	}

	var err error
	agent.Inject, err = agent.inject()
	if err != nil {
		return agent, err
	}

	agent.Istio.IsEnableIstioInitContainer, err = agent.getIstioInitInjectFlag()

	if err != nil {
		return agent, err
	}

	agent.InjectPluton, err = agent.injectPluton()
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

	agent.MainEntrypoint, err = agent.getEntrypoint()
	if err != nil {
		return agent, err
	}

	return agent, nil
}

// ShouldInject checks whether the pod in question should be injected
// with Vault Agent containers.
func ShouldInject(pod *corev1.Pod) (bool, error) {
	rawPluton, ok := pod.Annotations[AnnotationPlutonInject]
	if ok {
		injectPluton, err := strconv.ParseBool(rawPluton)
		if err != nil {
			return false, err
		}

		if !injectPluton {
			return false, nil
		} else {
			return true, nil
		}
	}

	//check annotation injectIstio and status IstioInject
	rawIstio, ok := pod.Annotations[AnnotationIstioInitInject]

	if ok {
		shouldInjectIstioInitContainer, err := strconv.ParseBool(rawIstio)
		fmt.Println("istio inject flat enable")
		if err != nil {
			return false, err
		}
		if shouldInjectIstioInitContainer {
			istioInjectStatus, ok := pod.Annotations[AnnotationIstioInitStatus]
			if ok {
				if istioInjectStatus != "injected" {
					return true, nil
				}
			} else {
				return true, nil
			}
		}
	}

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

	// This shouldn't happen so bail.
	raw, ok = pod.Annotations[AnnotationAgentStatus]
	if !ok {
		return true, nil
	}

	// "injected" is the only status we care about.  Don't do
	// anything if it's set.  The user can update the status
	// to force a new mutation.
	if raw == "injected" {
		return false, nil
	}

	return true, nil
}

// Patch creates the necessary pod patches to inject the Vault Agent
// containers.
func (a *Agent) Patch() ([]*jsonpatch.JsonPatchOperation, error) {
	// var patches []byte
	var patches []*jsonpatch.JsonPatchOperation

	// Add our volume that will be shared by the containers
	// for passing data in the pod.
	a.Patches = append(a.Patches, addVolumes(
		a.Pod.Spec.Volumes,
		[]corev1.Volume{a.ContainerVolume()},
		"/spec/volumes")...)

	// Add ConfigMap if one was provided
	if a.ConfigMapName != "" {
		a.Patches = append(a.Patches, addVolumes(
			a.Pod.Spec.Volumes,
			[]corev1.Volume{a.ContainerConfigMapVolume()},
			"/spec/volumes")...)
	}

	// Add TLS Secret if one was provided
	if a.Vault.TLSSecret != "" {
		a.Patches = append(a.Patches, addVolumes(
			a.Pod.Spec.Volumes,
			[]corev1.Volume{a.ContainerTLSSecretVolume()},
			"/spec/volumes")...)
	}

	//Add Volume Mounts
	for i, container := range a.Pod.Spec.Containers {
		a.Patches = append(a.Patches, addVolumeMounts(
			container.VolumeMounts,
			[]corev1.VolumeMount{a.ContainerVolumeMount()},
			fmt.Sprintf("/spec/containers/%d/volumeMounts", i))...)
	}

	// Init Container
	var container corev1.Container
	var getContainerErr error
	if a.PrePopulate {
		container, getContainerErr = a.ContainerInitSidecar()
	} else {
		if a.Istio.IsEnableIstioInitContainer == true {
			container, getContainerErr = a.CreateIstioInitSidecar()
		}
	}

	if getContainerErr != nil {
		return patches, getContainerErr
	}
	//if container with noname => container struct is not set => do not append
	if container.Name != "" {
		a.Patches = append(a.Patches, addContainers(
			a.Pod.Spec.InitContainers,
			[]corev1.Container{container},
			"/spec/initContainers")...)
	}

	// Sidecar Container
	if !a.PrePopulateOnly && a.Inject {
		container, err := a.ContainerSidecar()
		if err != nil {
			return patches, err
		}
		a.Patches = append(a.Patches, addContainers(
			a.Pod.Spec.Containers,
			[]corev1.Container{container},
			"/spec/containers")...)
	}

	// Add annotations so that we know we're injected
	annotations := map[string]string{
		AnnotationAgentStatus: "injected",
	}
	if a.Istio.IsEnableIstioInitContainer {
		annotations[AnnotationIstioInitStatus] = "injected"
		if deployName, err := getDeploymentNameFromPodName(a.Pod.Name); err == nil {
			a.Patches = append(a.Patches, updateLabels(a.Pod.Labels, map[string]string{"app": deployName})...)
		}
	}
	a.Patches = append(a.Patches, updateAnnotations(a.Pod.Annotations, annotations)...)

	// // Modify main container
	// a.Patches = append(a.Patches, modifyContainers(
	// 	a.Pod.Spec.Containers,
	// 	"/spec/containers",
	// )...)

	// Generate the patch
	// if len(a.Patches) > 0 {
	// 	var err error
	// 	patches, err = json.Marshal(a.Patches)
	// 	if err != nil {
	// 		return patches, err
	// 	}
	// } Move out of func to handler
	patches = a.Patches
	return patches, nil
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

	if a.ConfigMapName == "" && a.Pluton.InfluxdbUrl == "" {
		if a.Vault.Role == "" {
			return errors.New("no Vault role found")
		}

		if a.Vault.AuthPath == "" {
			return errors.New("no Vault Auth Path found")
		}

		if a.Vault.Address == "" {
			return errors.New("no Vault address found")
		}
	}
	return nil
}

func serviceaccount(pod *corev1.Pod) (string, string) {
	var serviceAccountName, serviceAccountPath string
	for _, container := range pod.Spec.Containers {
		for _, volumes := range container.VolumeMounts {
			if strings.Contains(volumes.MountPath, "serviceaccount") {
				return volumes.Name, volumes.MountPath
			}
		}
	}
	return serviceAccountName, serviceAccountPath
}
