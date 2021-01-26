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

// TODO swap out 'github.com/mattbaird/jsonpatch' for 'github.com/evanphx/json-patch'

const (
	DefaultVaultImage                    = "vault:1.6.1"
	DefaultVaultAuthPath                 = "auth/kubernetes"
	DefaultAgentRunAsUser                = 100
	DefaultAgentRunAsGroup               = 1000
	DefaultAgentRunAsSameUser            = false
	DefaultAgentAllowPrivilegeEscalation = false
	DefaultAgentDropCapabilities         = "ALL"
	DefaultAgentSetSecurityContext       = true
	DefaultAgentReadOnlyRoot             = true
	DefaultAgentCacheEnable              = "false"
	DefaultAgentCacheUseAutoAuthToken    = "true"
	DefaultAgentCacheListenerPort        = "8200"
	DefaultAgentUseLeaderElector         = false
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

	// InitFirst controls whether an init container is first to run.
	InitFirst bool

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
	// added to the request.
	PrePopulateOnly bool

	// RevokeOnShutdown controls whether a sidecar container will attempt to revoke its Vault
	// token on shutting down.
	RevokeOnShutdown bool

	// RevokeGrace controls after receiving the signal for pod
	// termination that the container will attempt to revoke its own Vault token.
	RevokeGrace uint64

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

	// VaultAgentCache is the structure holding the Vault agent cache specific configurations
	VaultAgentCache VaultAgentCache

	// RunAsUser is the user ID to run the Vault agent container(s) as.
	RunAsUser int64

	// RunAsGroup is the group ID to run the Vault agent container(s) as.
	RunAsGroup int64

	// RunAsSameID sets the user ID of the Vault agent container(s) to be the
	// same as the first application container
	RunAsSameID bool

	// SetSecurityContext controls whether the injected containers have a
	// SecurityContext set.
	SetSecurityContext bool

	// ExtraSecret is the Kubernetes secret to mount as a volume in the Vault agent container
	// which can be referenced by the Agent config for secrets. Mounted at /vault/custom/
	ExtraSecret string

	// CopyVolumeMounts is the name of the container in the Pod whose volume mounts
	// should be copied into the Vault Agent init and/or sidecar containers.
	CopyVolumeMounts string
}

type Secret struct {
	// Name of the secret used to identify other annotation directives, and used
	// as the filename for the rendered secret file (unless FilePathAndName is
	// specified).
	Name string

	// Path in Vault where the secret desired can be found.
	Path string

	// Template is the optional custom template to use when rendering the secret.
	Template string

	// Mount Path for the volume holding the rendered secret file
	MountPath string

	// Command is the optional command to run after rendering the secret.
	Command string

	// FilePathAndName is the optional file path and name for the rendered secret file.
	FilePathAndName string
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

	// LogLevel sets the Vault Agent log level.  Defaults to info.
	LogLevel string

	// Namespace is the Vault namespace to prepend to secret paths.
	Namespace string

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
}

type VaultAgentCache struct {
	// Enable configures whether the cache is enabled or not
	Enable bool

	// ListenerPort is the port the cache should listen to
	ListenerPort string

	// UseAutoAuthToken configures whether the auto auth token is used in cache requests
	UseAutoAuthToken string
}

// New creates a new instance of Agent by parsing all the Kubernetes annotations.
func New(pod *corev1.Pod, patches []*jsonpatch.JsonPatchOperation) (*Agent, error) {
	saName, saPath := serviceaccount(pod)

	agent := &Agent{
		Annotations:        pod.Annotations,
		ConfigMapName:      pod.Annotations[AnnotationAgentConfigMap],
		ImageName:          pod.Annotations[AnnotationAgentImage],
		LimitsCPU:          pod.Annotations[AnnotationAgentLimitsCPU],
		LimitsMem:          pod.Annotations[AnnotationAgentLimitsMem],
		Namespace:          pod.Annotations[AnnotationAgentRequestNamespace],
		Patches:            patches,
		Pod:                pod,
		RequestsCPU:        pod.Annotations[AnnotationAgentRequestsCPU],
		RequestsMem:        pod.Annotations[AnnotationAgentRequestsMem],
		ServiceAccountName: saName,
		ServiceAccountPath: saPath,
		Status:             pod.Annotations[AnnotationAgentStatus],
		ExtraSecret:        pod.Annotations[AnnotationAgentExtraSecret],
		CopyVolumeMounts:   pod.Annotations[AnnotationAgentCopyVolumeMounts],
		Vault: Vault{
			Address:          pod.Annotations[AnnotationVaultService],
			AuthPath:         pod.Annotations[AnnotationVaultAuthPath],
			CACert:           pod.Annotations[AnnotationVaultCACert],
			CAKey:            pod.Annotations[AnnotationVaultCAKey],
			ClientCert:       pod.Annotations[AnnotationVaultClientCert],
			ClientKey:        pod.Annotations[AnnotationVaultClientKey],
			ClientMaxRetries: pod.Annotations[AnnotationVaultClientMaxRetries],
			ClientTimeout:    pod.Annotations[AnnotationVaultClientTimeout],
			LogLevel:         pod.Annotations[AnnotationVaultLogLevel],
			Namespace:        pod.Annotations[AnnotationVaultNamespace],
			Role:             pod.Annotations[AnnotationVaultRole],
			TLSSecret:        pod.Annotations[AnnotationVaultTLSSecret],
			TLSServerName:    pod.Annotations[AnnotationVaultTLSServerName],
		},
	}

	var err error
	agent.Secrets = agent.secrets()
	agent.Inject, err = agent.inject()
	if err != nil {
		return agent, err
	}

	agent.InitFirst, err = agent.initFirst()
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

	agent.RevokeOnShutdown, err = agent.revokeOnShutdown()
	if err != nil {
		return agent, err
	}

	agent.RevokeGrace, err = agent.revokeGrace()
	if err != nil {
		return agent, err
	}

	agent.Vault.TLSSkipVerify, err = agent.tlsSkipVerify()
	if err != nil {
		return agent, err
	}

	agent.RunAsUser, err = strconv.ParseInt(pod.Annotations[AnnotationAgentRunAsUser], 10, 64)
	if err != nil {
		return agent, err
	}

	agent.RunAsGroup, err = strconv.ParseInt(pod.Annotations[AnnotationAgentRunAsGroup], 10, 64)
	if err != nil {
		return agent, err
	}

	agent.RunAsSameID, err = agent.runAsSameID(pod)
	if err != nil {
		return agent, err
	}

	agent.SetSecurityContext, err = agent.setSecurityContext()
	if err != nil {
		return agent, err
	}

	agentCacheEnable, err := agent.agentCacheEnable()
	if err != nil {
		return agent, err
	}

	agent.VaultAgentCache = VaultAgentCache{
		Enable:           agentCacheEnable,
		ListenerPort:     pod.Annotations[AnnotationAgentCacheListenerPort],
		UseAutoAuthToken: pod.Annotations[AnnotationAgentCacheUseAutoAuthToken],
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
func (a *Agent) Patch() ([]byte, error) {
	var patches []byte

	// Add a volume for the token sink
	a.Patches = append(a.Patches, addVolumes(
		a.Pod.Spec.Volumes,
		a.ContainerTokenVolume(),
		"/spec/volumes")...)

	// Add our volume that will be shared by the containers
	// for passing data in the pod.
	a.Patches = append(a.Patches, addVolumes(
		a.Pod.Spec.Volumes,
		a.ContainerVolumes(),
		"/spec/volumes")...)

	// Add ConfigMap if one was provided
	if a.ConfigMapName != "" {
		a.Patches = append(a.Patches, addVolumes(
			a.Pod.Spec.Volumes,
			[]corev1.Volume{a.ContainerConfigMapVolume()},
			"/spec/volumes")...)
	}

	// Add ExtraSecret if one was provided
	if a.ExtraSecret != "" {
		a.Patches = append(a.Patches, addVolumes(
			a.Pod.Spec.Volumes,
			[]corev1.Volume{a.ContainerExtraSecretVolume()},
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
			a.ContainerVolumeMounts(),
			fmt.Sprintf("/spec/containers/%d/volumeMounts", i))...)
	}

	// Init Container
	if a.PrePopulate {
		container, err := a.ContainerInitSidecar()
		if err != nil {
			return patches, err
		}

		containers := a.Pod.Spec.InitContainers

		// Init Containers run sequentially in Kubernetes and sometimes the order in
		// which they run matters.  This reorders the init containers to put the agent first.
		// For example, if an init container needed Vault secrets to work, the agent would need
		// to run first.
		if a.InitFirst {

			// Remove all init containers from the document so we can re-add them after the agent.
			if len(a.Pod.Spec.InitContainers) != 0 {
				a.Patches = append(a.Patches, removeContainers("/spec/initContainers")...)
			}

			containers = []corev1.Container{container}
			containers = append(containers, a.Pod.Spec.InitContainers...)

			a.Patches = append(a.Patches, addContainers(
				[]corev1.Container{},
				containers,
				"/spec/initContainers")...)
		} else {
			a.Patches = append(a.Patches, addContainers(
				a.Pod.Spec.InitContainers,
				[]corev1.Container{container},
				"/spec/initContainers")...)
		}

		//Add Volume Mounts
		for i, container := range containers {
			if container.Name == "vault-agent-init" {
				continue
			}
			a.Patches = append(a.Patches, addVolumeMounts(
				container.VolumeMounts,
				a.ContainerVolumeMounts(),
				fmt.Sprintf("/spec/initContainers/%d/volumeMounts", i))...)
		}
	}

	// Sidecar Container
	if !a.PrePopulateOnly {
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
	a.Patches = append(a.Patches, updateAnnotations(
		a.Pod.Annotations,
		map[string]string{AnnotationAgentStatus: "injected"})...)

	// Generate the patch
	if len(a.Patches) > 0 {
		var err error
		patches, err = json.Marshal(a.Patches)
		if err != nil {
			return patches, err
		}
	}
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

	if a.ConfigMapName == "" {
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

func (a *Agent) vaultCliFlags() []string {
	flags := []string{
		fmt.Sprintf("-address=%s", a.Vault.Address),
	}

	if a.Vault.CACert != "" {
		flags = append(flags, fmt.Sprintf("-ca-cert=%s", a.Vault.CACert))
	}

	if a.Vault.ClientCert != "" {
		flags = append(flags, fmt.Sprintf("-client-cert=%s", a.Vault.ClientCert))
	}

	if a.Vault.ClientKey != "" {
		flags = append(flags, fmt.Sprintf("-client-key=%s", a.Vault.ClientKey))
	}

	return flags
}

// copyVolumeMounts copies the specified container or init container's volume mounts.
// Ignores any Kubernetes service account token mounts.
func (a *Agent) copyVolumeMounts(targetContainerName string) []corev1.VolumeMount {
	// Deep copy the pod spec so append doesn't mutate the original containers slice
	podSpec := a.Pod.Spec.DeepCopy()
	copiedVolumeMounts := make([]corev1.VolumeMount, 0)
	for _, container := range append(podSpec.Containers, podSpec.InitContainers...) {
		if container.Name == targetContainerName {
			for _, volumeMount := range container.VolumeMounts {
				if !strings.Contains(strings.ToLower(volumeMount.MountPath), "serviceaccount") {
					copiedVolumeMounts = append(copiedVolumeMounts, volumeMount)
				}
			}
		}
	}
	return copiedVolumeMounts
}
