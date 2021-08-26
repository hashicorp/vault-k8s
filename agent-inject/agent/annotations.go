package agent

import (
	"fmt"
	"path"
	"strconv"
	"strings"

	"github.com/pkg/errors"
	corev1 "k8s.io/api/core/v1"
)

const (
	// AnnotationAgentStatus is the key of the annotation that is added to
	// a pod after an injection is done.
	// There's only one valid status we care about: "injected".
	AnnotationAgentStatus = "vault.hashicorp.com/agent-inject-status"

	// AnnotationAgentInject is the key of the annotation that controls whether
	// injection is explicitly enabled or disabled for a pod. This should
	// be set to a true or false value, as parseable by strconv.ParseBool
	AnnotationAgentInject = "vault.hashicorp.com/agent-inject"

	// AnnotationAgentInjectSecret is the key annotation that configures Vault
	// Agent to retrieve the secrets from Vault required by the app.  The name
	// of the secret is any unique string after "vault.hashicorp.com/agent-inject-secret-",
	// such as "vault.hashicorp.com/agent-inject-secret-foobar".  The value is the
	// path in Vault where the secret is located.
	AnnotationAgentInjectSecret = "vault.hashicorp.com/agent-inject-secret"

	// AnnotationAgentInjectFile is the key of the annotation that contains the
	// name (and optional path) of the file to create on disk. The name of the
	// secret is the string after "vault.hashicorp.com/agent-inject-file-", and
	// should map to the same unique value provided in
	// "vault.hashicorp.com/agent-inject-secret-". The value is the filename and
	// path in the secrets volume where the vault secret will be written. The
	// container mount path of the secrets volume may be modified with the
	// secret-volume-path annotation.
	AnnotationAgentInjectFile = "vault.hashicorp.com/agent-inject-file"

	// AnnotationAgentInjectFilePermission is the key of the annotation that contains the
	// permission of the file to create on disk. The name of the
	// secret is the string after "vault.hashicorp.com/agent-inject-perms-", and
	// should map to the same unique value provided in
	// "vault.hashicorp.com/agent-inject-secret-". The value is the value of the permission, for
	// example "0644"
	AnnotationAgentInjectFilePermission = "vault.hashicorp.com/agent-inject-perms"

	// AnnotationAgentInjectTemplate is the key annotation that configures Vault
	// Agent what template to use for rendering the secrets.  The name
	// of the template is any unique string after "vault.hashicorp.com/agent-inject-template-",
	// such as "vault.hashicorp.com/agent-inject-template-foobar".  This should map
	// to the same unique value provided in "vault.hashicorp.com/agent-inject-secret-".
	// If not provided, a default generic template is used.
	AnnotationAgentInjectTemplate = "vault.hashicorp.com/agent-inject-template"

	// AnnotationAgentInjectDefaultTemplate sets the default template type. Possible values
	// are "json" and "map".
	AnnotationAgentInjectDefaultTemplate = "vault.hashicorp.com/agent-inject-default-template"

	// AnnotationAgentInjectTemplateFile is the optional key annotation that configures Vault
	// Agent what template on disk to use for rendering the secrets.  The name
	// of the template is any unique string after "vault.hashicorp.com/agent-inject-template-file-",
	// such as "vault.hashicorp.com/agent-inject-template-file-foobar".  This should map
	// to the same unique value provided in "vault.hashicorp.com/agent-inject-secret-".
	// The value is the filename and path of the template used by the agent to render the secrets.
	// If not provided, the template content key annotation is used.
	AnnotationAgentInjectTemplateFile = "vault.hashicorp.com/agent-inject-template-file"

	// AnnotationAgentInjectToken is the annotation key for injecting the
	// auto-auth token into the secrets volume (e.g. /vault/secrets/token)
	AnnotationAgentInjectToken = "vault.hashicorp.com/agent-inject-token"

	// AnnotationAgentInjectCommand is the key annotation that configures Vault Agent
	// to run a command after the secret is rendered. The name of the template is any
	// unique string after "vault.hashicorp.com/agent-inject-command-". This should map
	// to the same unique value provided in "vault.hashicorp.com/agent-inject-secret-".
	// If not provided (the default), no command is executed.
	AnnotationAgentInjectCommand = "vault.hashicorp.com/agent-inject-command"

	// AnnotationAgentImage is the name of the Vault docker image to use.
	AnnotationAgentImage = "vault.hashicorp.com/agent-image"

	// AnnotationAgentRequestNamespace is the Kubernetes namespace where the request
	// originated from.
	AnnotationAgentRequestNamespace = "vault.hashicorp.com/agent-request-namespace"

	// AnnotationAgentInitFirst makes the initialization container the first container
	// to run when a pod starts. Default is last.
	AnnotationAgentInitFirst = "vault.hashicorp.com/agent-init-first"

	// AnnotationAgentPrePopulate controls whether an init container is included
	// to pre-populate the shared memory volume with secrets prior to the application
	// starting.
	AnnotationAgentPrePopulate = "vault.hashicorp.com/agent-pre-populate"

	// AnnotationAgentPrePopulateOnly controls whether an init container is the only
	// injected container.  If true, no sidecar container will be injected at runtime
	// of the application.
	AnnotationAgentPrePopulateOnly = "vault.hashicorp.com/agent-pre-populate-only"

	// AnnotationAgentConfigMap is the name of the configuration map where Vault Agent
	// configuration file and templates can be found.
	AnnotationAgentConfigMap = "vault.hashicorp.com/agent-configmap"

	// AnnotationAgentExtraSecret is the name of a Kubernetes secret that will be mounted
	// into the Vault agent container so that the agent config can reference secrets.
	AnnotationAgentExtraSecret = "vault.hashicorp.com/agent-extra-secret"

	// AnnotationAgentLimitsCPU sets the CPU limit on the Vault Agent containers.
	AnnotationAgentLimitsCPU = "vault.hashicorp.com/agent-limits-cpu"

	// AnnotationAgentLimitsMem sets the memory limit on the Vault Agent containers.
	AnnotationAgentLimitsMem = "vault.hashicorp.com/agent-limits-mem"

	// AnnotationAgentRequestsCPU sets the requested CPU amount on the Vault Agent containers.
	AnnotationAgentRequestsCPU = "vault.hashicorp.com/agent-requests-cpu"

	// AnnotationAgentRequestsMem sets the requested memory amount on the Vault Agent containers.
	AnnotationAgentRequestsMem = "vault.hashicorp.com/agent-requests-mem"

	// AnnotationAgentRevokeOnShutdown controls whether a sidecar container will revoke its
	// own Vault token before shutting down. If you are using a custom agent template, you must
	// make sure it's written to `/home/vault/.vault-token`. Only supported for sidecar containers.
	AnnotationAgentRevokeOnShutdown = "vault.hashicorp.com/agent-revoke-on-shutdown"

	// AnnotationAgentRevokeGrace sets the number of seconds after receiving the signal for pod
	// termination that the container will attempt to revoke its own Vault token. Defaults to 5s.
	AnnotationAgentRevokeGrace = "vault.hashicorp.com/agent-revoke-grace"

	// AnnotationVaultNamespace is the Vault namespace where secrets can be found.
	AnnotationVaultNamespace = "vault.hashicorp.com/namespace"

	// AnnotationAgentRunAsUser sets the User ID to run the Vault Agent containers as.
	AnnotationAgentRunAsUser = "vault.hashicorp.com/agent-run-as-user"

	// AnnotationAgentRunAsGroup sets the Group ID to run the Vault Agent containers as.
	AnnotationAgentRunAsGroup = "vault.hashicorp.com/agent-run-as-group"

	// AnnotationAgentRunAsSameUser sets the User ID of the injected Vault Agent
	// containers to the User ID of the first application container in the Pod.
	// Requires Spec.Containers[0].SecurityContext.RunAsUser to be set in the
	// Pod Spec.
	AnnotationAgentRunAsSameUser = "vault.hashicorp.com/agent-run-as-same-user"

	// AnnotationAgentSetSecurityContext controls whether a SecurityContext (uid
	// and gid) is set on the injected Vault Agent containers
	AnnotationAgentSetSecurityContext = "vault.hashicorp.com/agent-set-security-context"

	// AnnotationAgentServiceAccountTokenVolumeName is the optional name of a volume containing a
	// service account token
	AnnotationAgentServiceAccountTokenVolumeName = "vault.hashicorp.com/agent-service-account-token-volume-name"

	// AnnotationVaultService is the name of the Vault server.  This can be overridden by the
	// user but will be set by a flag on the deployment.
	AnnotationVaultService = "vault.hashicorp.com/service"

	// AnnotationProxyAddress is the HTTP proxy to use when talking to the Vault server.
	AnnotationProxyAddress = "vault.hashicorp.com/proxy-address"

	// AnnotationVaultTLSSkipVerify allows users to configure verifying TLS
	// when communicating with Vault.
	AnnotationVaultTLSSkipVerify = "vault.hashicorp.com/tls-skip-verify"

	// AnnotationVaultTLSSecret is the name of the Kubernetes secret containing
	// client TLS certificates and keys.
	AnnotationVaultTLSSecret = "vault.hashicorp.com/tls-secret"

	// AnnotationVaultTLSServerName is the name of the Vault server to verify the
	// authenticity of the server when communicating with Vault over TLS.
	AnnotationVaultTLSServerName = "vault.hashicorp.com/tls-server-name"

	// AnnotationVaultCACert is the path of the CA certificate used to verify Vault's
	// CA certificate.
	AnnotationVaultCACert = "vault.hashicorp.com/ca-cert"

	// AnnotationVaultCAKey is the path of the CA key used to verify Vault's CA.
	AnnotationVaultCAKey = "vault.hashicorp.com/ca-key"

	// AnnotationVaultClientCert is the path of the client certificate used to communicate
	// with Vault over TLS.
	AnnotationVaultClientCert = "vault.hashicorp.com/client-cert"

	// AnnotationVaultClientKey is the path of the client key used to communicate
	// with Vault over TLS.
	AnnotationVaultClientKey = "vault.hashicorp.com/client-key"

	// AnnotationVaultClientMaxRetries is the number of retry attempts when 5xx errors are encountered.
	AnnotationVaultClientMaxRetries = "vault.hashicorp.com/client-max-retries"

	// AnnotationVaultClientTimeout sets the request timeout when communicating with Vault.
	AnnotationVaultClientTimeout = "vault.hashicorp.com/client-timeout"

	// AnnotationVaultLogLevel sets the Vault Agent log level.
	AnnotationVaultLogLevel = "vault.hashicorp.com/log-level"

	// AnnotationVaultLogFormat sets the Vault Agent log format.
	AnnotationVaultLogFormat = "vault.hashicorp.com/log-format"

	// AnnotationVaultRole specifies the role to be used for the Kubernetes auto-auth
	// method.
	AnnotationVaultRole = "vault.hashicorp.com/role"

	// AnnotationVaultAuthType specifies the auto-auth method type to be used.
	AnnotationVaultAuthType = "vault.hashicorp.com/auth-type"

	// AnnotationVaultAuthPath specifies the mount path to be used for the auto-auth method.
	AnnotationVaultAuthPath = "vault.hashicorp.com/auth-path"

	// AnnotationVaultAuthConfig specifies the Auto Auth Method configuration parameters.
	// The name of the parameter is any unique string after "vault.hashicorp.com/auth-config-",
	// such as "vault.hashicorp.com/auth-config-foobar".
	AnnotationVaultAuthConfig = "vault.hashicorp.com/auth-config"

	// AnnotationVaultSecretVolumePath specifies where the secrets are to be
	// Mounted after fetching.
	AnnotationVaultSecretVolumePath = "vault.hashicorp.com/secret-volume-path"

	// AnnotationPreserveSecretCase if enabled will preserve the case of secret name
	// by default the name is converted to lower case.
	AnnotationPreserveSecretCase = "vault.hashicorp.com/preserve-secret-case"

	// AnnotationAgentCacheEnable if enabled will configure the sidecar container
	// to enable agent caching
	AnnotationAgentCacheEnable = "vault.hashicorp.com/agent-cache-enable"

	// AnnotationAgentCacheUseAutoAuthToken configures the agent cache to use the
	// auto auth token or not. Can be set to "force" to force usage of the auto-auth token
	AnnotationAgentCacheUseAutoAuthToken = "vault.hashicorp.com/agent-cache-use-auto-auth-token"

	// AnnotationAgentCacheListenerPort configures the port the agent cache should listen on
	AnnotationAgentCacheListenerPort = "vault.hashicorp.com/agent-cache-listener-port"

	// AnnotationAgentCacheExitOnErr configures whether the agent will exit on an
	// error while restoring the persistent cache
	AnnotationAgentCacheExitOnErr = "vault.hashicorp.com/agent-cache-exit-on-err"

	// AnnotationAgentCopyVolumeMounts is the name of the container or init container
	// in the Pod whose volume mounts should be copied onto the Vault Agent init and
	// sidecar containers. Ignores any Kubernetes service account token mounts.
	AnnotationAgentCopyVolumeMounts = "vault.hashicorp.com/agent-copy-volume-mounts"

	// AnnotationTemplateConfigExitOnRetryFailure configures whether agent
	// will exit on template render failures once it has exhausted all its retry
	// attempts. Defaults to true.
	AnnotationTemplateConfigExitOnRetryFailure = "vault.hashicorp.com/template-config-exit-on-retry-failure"

	// AnnotationTemplateConfigStaticSecretRenderInterval
	// If specified, configures how often Vault Agent Template should render non-leased secrets such as KV v2.
	// Defaults to 5 minutes.
	AnnotationTemplateConfigStaticSecretRenderInterval = "vault.hashicorp.com/template-static-secret-render-interval"
)

type AgentConfig struct {
	Image                      string
	Address                    string
	AuthType                   string
	AuthPath                   string
	Namespace                  string
	RevokeOnShutdown           bool
	UserID                     string
	GroupID                    string
	SameID                     bool
	SetSecurityContext         bool
	ProxyAddress               string
	DefaultTemplate            string
	ResourceRequestCPU         string
	ResourceRequestMem         string
	ResourceLimitCPU           string
	ResourceLimitMem           string
	ExitOnRetryFailure         bool
	StaticSecretRenderInterval string
}

// Init configures the expected annotations required to create a new instance
// of Agent.  This should be run before running new to ensure all annotations are
// present.
func Init(pod *corev1.Pod, cfg AgentConfig) error {
	var securityContextIsSet bool
	var runAsUserIsSet bool
	var runAsSameUserIsSet bool
	var runAsGroupIsSet bool

	if pod == nil {
		return errors.New("pod is empty")
	}

	if cfg.Address == "" {
		return errors.New("address for Vault required")
	}

	if cfg.AuthPath == "" {
		return errors.New("Vault Auth Path required")
	}

	if cfg.Namespace == "" {
		return errors.New("kubernetes namespace required")
	}

	if pod.ObjectMeta.Annotations == nil {
		pod.ObjectMeta.Annotations = make(map[string]string)
	}

	if _, ok := pod.ObjectMeta.Annotations[AnnotationVaultService]; !ok {
		pod.ObjectMeta.Annotations[AnnotationVaultService] = cfg.Address
	}

	if _, ok := pod.ObjectMeta.Annotations[AnnotationVaultAuthType]; !ok {
		if cfg.AuthType == "" {
			cfg.AuthType = DefaultVaultAuthType
		}
		pod.ObjectMeta.Annotations[AnnotationVaultAuthType] = cfg.AuthType
	}

	if _, ok := pod.ObjectMeta.Annotations[AnnotationVaultAuthPath]; !ok {
		pod.ObjectMeta.Annotations[AnnotationVaultAuthPath] = cfg.AuthPath
	}

	if _, ok := pod.ObjectMeta.Annotations[AnnotationProxyAddress]; !ok {
		pod.ObjectMeta.Annotations[AnnotationProxyAddress] = cfg.ProxyAddress
	}

	if _, ok := pod.ObjectMeta.Annotations[AnnotationAgentImage]; !ok {
		if cfg.Image == "" {
			cfg.Image = DefaultVaultImage
		}
		pod.ObjectMeta.Annotations[AnnotationAgentImage] = cfg.Image
	}

	if _, ok := pod.ObjectMeta.Annotations[AnnotationAgentRequestNamespace]; !ok {
		pod.ObjectMeta.Annotations[AnnotationAgentRequestNamespace] = cfg.Namespace
	}

	if _, ok := pod.ObjectMeta.Annotations[AnnotationAgentLimitsCPU]; !ok {
		pod.ObjectMeta.Annotations[AnnotationAgentLimitsCPU] = cfg.ResourceLimitCPU
	}

	if _, ok := pod.ObjectMeta.Annotations[AnnotationAgentLimitsMem]; !ok {
		pod.ObjectMeta.Annotations[AnnotationAgentLimitsMem] = cfg.ResourceLimitMem
	}

	if _, ok := pod.ObjectMeta.Annotations[AnnotationAgentRequestsCPU]; !ok {
		pod.ObjectMeta.Annotations[AnnotationAgentRequestsCPU] = cfg.ResourceRequestCPU
	}

	if _, ok := pod.ObjectMeta.Annotations[AnnotationAgentRequestsMem]; !ok {
		pod.ObjectMeta.Annotations[AnnotationAgentRequestsMem] = cfg.ResourceRequestMem
	}

	if _, ok := pod.ObjectMeta.Annotations[AnnotationVaultSecretVolumePath]; !ok {
		pod.ObjectMeta.Annotations[AnnotationVaultSecretVolumePath] = secretVolumePath
	}

	if _, ok := pod.ObjectMeta.Annotations[AnnotationAgentRevokeOnShutdown]; !ok {
		pod.ObjectMeta.Annotations[AnnotationAgentRevokeOnShutdown] = strconv.FormatBool(cfg.RevokeOnShutdown)
	}

	if _, ok := pod.ObjectMeta.Annotations[AnnotationAgentRevokeGrace]; !ok {
		pod.ObjectMeta.Annotations[AnnotationAgentRevokeGrace] = strconv.Itoa(DefaultRevokeGrace)
	}

	if _, ok := pod.ObjectMeta.Annotations[AnnotationVaultLogLevel]; !ok {
		pod.ObjectMeta.Annotations[AnnotationVaultLogLevel] = DefaultAgentLogLevel
	}

	if _, ok := pod.ObjectMeta.Annotations[AnnotationVaultLogFormat]; !ok {
		pod.ObjectMeta.Annotations[AnnotationVaultLogFormat] = DefaultAgentLogFormat
	}

	if _, ok := pod.ObjectMeta.Annotations[AnnotationAgentServiceAccountTokenVolumeName]; !ok {
		pod.ObjectMeta.Annotations[AnnotationAgentServiceAccountTokenVolumeName] = ""
	}

	if _, securityContextIsSet = pod.ObjectMeta.Annotations[AnnotationAgentSetSecurityContext]; !securityContextIsSet {
		pod.ObjectMeta.Annotations[AnnotationAgentSetSecurityContext] = strconv.FormatBool(cfg.SetSecurityContext)
	}

	if _, runAsUserIsSet = pod.ObjectMeta.Annotations[AnnotationAgentRunAsUser]; !runAsUserIsSet {

		if cfg.UserID == "" {
			cfg.UserID = strconv.Itoa(DefaultAgentRunAsUser)
		}
		pod.ObjectMeta.Annotations[AnnotationAgentRunAsUser] = cfg.UserID
	}

	if _, runAsSameUserIsSet = pod.ObjectMeta.Annotations[AnnotationAgentRunAsSameUser]; !runAsSameUserIsSet {
		pod.ObjectMeta.Annotations[AnnotationAgentRunAsSameUser] = strconv.FormatBool(cfg.SameID)
	}

	if _, runAsGroupIsSet = pod.ObjectMeta.Annotations[AnnotationAgentRunAsGroup]; !runAsGroupIsSet {
		if cfg.GroupID == "" {
			cfg.GroupID = strconv.Itoa(DefaultAgentRunAsGroup)
		}
		pod.ObjectMeta.Annotations[AnnotationAgentRunAsGroup] = cfg.GroupID
	}

	// If the SetSecurityContext startup option is false, and the analogous
	// annotation isn't set, but one of the user or group annotations is set,
	// flip SetSecurityContext to true so that the user and group options are
	// set in the containers.
	if !cfg.SetSecurityContext && !securityContextIsSet && (runAsUserIsSet || runAsSameUserIsSet || runAsGroupIsSet) {
		pod.ObjectMeta.Annotations[AnnotationAgentSetSecurityContext] = strconv.FormatBool(true)
	}

	if _, ok := pod.ObjectMeta.Annotations[AnnotationAgentCacheEnable]; !ok {
		pod.ObjectMeta.Annotations[AnnotationAgentCacheEnable] = DefaultAgentCacheEnable
	}

	if _, ok := pod.ObjectMeta.Annotations[AnnotationAgentCacheListenerPort]; !ok {
		pod.ObjectMeta.Annotations[AnnotationAgentCacheListenerPort] = DefaultAgentCacheListenerPort
	}

	if _, ok := pod.ObjectMeta.Annotations[AnnotationAgentCacheUseAutoAuthToken]; !ok {
		pod.ObjectMeta.Annotations[AnnotationAgentCacheUseAutoAuthToken] = DefaultAgentCacheUseAutoAuthToken
	}

	if _, ok := pod.ObjectMeta.Annotations[AnnotationAgentCacheExitOnErr]; !ok {
		pod.ObjectMeta.Annotations[AnnotationAgentCacheExitOnErr] = strconv.FormatBool(DefaultAgentCacheExitOnErr)
	}

	if _, ok := pod.ObjectMeta.Annotations[AnnotationAgentInjectDefaultTemplate]; !ok {
		pod.ObjectMeta.Annotations[AnnotationAgentInjectDefaultTemplate] = cfg.DefaultTemplate
	}

	if _, ok := pod.ObjectMeta.Annotations[AnnotationTemplateConfigExitOnRetryFailure]; !ok {
		pod.ObjectMeta.Annotations[AnnotationTemplateConfigExitOnRetryFailure] = strconv.FormatBool(cfg.ExitOnRetryFailure)
	}
	if _, ok := pod.ObjectMeta.Annotations[AnnotationTemplateConfigStaticSecretRenderInterval]; !ok {
		pod.ObjectMeta.Annotations[AnnotationTemplateConfigStaticSecretRenderInterval] = cfg.StaticSecretRenderInterval
	}

	return nil
}

// secrets parses annotations with the pattern "vault.hashicorp.com/agent-inject-secret-".
// Everything following the final dash becomes the name of the secret, and the
// value is the path in Vault. This method also matches and returns the
// Template, Command, and FilePathAndName settings from annotations associated
// with a secret name.
//
// For example: "vault.hashicorp.com/agent-inject-secret-foobar: db/creds/foobar"
// Name: foobar, Path: db/creds/foobar
func (a *Agent) secrets() []*Secret {
	var secrets []*Secret

	for name, path := range a.Annotations {
		secretName := fmt.Sprintf("%s-", AnnotationAgentInjectSecret)
		if strings.Contains(name, secretName) {
			raw := strings.ReplaceAll(name, secretName, "")
			name := raw

			if ok, _ := a.preserveSecretCase(raw); !ok {
				name = strings.ToLower(raw)
			}

			if name == "" {
				continue
			}

			s := &Secret{Name: name, Path: path}

			templateName := fmt.Sprintf("%s-%s", AnnotationAgentInjectTemplate, raw)
			if val, ok := a.Annotations[templateName]; ok {
				s.Template = val
			}
			if s.Template == "" {
				templateFileAnnotation := fmt.Sprintf("%s-%s", AnnotationAgentInjectTemplateFile, raw)
				if val, ok := a.Annotations[templateFileAnnotation]; ok {
					s.TemplateFile = val
				}
			}

			s.MountPath = a.Annotations[AnnotationVaultSecretVolumePath]
			mountPathAnnotationName := fmt.Sprintf("%s-%s", AnnotationVaultSecretVolumePath, raw)
			if val, ok := a.Annotations[mountPathAnnotationName]; ok {
				s.MountPath = val
			}

			commandName := fmt.Sprintf("%s-%s", AnnotationAgentInjectCommand, raw)
			if val, ok := a.Annotations[commandName]; ok {
				s.Command = val
			}

			file := fmt.Sprintf("%s-%s", AnnotationAgentInjectFile, raw)
			if val, ok := a.Annotations[file]; ok {
				s.FilePathAndName = val
			}

			filePerm := fmt.Sprintf("%s-%s", AnnotationAgentInjectFilePermission, raw)
			if val, ok := a.Annotations[filePerm]; ok {
				s.FilePermission = val
			}

			secrets = append(secrets, s)
		}
	}
	return secrets
}

func (a *Agent) inject() (bool, error) {
	raw, ok := a.Annotations[AnnotationAgentInject]
	if !ok {
		return true, nil
	}

	return strconv.ParseBool(raw)
}

func (a *Agent) initFirst() (bool, error) {
	raw, ok := a.Annotations[AnnotationAgentInitFirst]
	if !ok {
		return false, nil
	}

	return strconv.ParseBool(raw)
}

func (a *Agent) prePopulate() (bool, error) {
	raw, ok := a.Annotations[AnnotationAgentPrePopulate]
	if !ok {
		return true, nil
	}

	return strconv.ParseBool(raw)
}

func (a *Agent) prePopulateOnly() (bool, error) {
	raw, ok := a.Annotations[AnnotationAgentPrePopulateOnly]
	if !ok {
		return false, nil
	}

	return strconv.ParseBool(raw)
}

func (a *Agent) revokeOnShutdown() (bool, error) {
	raw, ok := a.Annotations[AnnotationAgentRevokeOnShutdown]
	if !ok {
		return false, nil
	}

	return strconv.ParseBool(raw)
}

func (a *Agent) revokeGrace() (uint64, error) {
	raw, ok := a.Annotations[AnnotationAgentRevokeGrace]
	if !ok {
		return 0, nil
	}

	return strconv.ParseUint(raw, 10, 64)
}

func (a *Agent) tlsSkipVerify() (bool, error) {
	raw, ok := a.Annotations[AnnotationVaultTLSSkipVerify]
	if !ok {
		return false, nil
	}

	return strconv.ParseBool(raw)
}

func (a *Agent) preserveSecretCase(secretName string) (bool, error) {

	preserveSecretCaseAnnotationName := fmt.Sprintf("%s-%s", AnnotationPreserveSecretCase, secretName)

	var raw string

	if val, ok := a.Annotations[preserveSecretCaseAnnotationName]; ok {
		raw = val
	} else {
		raw, ok = a.Annotations[AnnotationPreserveSecretCase]
		if !ok {
			return false, nil
		}
	}
	return strconv.ParseBool(raw)
}

func (a *Agent) runAsSameID(pod *corev1.Pod) (bool, error) {
	raw, ok := a.Annotations[AnnotationAgentRunAsSameUser]
	if !ok {
		return DefaultAgentRunAsSameUser, nil
	}
	runAsSameID, err := strconv.ParseBool(raw)
	if err != nil {
		return DefaultAgentRunAsSameUser, err
	}
	if runAsSameID {
		if len(pod.Spec.Containers) == 0 {
			return DefaultAgentRunAsSameUser, errors.New("No containers found in Pod Spec")
		}
		if pod.Spec.Containers[0].SecurityContext == nil {
			return DefaultAgentRunAsSameUser, errors.New("No SecurityContext found for Container 0")
		}
		if pod.Spec.Containers[0].SecurityContext.RunAsUser == nil {
			return DefaultAgentRunAsSameUser, errors.New("RunAsUser is nil for Container 0's SecurityContext")
		}
		if *pod.Spec.Containers[0].SecurityContext.RunAsUser == 0 {
			return DefaultAgentRunAsSameUser, errors.New("container not allowed to run as root")
		}
		a.RunAsUser = *pod.Spec.Containers[0].SecurityContext.RunAsUser
	}
	return runAsSameID, nil
}

func (a *Agent) setSecurityContext() (bool, error) {
	raw, ok := a.Annotations[AnnotationAgentSetSecurityContext]
	if !ok {
		return DefaultAgentSetSecurityContext, nil
	}

	return strconv.ParseBool(raw)
}

func (a *Agent) cacheEnable() (bool, error) {
	raw, ok := a.Annotations[AnnotationAgentCacheEnable]
	if !ok {
		return false, nil
	}

	return strconv.ParseBool(raw)
}

func (a *Agent) templateConfigExitOnRetryFailure() (bool, error) {
	raw, ok := a.Annotations[AnnotationTemplateConfigExitOnRetryFailure]
	if !ok {
		return DefaultTemplateConfigExitOnRetryFailure, nil
	}

	return strconv.ParseBool(raw)
}

func (a *Agent) cachePersist(cacheEnabled bool) bool {
	if cacheEnabled && a.PrePopulate && !a.PrePopulateOnly {
		return true
	}
	return false
}

func (a *Agent) cacheExitOnErr() (bool, error) {
	raw, ok := a.Annotations[AnnotationAgentCacheExitOnErr]
	if !ok {
		return false, nil
	}

	return strconv.ParseBool(raw)
}

func (a *Agent) injectToken() (bool, error) {
	raw, ok := a.Annotations[AnnotationAgentInjectToken]
	if !ok {
		return DefaultAgentInjectToken, nil
	}
	return strconv.ParseBool(raw)
}

func (a *Agent) authConfig() map[string]interface{} {
	authConfig := make(map[string]interface{})

	prefix := fmt.Sprintf("%s-", AnnotationVaultAuthConfig)
	for annotation, value := range a.Annotations {
		if strings.HasPrefix(annotation, prefix) {
			param := strings.TrimPrefix(annotation, prefix)
			param = strings.ReplaceAll(param, "-", "_")
			authConfig[param] = value
		}
	}
	if a.Vault.Role != "" {
		authConfig["role"] = a.Vault.Role
	}

	if a.ServiceAccountTokenVolume.MountPath != "" && a.ServiceAccountTokenVolume.TokenPath != "" {
		authConfig["token_path"] = path.Join(a.ServiceAccountTokenVolume.MountPath, a.ServiceAccountTokenVolume.TokenPath)
	}

	return authConfig
}
