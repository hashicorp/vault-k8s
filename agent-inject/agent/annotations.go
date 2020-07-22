package agent

import (
	"fmt"
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
	// path where the vault secret will be written. The path may either be an
	// absolute location like "/tmp/oreo/my_secret.pem", or a relative path that
	// will be created under the "/vault/secrets/" directory.
	AnnotationAgentInjectFile = "vault.hashicorp.com/agent-inject-file"

	// AnnotationAgentInjectTemplate is the key annotation that configures Vault
	// Agent what template to use for rendering the secrets.  The name
	// of the template is any unique string after "vault.hashicorp.com/agent-inject-template-",
	// such as "vault.hashicorp.com/agent-inject-template-foobar".  This should map
	// to the same unique value provided in "vault.hashicorp.com/agent-inject-secret-".
	// If not provided, a default generic template is used.
	AnnotationAgentInjectTemplate = "vault.hashicorp.com/agent-inject-template"

	// AnnotationAgentInjectToken is the annotation key for injecting the token
	// from auth/token/lookup-self
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

	// AnnotationVaultService is the name of the Vault server.  This can be overridden by the
	// user but will be set by a flag on the deployment.
	AnnotationVaultService = "vault.hashicorp.com/service"

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

	// AnnotationVaultRole specifies the role to be used for the Kubernetes auto-auth
	// method.
	AnnotationVaultRole = "vault.hashicorp.com/role"

	// AnnotationVaultAuthPath specifies the mount path to be used for the Kubernetes auto-auth
	// method.
	AnnotationVaultAuthPath = "vault.hashicorp.com/auth-path"
)

// Init configures the expected annotations required to create a new instance
// of Agent.  This should be run before running new to ensure all annotations are
// present.
func Init(pod *corev1.Pod, image, address, authPath, namespace string, revokeOnShutdown bool) error {
	if pod == nil {
		return errors.New("pod is empty")
	}

	if address == "" {
		return errors.New("address for Vault required")
	}

	if authPath == "" {
		return errors.New("Vault Auth Path required")
	}

	if namespace == "" {
		return errors.New("kubernetes namespace required")
	}

	if pod.ObjectMeta.Annotations == nil {
		pod.ObjectMeta.Annotations = make(map[string]string)
	}

	if _, ok := pod.ObjectMeta.Annotations[AnnotationVaultService]; !ok {
		pod.ObjectMeta.Annotations[AnnotationVaultService] = address
	}

	if _, ok := pod.ObjectMeta.Annotations[AnnotationVaultAuthPath]; !ok {
		pod.ObjectMeta.Annotations[AnnotationVaultAuthPath] = authPath
	}

	if _, ok := pod.ObjectMeta.Annotations[AnnotationAgentImage]; !ok {
		if image == "" {
			image = DefaultVaultImage
		}
		pod.ObjectMeta.Annotations[AnnotationAgentImage] = image
	}

	if _, ok := pod.ObjectMeta.Annotations[AnnotationAgentRequestNamespace]; !ok {
		pod.ObjectMeta.Annotations[AnnotationAgentRequestNamespace] = namespace
	}

	if _, ok := pod.ObjectMeta.Annotations[AnnotationAgentLimitsCPU]; !ok {
		pod.ObjectMeta.Annotations[AnnotationAgentLimitsCPU] = DefaultResourceLimitCPU
	}

	if _, ok := pod.ObjectMeta.Annotations[AnnotationAgentLimitsMem]; !ok {
		pod.ObjectMeta.Annotations[AnnotationAgentLimitsMem] = DefaultResourceLimitMem
	}

	if _, ok := pod.ObjectMeta.Annotations[AnnotationAgentRequestsCPU]; !ok {
		pod.ObjectMeta.Annotations[AnnotationAgentRequestsCPU] = DefaultResourceRequestCPU
	}

	if _, ok := pod.ObjectMeta.Annotations[AnnotationAgentRequestsMem]; !ok {
		pod.ObjectMeta.Annotations[AnnotationAgentRequestsMem] = DefaultResourceRequestMem
	}

	if _, ok := pod.ObjectMeta.Annotations[AnnotationAgentRevokeOnShutdown]; !ok {
		pod.ObjectMeta.Annotations[AnnotationAgentRevokeOnShutdown] = strconv.FormatBool(revokeOnShutdown)
	}

	if _, ok := pod.ObjectMeta.Annotations[AnnotationAgentRevokeGrace]; !ok {
		pod.ObjectMeta.Annotations[AnnotationAgentRevokeGrace] = strconv.Itoa(DefaultRevokeGrace)
	}

	if _, ok := pod.ObjectMeta.Annotations[AnnotationVaultLogLevel]; !ok {
		pod.ObjectMeta.Annotations[AnnotationVaultLogLevel] = DefaultAgentLogLevel
	}

	return nil
}

// secrets parses annotations with the pattern
// "vault.hashicorp.com/agent-inject-secret-". Everything following the final
// dash becomes the name of the secret, and the value is the path in Vault. This
// method also matches and returns the Template, Command, and FilePathAndName
// settings from annotations associated with a secret name.
//
// For example: "vault.hashicorp.com/agent-inject-secret-foobar: db/creds/foobar"
// Name: foobar, Path: db/creds/foobar
func secrets(annotations map[string]string) []*Secret {
	var secrets []*Secret
	// First check for the token-only injection annotation
	if _, found := annotations[AnnotationAgentInjectToken]; found {
		annotations[fmt.Sprintf("%s-%s", AnnotationAgentInjectSecret, "token")] = TokenSecret
		annotations[fmt.Sprintf("%s-%s", AnnotationAgentInjectTemplate, "token")] = TokenTemplate
	}

	for name, path := range annotations {
		secretName := fmt.Sprintf("%s-", AnnotationAgentInjectSecret)
		if strings.Contains(name, secretName) {
			raw := strings.ReplaceAll(name, secretName, "")
			name := strings.ToLower(raw)

			if name == "" {
				continue
			}

			var template string
			templateName := fmt.Sprintf("%s-%s", AnnotationAgentInjectTemplate, raw)

			if val, ok := annotations[templateName]; ok {
				template = val
			}

			var command string
			commandName := fmt.Sprintf("%s-%s", AnnotationAgentInjectCommand, raw)

			if val, ok := annotations[commandName]; ok {
				command = val
			}

			var filePathAndName string
			file := fmt.Sprintf("%s-%s", AnnotationAgentInjectFile, raw)

			if val, ok := annotations[file]; ok {
				filePathAndName = val
			}

			secrets = append(secrets, &Secret{Name: name, Path: path, FilePathAndName: filePathAndName, Template: template, Command: command})
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
