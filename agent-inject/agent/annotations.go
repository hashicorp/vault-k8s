package agent

import (
	"fmt"
	"github.com/mattbaird/jsonpatch"
	"github.com/pkg/errors"
	corev1 "k8s.io/api/core/v1"
	"strconv"
	"strings"
)

const (
	// AnnotationAgentStatus is the key of the annotation that is added to
	// a pod after an injection is done.
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
	AnnotationAgentInjectSecret = "vault.hashicorp.com/agent-inject-secret-"

	// AnnotationAgentInjectTemplate is the key annotation that configures Vault
	// Agent what template to use for rendering the secrets.  The name
	// of the template is any unique string after "vault.hashicorp.com/agent-inject-template-",
	// such as "vault.hashicorp.com/agent-inject-template-foobar".  This should map
	// to the same unique value provided in ""vault.hashicorp.com/agent-inject-secret-".
	// If not provided, a default generic template is used.
	AnnotationAgentInjectTemplate = "vault.hashicorp.com/agent-inject-template"

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

	// annotationVaultService is the name of the service to proxy. This defaults
	// to the name of the first container.
	AnnotationVaultService = "vault.hashicorp.com/service"

	// AnnotationVaultTLSSkipVerify allows users to configure verifying TLS
	// when communicating with Vault.
	AnnotationVaultTLSSkipVerify = "vault.hashicorp.com/tls-skip-verify"

	// AnnotationVaultTLSSecret is the n ame of the Kubernetes secret containing
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

	// AnnotationAgentRole specifies the role to be used for the Kubernetes auto-auth
	// method.
	AnnotationVaultRole = "vault.hashicorp.com/role"
)

// DefaultAnnotations are the expected annotations required to create a new instance
// of Agent.  This should be run before running new to ensure all annotations are
// present.
func DefaultAnnotations(pod *corev1.Pod, image, address, namespace string, patches *[]jsonpatch.JsonPatchOperation) error {
	if address == "" {
		return errors.New("address for Vault required")
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

	if _, ok := pod.ObjectMeta.Annotations[AnnotationAgentImage]; !ok {
		if image == "" {
			image = DefaultVaultImage
		}
		pod.ObjectMeta.Annotations[AnnotationAgentImage] = image
	}

	if _, ok := pod.ObjectMeta.Annotations[AnnotationAgentStatus]; !ok {
		pod.ObjectMeta.Annotations[AnnotationAgentStatus] = ""
	}

	if _, ok := pod.ObjectMeta.Annotations[AnnotationAgentRequestNamespace]; !ok {
		pod.ObjectMeta.Annotations[AnnotationAgentRequestNamespace] = namespace
	}

	return nil
}

func (a *Agent) secrets() []Secret {
	var secrets []Secret
	for name, path := range a.Annotations {
		if strings.Contains(name, AnnotationAgentInjectSecret) {
			raw := strings.Replace(name, AnnotationAgentInjectSecret, "", -1)
			name := strings.ToLower(raw)

			var template string
			templateName := fmt.Sprintf("%s-%s", AnnotationAgentInjectTemplate, raw)

			if val, ok := a.Annotations[templateName]; ok {
				template = val
			}

			secrets = append(secrets, Secret{Name: name, Path: path, Template: template})
		}
	}
	return secrets
}

func (a *Agent) inject() (bool, error) {
	if val, ok := a.Annotations[AnnotationAgentInject]; !ok {
		return false, nil
	} else {
		return strconv.ParseBool(val)
	}
}

func (a *Agent) image() string {
	raw, ok := a.Annotations[AnnotationAgentImage]
	if !ok || raw == "" {
		return DefaultVaultImage
	}

	return raw
}

func (a *Agent) namespace() string {
	raw, ok := a.Annotations[AnnotationAgentRequestNamespace]
	if !ok || raw == "" {
		return ""
	}

	return raw
}

func (a *Agent) status() string {
	raw, ok := a.Annotations[AnnotationAgentStatus]
	if !ok || raw == "" {
		return ""
	}

	return raw
}

func (a *Agent) configMap() string {
	raw, ok := a.Annotations[AnnotationAgentConfigMap]
	if !ok || raw == "" {
		return ""
	}

	return raw
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

func (a *Agent) role() string {
	raw, ok := a.Annotations[AnnotationVaultRole]
	if !ok || raw == "" {
		return ""
	}

	return raw
}

func (a *Agent) address() string {
	raw, ok := a.Annotations[AnnotationVaultService]
	if !ok || raw == "" {
		return ""
	}

	return raw
}

func (a *Agent) tlsSkipVerify() (bool, error) {
	raw, ok := a.Annotations[AnnotationVaultTLSSkipVerify]
	if !ok {
		return true, nil
	}
	return strconv.ParseBool(raw)
}

func (a *Agent) tlsSecret() string {
	raw, ok := a.Annotations[AnnotationVaultTLSSecret]
	if !ok || raw == "" {
		return ""
	}

	return raw
}

func (a *Agent) tlsServerName() string {
	raw, ok := a.Annotations[AnnotationVaultTLSServerName]
	if !ok || raw == "" {
		return ""
	}

	return raw
}

func (a *Agent) caCert() string {
	raw, ok := a.Annotations[AnnotationVaultCACert]
	if !ok || raw == "" {
		return ""
	}

	return raw
}

func (a *Agent) caKey() string {
	raw, ok := a.Annotations[AnnotationVaultCAKey]
	if !ok || raw == "" {
		return ""
	}

	return raw
}

func (a *Agent) clientCert() string {
	raw, ok := a.Annotations[AnnotationVaultClientCert]
	if !ok || raw == "" {
		return ""
	}

	return raw
}

func (a *Agent) clientKey() string {
	raw, ok := a.Annotations[AnnotationVaultClientKey]
	if !ok || raw == "" {
		return ""
	}

	return raw
}

func (a *Agent) clientMaxRetries() string {
	raw, ok := a.Annotations[AnnotationVaultClientMaxRetries]
	if !ok || raw == "" {
		return ""
	}

	return raw
}

func (a *Agent) clientTimeout() string {
	raw, ok := a.Annotations[AnnotationVaultClientTimeout]
	if !ok || raw == "" {
		return ""
	}

	return raw
}
