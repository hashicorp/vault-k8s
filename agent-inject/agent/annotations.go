package agent

import (
	"encoding/base64"
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

	// AnnotationIstioInitInject is the key of annotation that control whether
	// injection is enabled or disabled. Should be set to true or false value
	AnnotationIstioInitInject = "sidecar.istio.io/inject"

	AnnotationIstioInitStatus = "sidecar.istio.io/init-container-status"

	// AnnotationAgentInjectSecret is the key annotation that configures Vault
	// Agent to retrieve the secrets from Vault required by the app.  The name
	// of the secret is any unique string after "vault.hashicorp.com/agent-inject-secret-",
	// such as "vault.hashicorp.com/agent-inject-secret-foobar".  The value is the
	// path in Vault where the secret is located.
	AnnotationAgentInjectSecret = "vault.hashicorp.com/agent-inject-secret"

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

	// AnnotationAgentLimitsCPU sets the CPU limit on the Vault Agent containers.
	AnnotationAgentLimitsCPU = "vault.hashicorp.com/agent-limits-cpu"

	// AnnotationAgentLimitsMem sets the memory limit on the Vault Agent containers.
	AnnotationAgentLimitsMem = "vault.hashicorp.com/agent-limits-mem"

	// AnnotationAgentRequestsCPU sets the requested CPU amount on the Vault Agent containers.
	AnnotationAgentRequestsCPU = "vault.hashicorp.com/agent-requests-cpu"

	// AnnotationAgentRequestsMem sets the requested memory amount on the Vault Agent containers.
	AnnotationAgentRequestsMem = "vault.hashicorp.com/agent-requests-mem"

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

	// AnnotationVaultRole specifies the role to be used for the Kubernetes auto-auth
	// method.
	AnnotationVaultRole = "vault.hashicorp.com/role"

	// AnnotationVaultAuthPath specifies the mount path to be used for the Kubernetes auto-auth
	// method.
	AnnotationVaultAuthPath = "vault.hashicorp.com/auth-path"

	// AnnotationPlutonInfluxUrl specifies the InfluxDB URL
	AnnotationPlutonInfluxUrl = "pluton.tiki.vn/influxdb-url"
	AnnotationPlutonInjectEnv = "pluton.tiki.vn/inject-env"

	// AnnotationPlutonInject specifies whether pluton sidecar injected with higer priority than AnnotationAgentInject
	AnnotationPlutonInject = "pluton.tiki.vn/agent-inject"

	AnnotationAgentInjectStructure = "vault.hashicorp.com/agent-inject-structure"
	AnnotationAgentInjectMode      = "vault.hashicorp.com/agent-inject-mode"
	AnnotationMainEntrypoint       = "vault.hashicorp.com/main-entrypoint"
	AnnotationMainConfig           = "vault.hashicorp.com/main-config"
)

// Init configures the expected annotations required to create a new instance
// of Agent.  This should be run before running new to ensure all annotations are
// present.
func Init(pod *corev1.Pod, image, address, authPath, namespace string) error {
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

	if _, ok := pod.ObjectMeta.Annotations[AnnotationPlutonInfluxUrl]; !ok {
		pod.ObjectMeta.Annotations[AnnotationPlutonInfluxUrl] = DefaultInfluxdbUrl
	}

	if _, ok := pod.ObjectMeta.Annotations[AnnotationAgentInjectMode]; !ok {
		pod.ObjectMeta.Annotations[AnnotationAgentInjectMode] = DefaultAgentInjectMode
	}

	if _, ok := pod.ObjectMeta.Annotations[AnnotationAgentInjectStructure]; !ok {
		pod.ObjectMeta.Annotations[AnnotationAgentInjectStructure] = DefaultAgentInjectStructure
	}

	return nil
}

// secrets parses annotations with the pattern "vault.hashicorp.com/agent-inject-secret-".
// Everything following the final dash becomes the name of the secret,
// and the value is the path in Vault.
//
// For example: "vault.hashicorp.com/agent-inject-secret-foobar: db/creds/foobar"
// name: foobar, value: db/creds/foobar
func secrets(annotations map[string]string) []*Secret {
	var secrets []*Secret
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

			secrets = append(secrets, &Secret{Name: name, Path: path, Template: template})
		}
	}
	return secrets
}

func plutonEnvs(annotations map[string]string) []*PlutonEnv {
	var plutonEnvs []*PlutonEnv
	for annotationKey, annotationValue := range annotations {
		injectEnv := fmt.Sprintf("%s-", AnnotationPlutonInjectEnv)
		if strings.Contains(annotationKey, injectEnv) {
			envKey := strings.ReplaceAll(annotationKey, injectEnv, "")
			envValue := annotationValue

			plutonEnvs = append(plutonEnvs, &PlutonEnv{Key: envKey, Value: envValue})
		}
	}

	return plutonEnvs
}

func (a *Agent) inject() (bool, error) {
	raw, ok := a.Annotations[AnnotationAgentInject]
	if !ok {
		return false, nil
	}

	return strconv.ParseBool(raw)
}

func (a *Agent) injectPluton() (bool, error) {
	raw, ok := a.Annotations[AnnotationPlutonInject]
	if !ok {
		return false, nil
	}

	return strconv.ParseBool(raw)
}

func (a *Agent) prePopulate() (bool, error) {
	raw, ok := a.Annotations[AnnotationAgentPrePopulate]
	if !ok {
		return false, nil
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

func (a *Agent) tlsSkipVerify() (bool, error) {
	raw, ok := a.Annotations[AnnotationVaultTLSSkipVerify]
	if !ok {
		return false, nil
	}

	return strconv.ParseBool(raw)
}

func (a *Agent) getIstioInitInjectFlag() (bool, error) {
	raw, ok := a.Annotations[AnnotationIstioInitInject]
	if !ok {
		return false, nil
	}

	return strconv.ParseBool(raw)
}

func (a *Agent) getEntrypoint() (string, error) {
	raw, ok := a.Annotations[AnnotationMainEntrypoint]
	if !ok {
		return "", nil
	}
	data, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		fmt.Println("error:", err)
		return "", err
	}

	dataStr := string(data)
	fmt.Printf(dataStr)
	return string(data), nil
}
