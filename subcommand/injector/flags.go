package injector

import (
	"flag"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-secure-stdlib/tlsutil"
	"github.com/hashicorp/vault-k8s/agent-inject/agent"
	"github.com/hashicorp/vault-k8s/helper/flags"
	"github.com/kelseyhightower/envconfig"
)

const (
	DefaultLogLevel      = "info"
	DefaultLogFormat     = "standard"
	defaultTLSMinVersion = "tls12"
)

// Specification are the supported environment variables, prefixed with
// AGENT_INJECT.  The names of the variables in the struct are split using
// camel case: Specification.VaultAddr = AGENT_INJECT_VAULT_ADDR
type Specification struct {
	// Listen is the AGENT_INJECT_LISTEN environment variable.
	Listen string `split_words:"true" `

	// LogLevel is the AGENT_INJECT_LOG_LEVEL environment variable.
	LogLevel string `split_words:"true"`

	// LogFormat is the AGENT_INJECT_LOG_FORMAT environment variable
	LogFormat string `split_words:"true"`

	// TemplateConfigExitOnRetryFailure is the
	// AGENT_INJECT_TEMPLATE_CONFIG_EXIT_ON_RETRY_FAILURE environment variable.
	TemplateConfigExitOnRetryFailure string `split_words:"true"`

	// TemplateConfigStaticSecretRenderInterval is the
	// AGENT_INJECT_TEMPLATE_STATIC_SECRET_RENDER_INTERVAL environment variable.
	TemplateConfigStaticSecretRenderInterval string `envconfig:"AGENT_INJECT_TEMPLATE_STATIC_SECRET_RENDER_INTERVAL"`

	// TLSAuto is the AGENT_INJECT_TLS_AUTO environment variable.
	TLSAuto string `envconfig:"tls_auto"`

	// TLSAutoHosts is the AGENT_INJECT_TLS_AUTO_HOSTS environment variable.
	TLSAutoHosts string `envconfig:"tls_auto_hosts"`

	// TLSCertFile is the AGENT_INJECT_TLS_CERT_FILE environment variable.
	TLSCertFile string `envconfig:"tls_cert_file"`

	// TLSKeyFile is the AGENT_INJECT_TLS_KEY_FILE environment variable.
	TLSKeyFile string `envconfig:"tls_key_file"`

	// VaultAddr is the AGENT_INJECT_VAULT_ADDR environment variable.
	VaultAddr string `split_words:"true"`

	// ProxyAddr is the AGENT_INJECT_PROXY_ADDR environment variable.
	ProxyAddr string `split_words:"true"`

	// VaultImage is the AGENT_INJECT_VAULT_IMAGE environment variable.
	VaultImage string `split_words:"true"`

	// VaultAuthType is the AGENT_INJECT_VAULT_AUTH_TYPE environment variable.
	VaultAuthType string `split_words:"true"`

	// VaultAuthPath is the AGENT_INJECT_VAULT_AUTH_PATH environment variable.
	VaultAuthPath string `split_words:"true"`

	// RevokeOnShutdown is AGENT_INJECT_REVOKE_ON_SHUTDOWN environment variable.
	RevokeOnShutdown string `split_words:"true"`

	// RunAsUser is the AGENT_INJECT_RUN_AS_USER environment variable. (uid)
	RunAsUser string `envconfig:"AGENT_INJECT_RUN_AS_USER"`

	// RunAsGroup is the AGENT_INJECT_RUN_AS_GROUP environment variable. (gid)
	RunAsGroup string `envconfig:"AGENT_INJECT_RUN_AS_GROUP"`

	// RunAsSameUser is the AGENT_INJECT_RUN_AS_SAME_USER environment variable.
	RunAsSameUser string `envconfig:"AGENT_INJECT_RUN_AS_SAME_USER"`

	// SetSecurityContext is the AGENT_INJECT_SET_SECURITY_CONTEXT environment variable.
	SetSecurityContext string `envconfig:"AGENT_INJECT_SET_SECURITY_CONTEXT"`

	// TelemetryPath is the AGENT_INJECT_TELEMETRY_PATH environment variable.
	TelemetryPath string `split_words:"true"`

	// UseLeaderElector is the AGENT_INJECT_USE_LEADER_ELECTOR environment variable.
	UseLeaderElector string `split_words:"true"`

	// DefaultTemplate is the AGENT_INJECT_DEFAULT_TEMPLATE environment variable.
	DefaultTemplate string `split_words:"true"`

	// ResourceRequestCPU is the AGENT_INJECT_CPU_REQUEST environment variable.
	ResourceRequestCPU string `envconfig:"AGENT_INJECT_CPU_REQUEST"`

	// ResourceRequestMem is the AGENT_INJECT_MEM_REQUEST environment variable.
	ResourceRequestMem string `envconfig:"AGENT_INJECT_MEM_REQUEST"`

	// ResourceLimitCPU is the AGENT_INJECT_CPU_LIMIT environment variable.
	ResourceLimitCPU string `envconfig:"AGENT_INJECT_CPU_LIMIT"`

	// ResourceLimitMem is the AGENT_INJECT_MEM_LIMIT environment variable.
	ResourceLimitMem string `envconfig:"AGENT_INJECT_MEM_LIMIT"`

	// TLSMinVersion is the AGENT_INJECT_TLS_MIN_VERSION environment variable
	TLSMinVersion string `envconfig:"tls_min_version"`

	// TLSCipherSuites is the AGENT_INJECT_TLS_CIPHER_SUITES environment variable
	TLSCipherSuites string `envconfig:"tls_cipher_suites"`
}

func (c *Command) init() {
	c.flagSet = flag.NewFlagSet("", flag.ContinueOnError)
	c.flagSet.StringVar(&c.flagListen, "listen", ":8080", "Address to bind listener to.")
	c.flagSet.StringVar(&c.flagLogLevel, "log-level", DefaultLogLevel, "Log verbosity level. Supported values "+
		`(in order of detail) are "trace", "debug", "info", "warn", and "err".`)
	c.flagSet.StringVar(&c.flagLogFormat, "log-format", DefaultLogFormat, "Log output format. "+
		`Supported log formats: "standard", "json".`)
	c.flagSet.BoolVar(&c.flagExitOnRetryFailure, "template-config-exit-on-retry-failure", agent.DefaultTemplateConfigExitOnRetryFailure,
		fmt.Sprintf("Value for Agent's template_config.exit_on_retry_failure. Defaults to %t.", agent.DefaultTemplateConfigExitOnRetryFailure))
	c.flagSet.StringVar(&c.flagStaticSecretRenderInterval, "template-static-secret-render-interval", "",
		"Value for Agent's template_config.exit_on_retry_failure.")
	c.flagSet.StringVar(&c.flagAutoName, "tls-auto", "",
		"MutatingWebhookConfiguration name. If specified, will auto generate cert bundle.")
	c.flagSet.StringVar(&c.flagAutoHosts, "tls-auto-hosts", "",
		"Comma-separated hosts for auto-generated TLS cert. If specified, will auto generate cert bundle.")
	c.flagSet.StringVar(&c.flagCertFile, "tls-cert-file", "",
		"PEM-encoded TLS certificate to serve. If blank, will generate random cert.")
	c.flagSet.StringVar(&c.flagKeyFile, "tls-key-file", "",
		"PEM-encoded TLS private key to serve. If blank, will generate random cert.")
	c.flagSet.StringVar(&c.flagVaultImage, "vault-image", agent.DefaultVaultImage,
		fmt.Sprintf("Docker image for Vault. Defaults to %q.", agent.DefaultVaultImage))
	c.flagSet.StringVar(&c.flagVaultService, "vault-address", "",
		"Address of the Vault server.")
	c.flagSet.StringVar(&c.flagProxyAddress, "proxy-address", "",
		"HTTP proxy address used to talk to the Vault service.")
	c.flagSet.StringVar(&c.flagVaultAuthType, "vault-auth-type", agent.DefaultVaultAuthType,
		fmt.Sprintf("Type of Vault Auth Method to use. Defaults to %q.", agent.DefaultVaultAuthType))
	c.flagSet.StringVar(&c.flagVaultAuthPath, "vault-auth-path", agent.DefaultVaultAuthPath,
		fmt.Sprintf("Mount path of the Vault Auth Method. Defaults to %q.", agent.DefaultVaultAuthPath))
	c.flagSet.BoolVar(&c.flagRevokeOnShutdown, "revoke-on-shutdown", false,
		"Automatically revoke Vault Token on Pod termination.")
	c.flagSet.StringVar(&c.flagRunAsUser, "run-as-user", strconv.Itoa(agent.DefaultAgentRunAsUser),
		fmt.Sprintf("User (uid) to run Vault agent as. Defaults to %d.", agent.DefaultAgentRunAsUser))
	c.flagSet.StringVar(&c.flagRunAsGroup, "run-as-group", strconv.Itoa(agent.DefaultAgentRunAsGroup),
		fmt.Sprintf("Group (gid) to run Vault agent as. Defaults to %d.", agent.DefaultAgentRunAsGroup))
	c.flagSet.BoolVar(&c.flagRunAsSameUser, "run-as-same-user", agent.DefaultAgentRunAsSameUser,
		"Run the injected Vault agent containers as the User (uid) of the first application container in the pod. "+
			"Requires Spec.Containers[0].SecurityContext.RunAsUser to be set in the pod spec. "+
			"Defaults to false.")
	c.flagSet.BoolVar(&c.flagSetSecurityContext, "set-security-context", agent.DefaultAgentSetSecurityContext,
		fmt.Sprintf("Set SecurityContext in injected containers. Defaults to %v.", agent.DefaultAgentSetSecurityContext))
	c.flagSet.StringVar(&c.flagTelemetryPath, "telemetry-path", "",
		"Path under which to expose metrics")
	c.flagSet.BoolVar(&c.flagUseLeaderElector, "use-leader-elector", agent.DefaultAgentUseLeaderElector,
		"Use leader elector to coordinate multiple replicas when updating CA and Certs with auto-tls")
	c.flagSet.StringVar(&c.flagDefaultTemplate, "default-template", agent.DefaultTemplateType,
		"Sets the default template type (map or json). Defaults to map.")

	c.flagSet.StringVar(&c.flagResourceRequestCPU, "cpu-request", agent.DefaultResourceRequestCPU,
		fmt.Sprintf("CPU resource request set in injected containers. Defaults to %s", agent.DefaultResourceRequestCPU))
	c.flagSet.StringVar(&c.flagResourceRequestMem, "memory-request", agent.DefaultResourceRequestMem,
		fmt.Sprintf("Memory resource request set in injected containers. Defaults to %s", agent.DefaultResourceRequestMem))

	c.flagSet.StringVar(&c.flagResourceLimitCPU, "cpu-limit", agent.DefaultResourceLimitCPU,
		fmt.Sprintf("CPU resource limit set in injected containers. Defaults to %s", agent.DefaultResourceLimitCPU))
	c.flagSet.StringVar(&c.flagResourceLimitMem, "memory-limit", agent.DefaultResourceLimitMem,
		fmt.Sprintf("Memory resource limit set in injected containers. Defaults to %s", agent.DefaultResourceLimitMem))

	tlsVersions := []string{}
	for v := range tlsutil.TLSLookup {
		tlsVersions = append(tlsVersions, v)
	}
	sort.Strings(tlsVersions)
	tlsStr := strings.Join(tlsVersions, ", ")
	c.flagSet.StringVar(&c.flagTLSMinVersion, "tls-min-version", defaultTLSMinVersion,
		fmt.Sprintf(`Minimum supported version of TLS. Defaults to %s. Accepted values are %s.`, defaultTLSMinVersion, tlsStr))
	c.flagSet.StringVar(&c.flagTLSCipherSuites, "tls-cipher-suites", "",
		"Comma-separated list of supported cipher suites for TLS 1.0-1.2")

	c.help = flags.Usage(help, c.flagSet)
}

func (c *Command) logLevel() (hclog.Level, error) {
	var level hclog.Level
	c.flagLogLevel = strings.ToLower(strings.TrimSpace(c.flagLogLevel))

	switch c.flagLogLevel {
	case "trace":
		level = hclog.Trace
	case "debug":
		level = hclog.Debug
	case "notice", "info", "":
		level = hclog.Info
	case "warn", "warning":
		level = hclog.Warn
	case "err", "error":
		level = hclog.Error
	default:
		return level, fmt.Errorf("unknown log level: %s", c.flagLogLevel)
	}
	return level, nil
}

func (c *Command) parseEnvs() error {
	var envs Specification

	err := envconfig.Process("agent_inject", &envs)
	if err != nil {
		return err
	}

	if envs.Listen != "" {
		c.flagListen = envs.Listen
	}

	if envs.LogLevel != "" {
		c.flagLogLevel = envs.LogLevel
	}

	if envs.LogFormat != "" {
		c.flagLogFormat = envs.LogFormat
	}

	if envs.TemplateConfigExitOnRetryFailure != "" {
		c.flagExitOnRetryFailure, err = strconv.ParseBool(envs.TemplateConfigExitOnRetryFailure)
		if err != nil {
			return err
		}
	}

	if envs.TemplateConfigStaticSecretRenderInterval != "" {
		c.flagStaticSecretRenderInterval = envs.TemplateConfigStaticSecretRenderInterval
	}

	if envs.TLSAuto != "" {
		c.flagAutoName = envs.TLSAuto
	}

	if envs.TLSAutoHosts != "" {
		c.flagAutoHosts = envs.TLSAutoHosts
	}

	if envs.TLSCertFile != "" {
		c.flagCertFile = envs.TLSCertFile
	}

	if envs.TLSKeyFile != "" {
		c.flagKeyFile = envs.TLSKeyFile
	}

	if envs.VaultImage != "" {
		c.flagVaultImage = envs.VaultImage
	}

	if envs.VaultAddr != "" {
		c.flagVaultService = envs.VaultAddr
	}

	if envs.ProxyAddr != "" {
		c.flagProxyAddress = envs.ProxyAddr
	}

	if envs.VaultAuthType != "" {
		c.flagVaultAuthType = envs.VaultAuthType
	}

	if envs.VaultAuthPath != "" {
		c.flagVaultAuthPath = envs.VaultAuthPath
	}

	if envs.RevokeOnShutdown != "" {
		c.flagRevokeOnShutdown, err = strconv.ParseBool(envs.RevokeOnShutdown)
		if err != nil {
			return err
		}
	}

	if envs.RunAsUser != "" {
		c.flagRunAsUser = envs.RunAsUser
	}

	if envs.RunAsGroup != "" {
		c.flagRunAsGroup = envs.RunAsGroup
	}

	if envs.RunAsSameUser != "" {
		c.flagRunAsSameUser, err = strconv.ParseBool(envs.RunAsSameUser)
		if err != nil {
			return err
		}
	}

	if envs.SetSecurityContext != "" {
		c.flagSetSecurityContext, err = strconv.ParseBool(envs.SetSecurityContext)
		if err != nil {
			return err
		}
	}

	if envs.TelemetryPath != "" {
		c.flagTelemetryPath = envs.TelemetryPath
	}

	if envs.UseLeaderElector != "" {
		c.flagUseLeaderElector, err = strconv.ParseBool(envs.UseLeaderElector)
		if err != nil {
			return err
		}
	}

	if envs.DefaultTemplate != "" {
		c.flagDefaultTemplate = envs.DefaultTemplate
	}

	if envs.ResourceRequestCPU != "" {
		c.flagResourceRequestCPU = envs.ResourceRequestCPU
	}

	if envs.ResourceRequestMem != "" {
		c.flagResourceRequestMem = envs.ResourceRequestMem
	}

	if envs.ResourceLimitCPU != "" {
		c.flagResourceLimitCPU = envs.ResourceLimitCPU
	}

	if envs.ResourceLimitMem != "" {
		c.flagResourceLimitMem = envs.ResourceLimitMem
	}

	if envs.TLSMinVersion != "" {
		c.flagTLSMinVersion = envs.TLSMinVersion
	}

	if envs.TLSCipherSuites != "" {
		c.flagTLSCipherSuites = envs.TLSCipherSuites
	}

	return nil
}
