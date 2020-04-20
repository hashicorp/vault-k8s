package injector

import (
	"flag"
	"fmt"
	"strconv"
	"strings"

	"github.com/hashicorp/consul/command/flags"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault-k8s/agent-inject/agent"
	"github.com/kelseyhightower/envconfig"
)

const (
	DefaultLogLevel  = "info"
	DefaultLogFormat = "standard"
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

	// VaultImage is the AGENT_INJECT_VAULT_IMAGE environment variable.
	VaultImage string `split_words:"true"`

	// VaultAuthPath is the AGENT_INJECT_VAULT_AUTH_PATH environment variable.
	VaultAuthPath string `split_words:"true"`

	// RevokeOnShutdown is AGENT_INJECT_REVOKE_ON_SHUTDOWN environment variable.
	RevokeOnShutdown string `split_words:"true"`

	// RunAsUser is the AGENT_INJECT_RUN_AS_USER environment variable. (uid)
	RunAsUser string `envconfig:"AGENT_INJECT_RUN_AS_USER"`

	// RunAsGroup is the AGENT_INJECT_RUN_AS_GROUP environment variable. (gid)
	RunAsGroup string `envconfig:"AGENT_INJECT_RUN_AS_GROUP"`

	// RunAsSameUser is the AGENT_INJECT_RUN_AS_SAME_USER environment variable. (gid)
	RunAsSameUser string `envconfig:"AGENT_INJECT_RUN_AS_SAME_USER"`
}

func (c *Command) init() {
	c.flagSet = flag.NewFlagSet("", flag.ContinueOnError)
	c.flagSet.StringVar(&c.flagListen, "listen", ":8080", "Address to bind listener to.")
	c.flagSet.StringVar(&c.flagLogLevel, "log-level", DefaultLogLevel, "Log verbosity level. Supported values "+
		`(in order of detail) are "trace", "debug", "info", "warn", and "err".`)
	c.flagSet.StringVar(&c.flagLogFormat, "log-format", DefaultLogFormat, "Log output format. "+
		`Supported log formats: "standard", "json".`)
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
	c.flagSet.StringVar(&c.flagVaultAuthPath, "vault-auth-path", agent.DefaultVaultAuthPath,
		fmt.Sprintf("Mount Path of the Vault Kubernetes Auth Method. Defaults to %q.", agent.DefaultVaultAuthPath))
	c.flagSet.BoolVar(&c.flagRevokeOnShutdown, "revoke-on-shutdown", false,
		"Automatically revoke Vault Token on Pod termination.")
	c.flagSet.StringVar(&c.flagRunAsUser, "run-as-user", strconv.Itoa(agent.DefaultAgentRunAsUser),
		fmt.Sprintf("User (uid) to run Vault agent as. Defaults to %d.", agent.DefaultAgentRunAsUser))
	c.flagSet.StringVar(&c.flagRunAsGroup, "run-as-group", strconv.Itoa(agent.DefaultAgentRunAsGroup),
		fmt.Sprintf("Group (gid) to run Vault agent as. Defaults to %d.", agent.DefaultAgentRunAsGroup))
	c.flagSet.BoolVar(&c.flagRunAsSameUser, "run-as-same-user", true,
		"User (gid) to run Vault agent same as User (uid) application.")

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

	return nil
}
