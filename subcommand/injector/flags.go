package injector

import (
	"flag"
	"fmt"
	"strings"

	"github.com/hashicorp/consul/command/flags"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault-k8s/agent-inject/agent"
	"github.com/kelseyhightower/envconfig"
)

const (
	DefaultLogLevel = "info"
)

// Specification are the supported environment variables, prefixed with
// AGENT_INJECT.  The names of the variables in the struct are split using
// camel case: Specification.VaultAddr = AGENT_INJECT_VAULT_ADDR
type Specification struct {
	// Listen is the AGENT_INJECT_LISTEN environment variable.
	Listen string `split_words:"true" `

	// LogLevel is the AGENT_INJECT_LOG_LEVEL environment variable.
	LogLevel string `split_words:"true"`

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
}

func (c *Command) init() {
	c.flagSet = flag.NewFlagSet("", flag.ContinueOnError)
	c.flagSet.StringVar(&c.flagListen, "listen", ":8080", "Address to bind listener to.")
	c.flagSet.StringVar(&c.flagLogLevel, "log-level", DefaultLogLevel, "Log verbosity level. Supported values "+
		`(in order of detail) are "trace", "debug", "info", "warn", and "err".`)
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

	return nil
}
