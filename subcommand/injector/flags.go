package injector

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/hashicorp/consul/command/flags"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault-k8s/agent-inject/agent"
)

const (
	DefaultLogLevel       = "info"
	EnvInjectListen       = "AGENT_INJECT_LISTEN"
	EnvInjectLogLevel     = "AGENT_INJECT_LOG_LEVEL"
	EnvInjectTLSAuto      = "AGENT_INJECT_TLS_AUTO"
	EnvInjectTLSAutoHosts = "AGENT_INJECT_TLS_AUTO_HOSTS"
	EnvInjectTLSCertFile  = "AGENT_INJECT_CERT_FILE"
	EnvInjectTLSKeyFile   = "AGENT_INJECT_KEY_FILE"
	EnvInjectVaultAddr    = "AGENT_INJECT_VAULT_ADDR"
	EnvInjectVaultImage   = "AGENT_INJECT_VAULT_IMAGE"
)

// TODO Add env support
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
		fmt.Sprintf("Docker image for Vault. Defaults to %s.", agent.DefaultVaultImage))
	c.flagSet.StringVar(&c.flagVaultService, "vault-address", "",
		"Address of the Vault server.")

	c.help = flags.Usage(help, c.flagSet)
	c.parseEnvs()
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

func (c *Command) parseEnvs() {
	if listen := os.Getenv(EnvInjectListen); listen != "" {
		c.flagListen = listen
	}

	if logLevel := os.Getenv(EnvInjectLogLevel); logLevel != "" {
		c.flagLogLevel = logLevel
	}

	if tlsAuto := os.Getenv(EnvInjectTLSAuto); tlsAuto != "" {
		c.flagAutoName = tlsAuto
	}

	if tlsAutoHosts := os.Getenv(EnvInjectTLSAutoHosts); tlsAutoHosts != "" {
		c.flagAutoHosts = tlsAutoHosts
	}

	if tlsCertFile := os.Getenv(EnvInjectTLSCertFile); tlsCertFile != "" {
		c.flagCertFile = tlsCertFile
	}

	if tlsKeyFile := os.Getenv(EnvInjectTLSKeyFile); tlsKeyFile != "" {
		c.flagKeyFile = tlsKeyFile
	}

	if image := os.Getenv(EnvInjectVaultImage); image != "" {
		c.flagVaultImage = image
	}

	if addr := os.Getenv(EnvInjectVaultAddr); addr != "" {
		c.flagVaultService = addr
	}
}
