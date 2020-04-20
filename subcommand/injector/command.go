package injector

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hashicorp/go-hclog"
	agentInject "github.com/hashicorp/vault-k8s/agent-inject"
	"github.com/hashicorp/vault-k8s/helper/cert"
	"github.com/mitchellh/cli"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

type Command struct {
	UI cli.Ui

	flagListen           string // Address of Vault Server
	flagLogLevel         string // Log verbosity
	flagLogFormat        string // Log format
	flagCertFile         string // TLS Certificate to serve
	flagKeyFile          string // TLS private key to serve
	flagAutoName         string // MutatingWebhookConfiguration for updating
	flagAutoHosts        string // SANs for the auto-generated TLS cert.
	flagVaultService     string // Name of the Vault service
	flagVaultImage       string // Name of the Vault Image to use
	flagVaultAuthPath    string // Mount Path of the Vault Kubernetes Auth Method
	flagRevokeOnShutdown bool   // Revoke Vault Token on pod shutdown
	flagRunAsUser        string // User (uid) to run Vault agent as
	flagRunAsGroup       string // Group (gid) to run Vault agent as
	flagRunAsSameUser    bool   // User (gid) to run Vault agent same as User (uid) application

	flagSet *flag.FlagSet

	once sync.Once
	help string
	cert atomic.Value
}

// TODO Add flag for Vault TLS
func (c *Command) Run(args []string) int {
	ctx, cancelFunc := context.WithCancel(context.Background())
	defer cancelFunc()

	c.once.Do(c.init)
	if err := c.flagSet.Parse(args); err != nil {
		return 1
	}

	if err := c.parseEnvs(); err != nil {
		c.UI.Error(fmt.Sprintf("Error parsing environment variables: %s", err))
		return 1
	}

	if c.flagVaultService == "" {
		c.UI.Error("No Vault service configured")
		return 1
	}

	// We must have an in-cluster K8S client
	config, err := rest.InClusterConfig()
	if err != nil {
		c.UI.Error(fmt.Sprintf("Error loading in-cluster K8S config: %s", err))
		return 1
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		c.UI.Error(fmt.Sprintf("Error creating K8S client: %s", err))
		return 1
	}

	// Determine where to source the certificates from
	var certSource cert.Source = &cert.GenSource{
		Name:  "Agent Inject",
		Hosts: strings.Split(c.flagAutoHosts, ","),
	}
	if c.flagCertFile != "" {
		certSource = &cert.DiskSource{
			CertPath: c.flagCertFile,
			KeyPath:  c.flagKeyFile,
		}
	}

	// Create the certificate notifier so we can update for certificates,
	// then start all the background routines for updating certificates.
	certCh := make(chan cert.Bundle)
	certNotify := cert.NewNotify(ctx, certCh, certSource)
	go certNotify.Run()
	go c.certWatcher(ctx, certCh, clientset)

	level, err := c.logLevel()
	if err != nil {
		c.UI.Error(fmt.Sprintf("Error setting log level: %s", err))
		return 1
	}

	logger := hclog.New(&hclog.LoggerOptions{
		Name:       "handler",
		Level:      level,
		JSONFormat: (c.flagLogFormat == "json")})

	// Build the HTTP handler and server
	injector := agentInject.Handler{
		VaultAddress:      c.flagVaultService,
		VaultAuthPath:     c.flagVaultAuthPath,
		ImageVault:        c.flagVaultImage,
		Clientset:         clientset,
		RequireAnnotation: true,
		Log:               logger,
		RevokeOnShutdown:  c.flagRevokeOnShutdown,
		UserID:            c.flagRunAsUser,
		GroupID:           c.flagRunAsGroup,
		SameID:            c.flagRunAsSameUser,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/mutate", injector.Handle)
	mux.HandleFunc("/health/ready", c.handleReady)
	var handler http.Handler = mux
	server := &http.Server{
		Addr:      c.flagListen,
		Handler:   handler,
		TLSConfig: &tls.Config{GetCertificate: c.getCertificate},
	}

	trap := make(chan os.Signal, 1)
	signal.Notify(trap, os.Interrupt)
	defer func() {
		signal.Stop(trap)
		cancelFunc()
	}()
	go func() {
		select {
		case <-trap:
			if err := server.Shutdown(ctx); err != nil {
				c.UI.Error(fmt.Sprintf("Error shutting down handler: %s", err))
			}
			cancelFunc()
		case <-ctx.Done():
		}
	}()

	injector.Log.Info("Starting handler..")

	c.UI.Info(fmt.Sprintf("Listening on %q...", c.flagListen))
	if err := server.ListenAndServeTLS(c.flagCertFile, c.flagKeyFile); err != nil {
		c.UI.Error(fmt.Sprintf("Error listening: %s", err))
		return 1
	}

	return 0
}

func (c *Command) handleReady(rw http.ResponseWriter, req *http.Request) {
	// Always ready at this point. The main readiness check is whether
	// there is a TLS certificate. If we reached this point it means we
	// served a TLS certificate.
	rw.WriteHeader(204)
}

func (c *Command) getCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	certRaw := c.cert.Load()
	if certRaw == nil {
		return nil, errors.New("no certificate available")
	}

	return certRaw.(*tls.Certificate), nil
}

func (c *Command) certWatcher(ctx context.Context, ch <-chan cert.Bundle, clientset *kubernetes.Clientset) {
	var bundle cert.Bundle
	for {
		select {
		case bundle = <-ch:
			c.UI.Output("Updated certificate bundle received. Updating certs...")
			// Bundle is updated, set it up

		case <-time.After(1 * time.Second):
			// This forces the mutating webhook config to remain updated
			// fairly quickly. This is a jank way to do this and we should
			// look to improve it in the future. Since we use Patch requests
			// it is pretty cheap to do, though.

		case <-ctx.Done():
			// Quit
			return
		}

		crt, err := tls.X509KeyPair(bundle.Cert, bundle.Key)
		if err != nil {
			c.UI.Error(fmt.Sprintf("Error loading TLS keypair: %s", err))
			continue
		}

		// If there is a MWC name set, then update the CA bundle.
		if c.flagAutoName != "" && len(bundle.CACert) > 0 {
			// The CA Bundle value must be base64 encoded
			value := base64.StdEncoding.EncodeToString(bundle.CACert)

			_, err := clientset.AdmissionregistrationV1beta1().
				MutatingWebhookConfigurations().
				Patch(c.flagAutoName, types.JSONPatchType, []byte(fmt.Sprintf(
					`[{
						"op": "add",
						"path": "/webhooks/0/clientConfig/caBundle",
						"value": %q
					}]`, value)))
			if err != nil {
				c.UI.Error(fmt.Sprintf(
					"Error updating MutatingWebhookConfiguration: %s",
					err))
				continue
			}
		}

		// Update the certificate
		c.cert.Store(&crt)
	}
}

func (c *Command) Synopsis() string { return synopsis }
func (c *Command) Help() string {
	c.once.Do(c.init)
	return c.help
}

const synopsis = "Vault Agent injector service"
const help = `
Usage: vault-k8s agent-inject [options]
  Run the Admission Webhook server for injecting Vault Agent containers into pods.
`
