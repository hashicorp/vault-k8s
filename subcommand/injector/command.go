// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package injector

import (
	"bytes"
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

	"github.com/cenkalti/backoff/v4"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-secure-stdlib/tlsutil"
	agentInject "github.com/hashicorp/vault-k8s/agent-inject"
	"github.com/hashicorp/vault-k8s/helper/cert"
	"github.com/hashicorp/vault-k8s/leader"
	"github.com/hashicorp/vault-k8s/version"
	"github.com/mitchellh/cli"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	adminv1 "k8s.io/api/admissionregistration/v1"
	adminv1beta "k8s.io/api/admissionregistration/v1beta1"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/informers"
	informerv1 "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/kubernetes"
	v1 "k8s.io/client-go/listers/admissionregistration/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
)

type Command struct {
	UI cli.Ui

	flagListen                     string // Address of Vault Server
	flagLogLevel                   string // Log verbosity
	flagLogFormat                  string // Log format
	flagCertFile                   string // TLS Certificate to serve
	flagKeyFile                    string // TLS private key to serve
	flagExitOnRetryFailure         bool   // Set template_config.exit_on_retry_failure on agent
	flagStaticSecretRenderInterval string // Set template_config.static_secret_render_interval on agent
	flagMaxConnectionsPerHost      int64  // Set template_config.max_connections_per_host on agent
	flagAutoName                   string // MutatingWebhookConfiguration for updating
	flagAutoHosts                  string // SANs for the auto-generated TLS cert.
	flagVaultService               string // Name of the Vault service
	flagVaultCACertBytes           string // CA Cert to trust for TLS with Vault.
	flagProxyAddress               string // HTTP proxy address used to talk to the Vault service
	flagVaultImage                 string // Name of the Vault Image to use
	flagVaultAuthType              string // Type of Vault Auth Method to use
	flagVaultAuthPath              string // Mount path of the Vault Auth Method
	flagVaultNamespace             string // Vault enterprise namespace
	flagRevokeOnShutdown           bool   // Revoke Vault Token on pod shutdown
	flagRunAsUser                  string // User (uid) to run Vault agent as
	flagRunAsGroup                 string // Group (gid) to run Vault agent as
	flagRunAsSameUser              bool   // Run Vault agent as the User (uid) of the first application container
	flagSetSecurityContext         bool   // Set SecurityContext in injected containers
	flagTelemetryPath              string // Path under which to expose metrics
	flagUseLeaderElector           bool   // Use leader elector code
	flagDefaultTemplate            string // Toggles which default template to use
	flagResourceRequestCPU         string // Set CPU request in the injected containers
	flagResourceRequestMem         string // Set Memory request in the injected containers
	flagResourceRequestEphemeral   string // Set Ephemeral Storage request in the injected containers
	flagResourceLimitCPU           string // Set CPU limit in the injected containers
	flagResourceLimitMem           string // Set Memory limit in the injected containers
	flagResourceLimitEphemeral     string // Set Ephemeral storage limit in the injected containers
	flagTLSMinVersion              string // Minimum TLS version supported by the webhook server
	flagTLSCipherSuites            string // Comma-separated list of supported cipher suites
	flagAuthMinBackoff             string // Auth min backoff on failure
	flagAuthMaxBackoff             string // Auth min backoff on failure
	flagDisableIdleConnections     string // Idle connections control
	flagDisableKeepAlives          string // Keep-alives control

	flagSet *flag.FlagSet

	once sync.Once
	help string
	cert atomic.Value
}

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

	switch c.flagDefaultTemplate {
	case "map":
	case "json":
	default:
		c.UI.Error(fmt.Sprintf("Invalid default flag type: %s", c.flagDefaultTemplate))
		return 1
	}

	// We must have an in-cluster K8S client
	config, err := rest.InClusterConfig()
	if err != nil {
		c.UI.Error(fmt.Sprintf("Error loading in-cluster K8S config: %s", err))
		return 1
	}
	config.UserAgent = fmt.Sprintf("vault-k8s/%s", version.Version)

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		c.UI.Error(fmt.Sprintf("Error creating K8S client: %s", err))
		return 1
	}

	level, err := c.logLevel()
	if err != nil {
		c.UI.Error(fmt.Sprintf("Error setting log level: %s", err))
		return 1
	}

	logger := hclog.New(&hclog.LoggerOptions{
		Name:       "handler",
		Level:      level,
		JSONFormat: (c.flagLogFormat == "json"),
	})

	namespace := getNamespace()
	var secrets informerv1.SecretInformer
	var leaderElector leader.Elector
	// The exitOnError channel will be used for signaling an injector shutdown
	// from the leader goroutine
	exitOnError := make(chan error)
	if c.flagUseLeaderElector {
		c.UI.Info("Using internal leader elector logic for webhook certificate management")
		factory := informers.NewSharedInformerFactoryWithOptions(clientset, 0, informers.WithNamespace(namespace))
		secrets = factory.Core().V1().Secrets()
		go secrets.Informer().Run(ctx.Done())
		if !cache.WaitForCacheSync(ctx.Done(), secrets.Informer().HasSynced) {
			c.UI.Error("timeout syncing Secrets informer")
			return 1
		}
		leaderElector = leader.New(ctx, logger, clientset, exitOnError)
	}

	adminAPIVersion, err := getAdminAPIVersion(ctx, clientset)
	if err != nil {
		logger.Warn(fmt.Sprintf("failed to determine Admissionregistration API version, defaulting to %s", adminAPIVersion), "error", err)
	}

	// Determine where to source the certificates from
	var certSource cert.Source = &cert.GenSource{
		Name:            "Agent Inject",
		Hosts:           strings.Split(c.flagAutoHosts, ","),
		K8sClient:       clientset,
		Namespace:       namespace,
		SecretsCache:    secrets,
		LeaderElector:   leaderElector,
		WebhookName:     c.flagAutoName,
		AdminAPIVersion: adminAPIVersion,
		Log:             logger.Named("auto-tls"),
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
	certReady := make(chan bool)
	certNotify := cert.NewNotify(ctx, certCh, certReady, certSource, logger.Named("notify"))
	go certNotify.Run()
	go c.certWatcher(ctx, certCh, clientset, leaderElector, logger.Named("certwatcher"))

	// Build the HTTP handler and server
	injector := agentInject.Handler{
		VaultAddress:               c.flagVaultService,
		VaultCACertBytes:           c.flagVaultCACertBytes,
		VaultAuthType:              c.flagVaultAuthType,
		VaultAuthPath:              c.flagVaultAuthPath,
		VaultNamespace:             c.flagVaultNamespace,
		ProxyAddress:               c.flagProxyAddress,
		ImageVault:                 c.flagVaultImage,
		Clientset:                  clientset,
		RequireAnnotation:          true,
		Log:                        logger,
		RevokeOnShutdown:           c.flagRevokeOnShutdown,
		UserID:                     c.flagRunAsUser,
		GroupID:                    c.flagRunAsGroup,
		SameID:                     c.flagRunAsSameUser,
		SetSecurityContext:         c.flagSetSecurityContext,
		DefaultTemplate:            c.flagDefaultTemplate,
		ResourceRequestCPU:         c.flagResourceRequestCPU,
		ResourceRequestMem:         c.flagResourceRequestMem,
		ResourceRequestEphemeral:   c.flagResourceRequestEphemeral,
		ResourceLimitCPU:           c.flagResourceLimitCPU,
		ResourceLimitMem:           c.flagResourceLimitMem,
		ResourceLimitEphemeral:     c.flagResourceLimitEphemeral,
		ExitOnRetryFailure:         c.flagExitOnRetryFailure,
		StaticSecretRenderInterval: c.flagStaticSecretRenderInterval,
		MaxConnectionsPerHost:      c.flagMaxConnectionsPerHost,
		AuthMinBackoff:             c.flagAuthMinBackoff,
		AuthMaxBackoff:             c.flagAuthMaxBackoff,
		DisableIdleConnections:     c.flagDisableIdleConnections,
		DisableKeepAlives:          c.flagDisableKeepAlives,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/mutate", injector.Handle)
	mux.HandleFunc("/health/ready", c.handleReady)

	// Registering path to expose metrics
	if c.flagTelemetryPath != "" {
		c.UI.Info(fmt.Sprintf("Registering telemetry path on %q", c.flagTelemetryPath))
		mux.Handle(c.flagTelemetryPath, promhttp.Handler())
	}

	var handler http.Handler = mux
	tlsConfig, err := c.makeTLSConfig()
	if err != nil {
		c.UI.Error(fmt.Sprintf("Failed to configure TLS: %s", err))
		return 1
	}

	// if we don't have a certificate given to us, wait for cert to generate to prevent
	// TLS errors on startup
	if c.flagCertFile == "" && c.flagKeyFile == "" {
		<-certReady
	} else {
		// otherwise drain async just to clean up the sending goroutine
		go func() {
			<-certReady
		}()
	}

	server := &http.Server{
		Addr:      c.flagListen,
		Handler:   handler,
		TLSConfig: tlsConfig,
		ErrorLog:  logger.StandardLogger(&hclog.StandardLoggerOptions{ForceLevel: hclog.Error}),
	}

	trap := make(chan os.Signal, 1)
	signal.Notify(trap, os.Interrupt)
	defer func() {
		signal.Stop(trap)
		cancelFunc()
	}()
	go func() {
		select {
		case err := <-exitOnError:
			logger.Error("Shutting down due to error", "error", err)
			c.shutdownHandler(ctx, server, cancelFunc)
		case sig := <-trap:
			logger.Info("Caught signal, shutting down", "signal", sig)
			c.shutdownHandler(ctx, server, cancelFunc)
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

func (c *Command) shutdownHandler(ctx context.Context, server *http.Server, cancelFunc context.CancelFunc) {
	if err := server.Shutdown(ctx); err != nil {
		c.UI.Error(fmt.Sprintf("Error shutting down handler: %s", err))
	}
	cancelFunc()
}

func getNamespace() string {
	namespace := os.Getenv("NAMESPACE")
	if namespace != "" {
		return namespace
	}

	return "default"
}

func (c *Command) handleReady(rw http.ResponseWriter, req *http.Request) {
	// Always ready at this point. The main readiness check is whether
	// there is a TLS certificate. If we reached this point it means we
	// served a TLS certificate.
	rw.WriteHeader(204)
}

func (c *Command) makeTLSConfig() (*tls.Config, error) {
	minTLSVersion, ok := tlsutil.TLSLookup[c.flagTLSMinVersion]
	if !ok {
		return nil, fmt.Errorf("invalid or unsupported TLS version %q", c.flagTLSMinVersion)
	}

	ciphers, err := tlsutil.ParseCiphers(c.flagTLSCipherSuites)
	if err != nil {
		return nil, fmt.Errorf("failed to parse TLS cipher suites list %q: %s", c.flagTLSCipherSuites, err)
	}

	tlsConfig := &tls.Config{
		GetCertificate: c.getCertificate,
		MinVersion:     minTLSVersion,
	}
	if len(ciphers) > 0 {
		tlsConfig.CipherSuites = ciphers
	}

	return tlsConfig, nil
}

func (c *Command) getCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	certRaw := c.cert.Load()
	if certRaw == nil {
		return nil, errors.New("no certificate available")
	}

	return certRaw.(*tls.Certificate), nil
}

func getAdminAPIVersion(ctx context.Context, clientset *kubernetes.Clientset) (string, error) {
	adminAPIVersion := adminv1.SchemeGroupVersion.Version
	_, err := clientset.AdmissionregistrationV1().
		MutatingWebhookConfigurations().
		List(ctx, metav1.ListOptions{})
	if k8sErrors.IsNotFound(err) {
		adminAPIVersion = adminv1beta.SchemeGroupVersion.Version
	}
	return adminAPIVersion, err
}

func (c *Command) certWatcher(ctx context.Context, ch <-chan cert.Bundle, clientset *kubernetes.Clientset, leaderElector leader.Elector, log hclog.Logger) {
	var bundle cert.Bundle
	webhooksCache, webhooksWatcher, err := watchWebhooks(ctx, clientset)
	if err != nil {
		log.Error("Error watching webhooks", "error", err)
		panic(err)
	}

	defaultLoopTime := 1 * time.Hour // update after this amount of time even if nothing has happened
	expBackoff := backoff.NewExponentialBackOff()
	interval := defaultLoopTime

	for {
		select {
		case bundle = <-ch:
			// Bundle is updated, set it up
			log.Info("Updated certificate bundle received. Updating certs...")

		case <-webhooksWatcher:
			// Webhooks changed, make sure the CA bundle is up-to-date.
			log.Info("Webhooks changed. Updating certs...")

		case <-ctx.Done():
			// Quit
			return

		case <-time.After(interval):
			// we are told to retry or periodically update
		}

		err := c.updateCertificate(ctx, clientset, bundle, webhooksCache, leaderElector, log)
		if err != nil {
			// retry after a delay
			interval = expBackoff.NextBackOff()
		} else {
			expBackoff.Reset()
			interval = defaultLoopTime
		}
	}
}

func (c *Command) fetchWebhook(ctx context.Context, clientset *kubernetes.Clientset) (*adminv1.MutatingWebhookConfiguration, error) {
	return clientset.AdmissionregistrationV1().MutatingWebhookConfigurations().Get(ctx, c.flagAutoName, metav1.GetOptions{})
}

func (c *Command) updateCertificate(ctx context.Context, clientset *kubernetes.Clientset, bundle cert.Bundle, webhooksCache v1.MutatingWebhookConfigurationLister, leaderElector leader.Elector, log hclog.Logger) error {
	crt, err := tls.X509KeyPair(bundle.Cert, bundle.Key)
	if err != nil {
		log.Warn(fmt.Sprintf("Could not load TLS keypair: %s. Trying again...", err))
		return err
	}

	isLeader := true
	if c.flagUseLeaderElector {
		// Only the leader should do the caBundle patching in k8s API
		var err error
		isLeader, err = leaderElector.IsLeader()
		if err != nil {
			log.Warn(fmt.Sprintf("Could not check leader: %s. Trying again...", err))
			return err
		}
	}

	// If there is an MWC name set, then update the CA bundle.
	if isLeader && c.flagAutoName != "" && len(bundle.CACert) > 0 {
		config, err := webhooksCache.Get(c.flagAutoName)
		if err != nil {
			log.Warn("Getting webhook config from cache failed", "err", err)
			config, err = c.fetchWebhook(ctx, clientset)
			if err != nil {
				log.Warn("Fetching webhook config directly failed; will try again", "err", err)
				return err
			}
		}

		// Check the current bundles and only update if necessary.
		if len(config.Webhooks) == 0 || !bytes.Equal(config.Webhooks[0].ClientConfig.CABundle, bundle.CACert) {
			err = c.updateCABundle(ctx, &bundle, clientset)
			if err != nil {
				c.UI.Error(fmt.Sprintf(
					"Error updating MutatingWebhookConfiguration: %s",
					err))
				return err
			}
		}
	}

	// Update the certificate
	c.cert.Store(&crt)
	return nil
}

func watchWebhooks(ctx context.Context, clientset *kubernetes.Clientset) (v1.MutatingWebhookConfigurationLister, <-chan interface{}, error) {
	factory := informers.NewSharedInformerFactoryWithOptions(clientset, 0)
	webhooks := factory.Admissionregistration().V1().MutatingWebhookConfigurations()
	go webhooks.Informer().Run(ctx.Done())
	if !cache.WaitForCacheSync(ctx.Done(), webhooks.Informer().HasSynced) {
		return nil, nil, fmt.Errorf("timeout syncing Webhooks informer")
	}
	notifyCh := make(webhookWatcher)
	webhooks.Informer().AddEventHandler(notifyCh)
	return webhooks.Lister(), notifyCh, nil
}

var _ cache.ResourceEventHandler = (*webhookWatcher)(nil)

type webhookWatcher chan interface{}

func (w webhookWatcher) OnAdd(_ interface{}, _ bool) {
	w <- nil
}

func (w webhookWatcher) OnUpdate(_, _ interface{}) {
	w <- nil
}

func (w webhookWatcher) OnDelete(_ interface{}) {
	w <- nil
}

// updateCABundle updates the current CA bundle for the first mutating webhook
func (c *Command) updateCABundle(ctx context.Context, bundle *cert.Bundle, clientset *kubernetes.Clientset) error {
	// The CA Bundle value must be base64 encoded
	value := base64.StdEncoding.EncodeToString(bundle.CACert)
	payload := []byte(fmt.Sprintf(
		`[{
					"op": "add",
					"path": "/webhooks/0/clientConfig/caBundle",
					"value": %q
				}]`, value))

	_, err := clientset.AdmissionregistrationV1().
		MutatingWebhookConfigurations().
		Patch(ctx, c.flagAutoName, types.JSONPatchType, payload,
			metav1.PatchOptions{})
	return err
}

func (c *Command) Synopsis() string { return synopsis }
func (c *Command) Help() string {
	c.once.Do(c.init)
	return c.help
}

const (
	synopsis = "Vault Agent injector service"
	help     = `
Usage: vault-k8s agent-inject [options]
  Run the Admission Webhook server for injecting Vault Agent containers into pods.
`
)
