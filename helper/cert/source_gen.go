package cert

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault-k8s/leader"
	adminv1 "k8s.io/api/admissionregistration/v1"
	adminv1beta "k8s.io/api/admissionregistration/v1beta1"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	informerv1 "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/kubernetes"
)

// Name of the k8s Secret used to share the caBundle between leader and
// followers
const certSecretName = "vault-injector-certs"

// GenSource generates a self-signed CA and certificate pair.
//
// This generator is stateful. On the first run (last == nil to Certificate),
// a CA will be generated. On subsequent calls, the same CA will be used to
// create a new certificate when the expiry is near. To create a new CA, a
// new GenSource must be allocated.
type GenSource struct {
	Name  string   // Name is used as part of the common name
	Hosts []string // Hosts is the list of hosts to make the leaf valid for

	// Expiry is the duration that a certificate is valid for. This
	// defaults to 24 hours.
	Expiry time.Duration

	// ExpiryWithin is the duration value used for determining whether to
	// regenerate a new leaf certificate. If the old leaf certificate is
	// expiring within this value, then a new leaf will be generated. Default
	// is about 10% of Expiry.
	ExpiryWithin time.Duration

	mu             sync.Mutex
	caCert         []byte
	caCertTemplate *x509.Certificate
	caSigner       crypto.Signer

	K8sClient       kubernetes.Interface
	Namespace       string
	SecretsCache    informerv1.SecretInformer
	LeaderElector   leader.Elector
	WebhookName     string
	AdminAPIVersion string

	Log hclog.Logger
}

// Certificate implements source
func (s *GenSource) Certificate(ctx context.Context, last *Bundle) (Bundle, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var result Bundle
	leaderCh := make(chan bool)

	if s.LeaderElector != nil {
		leaderCheck, err := s.LeaderElector.IsLeader()
		if err != nil {
			return result, err
		}
		// For followers, run different function here that reads bundle from Secret,
		// and returns that in the result. That will flow through the existing
		// notify channel structure, testing if it's the same cert as last, etc.
		if !leaderCheck {
			s.Log.Debug("Currently a follower")
			return s.getBundleFromSecret()
		}
		s.Log.Info("Currently the leader")

		// Start a goroutine that checks for a leadership change, otherwise this
		// would wait until the current certificate expires before moving on.
		changeContext, cancel := context.WithCancel(ctx)
		defer cancel()
		go s.checkLeader(changeContext, leaderCh)
	}

	// If we have no CA, generate it for the first time.
	if len(s.caCert) == 0 {
		if err := s.generateCA(); err != nil {
			return result, err
		}
		// If we had no CA, also ensure the cert is regenerated
		last = nil

		s.Log.Info("Generated CA")

		// Check if there's an existing caBundle on the webhook config
		oldCAs := s.getExistingCA(ctx)
		if len(oldCAs) > 0 {
			bothCerts, err := prependLastCA(s.caCert, oldCAs, s.Log)
			if err != nil {
				// If there's an error, don't set s.caCert; just log a warning
				// and continue on, so that the caCert will be replaced
				s.Log.Warn("failed to append previous CA cert to new CA cert", "err", err)
			} else {
				s.caCert = bothCerts
			}
		}
	}

	// Set the CA cert
	result.CACert = s.caCert

	// If we have a prior cert, we wait for getting near to the expiry
	// (within 30 minutes arbitrarily chosen).
	if last != nil {
		// We have a prior certificate, let's parse it to get the expiry
		cert, err := parseCert(last.Cert)
		if err != nil {
			return result, err
		}

		waitTime := time.Until(cert.NotAfter) - s.expiryWithin()
		if waitTime < 0 {
			waitTime = 1 * time.Millisecond
		}

		timer := time.NewTimer(waitTime)
		defer timer.Stop()

		select {
		case <-leaderCh:
			s.Log.Debug("got a leadership change, returning")
			return result, fmt.Errorf("lost leadership")

		case <-timer.C:
			// Fall through, generate cert

		case <-ctx.Done():
			return result, ctx.Err()
		}
	}

	// Generate cert, set it on the result, and return
	cert, key, err := s.generateCert()
	if err != nil {
		return result, err
	}
	result.Cert = []byte(cert)
	result.Key = []byte(key)

	if s.LeaderElector != nil {
		if err := s.retryUpdateSecret(ctx, leaderCh, result); err != nil {
			return result, err
		}
	}

	return result, nil
}

func (s *GenSource) checkLeader(ctx context.Context, changed chan<- bool) {
	for {
		select {
		case <-time.After(1 * time.Second):
			// Check once a second for a leadership change
			s.Log.Named("checkLeader").Trace("checking for leadership change")

		case <-ctx.Done():
			// Quit
			return
		}

		check, err := s.LeaderElector.IsLeader()
		if err != nil {
			s.Log.Warn("failed to check for leadership change: %s", err)
		}
		if !check {
			s.Log.Named("checkLeader").Debug("lost the leadership, sending notification")
			select {
			case changed <- true:
				s.Log.Named("checkLeader").Trace("sent changed <- true")
				return
			case <-ctx.Done():
				s.Log.Named("checkLeader").Trace("got done")
				return
			}
		}
	}
}

func (s *GenSource) retryUpdateSecret(ctx context.Context, leaderCh chan bool, bundle Bundle) error {
	// New exponential backoff, with a max elapsed time of 90% of the newly
	// created cert expiration, since that's the point where it would be renewed
	// by the calling function
	bo := backoff.NewExponentialBackOff()
	bo.MaxInterval = 30 * time.Second
	bo.MaxElapsedTime = time.Duration(float64(s.expiry()) * 0.90)
	ticker := backoff.NewTicker(bo)
	defer ticker.Stop()

	var err error
	for {
		select {
		case _, ok := <-ticker.C:
			if !ok {
				return fmt.Errorf("timed out attempting to update cert secret: %w", err)
			}
			if err = s.updateSecret(ctx, bundle); err != nil {
				s.Log.Error("attempt to update cert secret failed", "certSecretName", certSecretName, "err", err)
			} else {
				s.Log.Trace("updated cert secret, quitting update thread", "certSecretName", certSecretName)
				return nil
			}
		case <-ctx.Done():
			s.Log.Trace("quitting update cert retries due to done context")
			return nil
		case <-leaderCh:
			s.Log.Trace("quitting update cert retries due to leadership change")
			return nil
		}
	}
}

func (s *GenSource) updateSecret(ctx context.Context, bundle Bundle) error {
	certB64 := base64.StdEncoding.EncodeToString(bundle.CACert)
	keyB64 := base64.StdEncoding.EncodeToString(bundle.Key)
	payload_str := fmt.Sprintf(
		`{
			"data": {
				"cert": %q,
				"key": %q
			}
		}`, certB64, keyB64)
	payload := []byte(payload_str)

	_, err := s.K8sClient.CoreV1().Secrets(s.Namespace).Patch(ctx, certSecretName, types.MergePatchType, payload, metav1.PatchOptions{})
	if errors.IsNotFound(err) {
		secret := &v1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name: certSecretName,
			},
			Data: map[string][]byte{
				"cert": bundle.Cert,
				"key":  bundle.Key,
			},
		}
		_, err = s.K8sClient.CoreV1().Secrets(s.Namespace).Create(ctx, secret, metav1.CreateOptions{})
	}
	if err != nil {
		return err
	}
	return nil
}

func (s *GenSource) getBundleFromSecret() (Bundle, error) {
	var bundle Bundle

	secret, err := s.SecretsCache.Lister().Secrets(s.Namespace).Get(certSecretName)
	if err != nil {
		return bundle, fmt.Errorf("failed to get secret: %s", err)
	}
	bundle.Cert = secret.Data["cert"]
	bundle.Key = secret.Data["key"]

	return bundle, nil
}

func (s *GenSource) getExistingCA(ctx context.Context) []byte {
	switch s.AdminAPIVersion {
	case adminv1.SchemeGroupVersion.Version:
		cfg, err := s.K8sClient.AdmissionregistrationV1().
			MutatingWebhookConfigurations().
			Get(ctx, s.WebhookName, metav1.GetOptions{})
		if err != nil {
			s.Log.Warn("failed to fetch v1 mutating webhook config", "WebhookName", s.WebhookName, "err", err)
			return []byte{}
		}
		if len(cfg.Webhooks) > 0 {
			return cfg.Webhooks[0].ClientConfig.CABundle
		}
	case adminv1beta.SchemeGroupVersion.Version:
		cfg, err := s.K8sClient.AdmissionregistrationV1beta1().
			MutatingWebhookConfigurations().
			Get(ctx, s.WebhookName, metav1.GetOptions{})
		if err != nil {
			s.Log.Warn("failed to fetch v1beta mutating webhook config", "WebhookName", s.WebhookName, "err", err)
			return []byte{}
		}
		if len(cfg.Webhooks) > 0 {
			return cfg.Webhooks[0].ClientConfig.CABundle
		}
	}

	// At this point either the AdminAPIVersion was unknown, or the CABundle was
	// empty, so just return an empty slice
	return []byte{}
}

func (s *GenSource) expiry() time.Duration {
	if s.Expiry > 0 {
		return s.Expiry
	}

	return 24 * time.Hour
}

func (s *GenSource) expiryWithin() time.Duration {
	if s.ExpiryWithin > 0 {
		return s.ExpiryWithin
	}

	// Roughly 10% accounting for float errors
	return time.Duration(float64(s.expiry()) * 0.10)
}

func (s *GenSource) generateCert() (string, string, error) {
	// Create the private key we'll use for this leaf cert.
	signer, keyPEM, err := s.privateKey()
	if err != nil {
		return "", "", err
	}

	// The serial number for the cert
	sn, err := serialNumber()
	if err != nil {
		return "", "", err
	}

	// Create the leaf cert
	template := x509.Certificate{
		SerialNumber:          sn,
		Subject:               pkix.Name{CommonName: s.Name + " Service"},
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		NotAfter:              time.Now().Add(s.expiry()),
		NotBefore:             time.Now().Add(-1 * time.Minute),
	}
	for _, h := range s.Hosts {
		if ip := net.ParseIP(h); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, h)
		}
	}

	bs, err := x509.CreateCertificate(
		rand.Reader, &template, s.caCertTemplate, signer.Public(), s.caSigner)
	if err != nil {
		return "", "", err
	}
	var buf bytes.Buffer
	err = pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: bs})
	if err != nil {
		return "", "", err
	}

	return buf.String(), keyPEM, nil
}

func (s *GenSource) generateCA() error {
	// Create the private key we'll use for this CA cert.
	signer, _, err := s.privateKey()
	if err != nil {
		return err
	}
	s.caSigner = signer

	// The serial number for the cert
	sn, err := serialNumber()
	if err != nil {
		return err
	}

	signerKeyId, err := keyId(signer.Public())
	if err != nil {
		return err
	}

	// Create the CA cert
	template := x509.Certificate{
		SerialNumber:          sn,
		Subject:               pkix.Name{CommonName: s.Name + " CA"},
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:                  true,
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		NotBefore:             time.Now().Add(-1 * time.Minute),
		AuthorityKeyId:        signerKeyId,
		SubjectKeyId:          signerKeyId,
	}

	bs, err := x509.CreateCertificate(
		rand.Reader, &template, &template, signer.Public(), signer)
	if err != nil {
		return err
	}

	var buf bytes.Buffer
	err = pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: bs})
	if err != nil {
		return err
	}

	s.caCert = buf.Bytes()
	s.caCertTemplate = &template

	return nil
}

// privateKey returns a new ECDSA-based private key. Both a crypto.Signer
// and the key in PEM format are returned.
func (s *GenSource) privateKey() (crypto.Signer, string, error) {
	pk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, "", err
	}

	bs, err := x509.MarshalECPrivateKey(pk)
	if err != nil {
		return nil, "", err
	}

	var buf bytes.Buffer
	err = pem.Encode(&buf, &pem.Block{Type: "EC PRIVATE KEY", Bytes: bs})
	if err != nil {
		return nil, "", err
	}

	return pk, buf.String(), nil
}

// serialNumber generates a new random serial number.
func serialNumber() (*big.Int, error) {
	return rand.Int(rand.Reader, (&big.Int{}).Exp(big.NewInt(2), big.NewInt(159), nil))
}

// keyId returns a x509 KeyId from the given signing key. The key must be
// an *ecdsa.PublicKey currently, but may support more types in the future.
func keyId(raw interface{}) ([]byte, error) {
	switch raw.(type) {
	case *ecdsa.PublicKey:
	default:
		return nil, fmt.Errorf("invalid key type: %T", raw)
	}

	// This is not standard; RFC allows any unique identifier as long as they
	// match in subject/authority chains but suggests specific hashing of DER
	// bytes of public key including DER tags.
	bs, err := x509.MarshalPKIXPublicKey(raw)
	if err != nil {
		return nil, err
	}

	// String formatted
	kID := sha256.Sum256(bs)
	return []byte(strings.Replace(fmt.Sprintf("% x", kID), " ", ":", -1)), nil
}

// parseCert parses the x509 certificate from a PEM-encoded value.
func parseCert(pemValue []byte) (*x509.Certificate, error) {
	// The _ result below is not an error but the remaining PEM bytes.
	block, _ := pem.Decode(pemValue)
	if block == nil {
		return nil, fmt.Errorf("no PEM-encoded data found")
	}

	if block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("first PEM-block should be CERTIFICATE type")
	}

	return x509.ParseCertificate(block.Bytes)
}

// decodeCerts decodes a caBundle ([]byte) into a list of certs ([][]byte)
func decodeCerts(caBundle []byte, log hclog.Logger) tls.Certificate {
	certs := tls.Certificate{}
	remainder := caBundle
	var next *pem.Block
	for {
		next, remainder = pem.Decode(remainder)
		if next == nil {
			break
		}
		if next.Type == "CERTIFICATE" {
			certs.Certificate = append(certs.Certificate, next.Bytes)
		} else {
			log.Warn("unexpected pem block type in caBundle, ignoring", "type", next.Type)
		}
	}
	return certs
}

// prependLastCA returns a new CA bundle:
// [0] last CA cert from oldCABundle
// [1] newCACert
func prependLastCA(newCACert, oldCABundle []byte, log hclog.Logger) ([]byte, error) {
	// Decode the certs from the old CA bundle
	oldCerts := decodeCerts(oldCABundle, log)
	// Append the old CA if it exists
	newBundle := []byte{}
	if len(oldCerts.Certificate) > 0 {
		last := oldCerts.Certificate[len(oldCerts.Certificate)-1]
		var buf bytes.Buffer
		if err := pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: last}); err != nil {
			return nil, fmt.Errorf("failed to encode old CA cert: %w", err)
		}
		newBundle = append(newBundle, buf.Bytes()...)
	}
	// Then append the new CA
	newBundle = append(newBundle, newCACert...)
	return newBundle, nil
}
