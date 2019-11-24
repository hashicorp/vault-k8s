package cert

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"strings"
	"sync"
	"time"
)

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
}

// Certificate implements Source
func (s *GenSource) Certificate(ctx context.Context, last *Bundle) (Bundle, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var result Bundle

	// If we have no CA, generate it for the first time.
	if len(s.caCert) == 0 {
		if err := s.generateCA(); err != nil {
			return result, err
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

		waitTime := cert.NotAfter.Sub(time.Now()) - s.expiryWithin()
		if waitTime < 0 {
			waitTime = 1 * time.Millisecond
		}

		timer := time.NewTimer(waitTime)
		defer timer.Stop()

		select {
		case <-timer.C:
			// Fall through, generate cert

		case <-ctx.Done():
			return result, ctx.Err()
		}
	}

	// Generate cert, set it on the result, and return
	cert, key, err := s.generateCert()
	if err == nil {
		result.Cert = []byte(cert)
		result.Key = []byte(key)
	}

	return result, err
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
