package cert

import (
	"context"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// hasOpenSSL is used to determine if the openssl CLI exists for unit tests.
var hasOpenSSL bool

func init() {
	_, err := exec.LookPath("openssl")
	hasOpenSSL = err == nil
}

// Test that valid certificates are generated
func TestGenSource_valid(t *testing.T) {
	t.Parallel()

	if !hasOpenSSL {
		t.Skip("openssl not found")
		return
	}

	// Generate the bundle
	source := testGenSource()
	bundle, err := source.Certificate(context.Background(), nil)
	require.NoError(t, err)
	testBundleVerify(t, &bundle)
}

// Test that certs are regenerated near expiry
func TestGenSource_expiry(t *testing.T) {
	t.Parallel()

	if !hasOpenSSL {
		t.Skip("openssl not found")
		return
	}

	// Generate the bundle
	source := testGenSource()
	source.Expiry = 5 * time.Second
	source.ExpiryWithin = 2 * time.Second

	// First bundle
	bundle, err := source.Certificate(context.Background(), nil)
	require.NoError(t, err)
	testBundleVerify(t, &bundle)

	// Generate again
	start := time.Now()
	next, err := source.Certificate(context.Background(), &bundle)
	dur := time.Now().Sub(start)
	require.NoError(t, err)
	require.False(t, bundle.Equal(&next))
	require.True(t, dur > time.Second)
	testBundleVerify(t, &bundle)
}

func testGenSource() *GenSource {
	return &GenSource{
		Name:  "Test",
		Hosts: []string{"127.0.0.1", "localhost"},
	}
}

// testBundle returns a valid bundle.
func testBundle(t *testing.T) *Bundle {
	source := testGenSource()
	bundle, err := source.Certificate(context.Background(), nil)
	require.NoError(t, err)
	return &bundle
}

// testBundleDir writes the bundle contents to a directory and returns the
// directory. The directory must be removed by the caller. The files in the
// directory are ca.pem, leaf.pem, and leaf.key.pem.
func testBundleDir(t *testing.T, bundle *Bundle, dir string) string {
	if dir == "" {
		// Create a temporary directory for storing the certs
		td, err := ioutil.TempDir("", "consul")
		require.NoError(t, err)
		dir = td
	}

	// Write the cert
	require.NoError(t, ioutil.WriteFile(filepath.Join(dir, "ca.pem"), bundle.CACert, 0644))
	require.NoError(t, ioutil.WriteFile(filepath.Join(dir, "leaf.pem"), bundle.Cert, 0644))
	require.NoError(t, ioutil.WriteFile(filepath.Join(dir, "leaf.key.pem"), bundle.Key, 0644))

	return dir
}

// testBundleVerify verifies that a bundle is valid with OpenSSL (if installed).
func testBundleVerify(t *testing.T, bundle *Bundle) {
	require := require.New(t)

	// Create a temporary directory for storing the certs
	td := testBundleDir(t, bundle, "")
	defer os.RemoveAll(td)

	// Use OpenSSL to verify so we have an external, known-working process
	// that can verify this outside of our own implementations.
	cmd := exec.Command(
		"openssl", "verify", "-verbose", "-CAfile", "ca.pem", "leaf.pem")
	cmd.Dir = td
	output, err := cmd.Output()
	t.Log(string(output))
	require.NoError(err)
}
