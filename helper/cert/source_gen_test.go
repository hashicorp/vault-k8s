package cert

import (
	"context"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault-k8s/leader"
	"github.com/stretchr/testify/require"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/cache"
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
		Log:   hclog.Default(),
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

func TestGenSource_leader(t *testing.T) {

	if !hasOpenSSL {
		t.Skip("openssl not found")
		return
	}

	// Generate the bundle
	source := testGenSource()

	// Setup test leader service returning this host as the leader
	ts := testLeaderServer(t, testGetHostname(t))
	defer ts.Close()
	source.LeaderElector = leader.NewWithURL(ts.URL)

	source.Namespace = "default"
	source.K8sClient = fake.NewSimpleClientset()
	bundle, err := source.Certificate(context.Background(), nil)
	require.NoError(t, err)
	testBundleVerify(t, &bundle)

	// check that the Secret has been created
	checkSecret, err := source.K8sClient.CoreV1().Secrets(source.Namespace).Get(context.Background(), certSecretName, metav1.GetOptions{})
	require.NoError(t, err)
	require.Equal(t, checkSecret.Data["cert"], bundle.Cert,
		"cert in the Secret should've matched what was returned from source.Certificate()",
	)
	require.Equal(t, checkSecret.Data["key"], bundle.Key,
		"key in the Secret should've matched what was returned from source.Certificate()",
	)
}

func TestGenSource_follower(t *testing.T) {

	if !hasOpenSSL {
		t.Skip("openssl not found")
		return
	}

	// Generate the bundle
	source := testGenSource()

	// Setup a leader elector service that returns a different hostname, so it
	// thinks we're the follower
	ts := testLeaderServer(t, testGetHostname(t)+"not it")
	defer ts.Close()
	source.LeaderElector = leader.NewWithURL(ts.URL)

	// Setup the k8s client with a Secret for a follower to pick up
	source.Namespace = "default"
	secretBundle := testBundle(t)
	source.K8sClient = fake.NewSimpleClientset(&v1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      certSecretName,
			Namespace: source.Namespace,
		},
		Data: map[string][]byte{
			"cert": secretBundle.Cert,
			"key":  secretBundle.Key,
		},
	})

	// setup a Secret informer cache with the fake clientset for followers to use
	factory := informers.NewSharedInformerFactoryWithOptions(source.K8sClient, 0, informers.WithNamespace(source.Namespace))
	secrets := factory.Core().V1().Secrets()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go secrets.Informer().Run(ctx.Done())
	synced := cache.WaitForCacheSync(ctx.Done(), secrets.Informer().HasSynced)
	require.True(t, synced, "timeout syncing Secrets informer")
	source.SecretsCache = secrets

	bundle, err := source.Certificate(ctx, nil)
	require.NoError(t, err)

	require.Equal(t, secretBundle.Cert, bundle.Cert,
		"cert returned from source.Certificate() should have matched what the Secret was created with",
	)
	require.Equal(t, secretBundle.Key, bundle.Key,
		"key returned from source.Certificate() should have matched what the Secret was created with",
	)
}

func testLeaderServer(t *testing.T, hostname string) *httptest.Server {
	t.Helper()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lResp := leader.LeaderResponse{
			Name: hostname,
		}
		body, err := json.Marshal(lResp)
		if err != nil {
			t.Fatalf("failed to marshal leader response: %s", err)
		}
		w.WriteHeader(200)
		w.Write(body)
	}))
	return ts
}

func testGetHostname(t *testing.T) string {
	t.Helper()

	host, err := os.Hostname()
	if err != nil {
		t.Fatalf("failed to get hostname for test leader service: %s", err)
	}
	return host
}
