package cert

import (
	"context"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	adminv1 "k8s.io/api/admissionregistration/v1"
	adminv1beta "k8s.io/api/admissionregistration/v1beta1"
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

	// Pretend this host is the leader
	source.LeaderElector = newFakeLeader(true)

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

	// Pretend this host is the follower
	source.LeaderElector = newFakeLeader(false)

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

type FakeLeader struct {
	leader bool
}

func newFakeLeader(isLeader bool) *FakeLeader {
	return &FakeLeader{leader: isLeader}
}

func (fl *FakeLeader) IsLeader() (bool, error) {
	return fl.leader, nil
}

func TestGensource_prependLastCA(t *testing.T) {
	// Construct caBundle's (old and new) to use in the test cases
	new1 := testGenSource()
	newBundle1, err := new1.Certificate(context.Background(), nil)
	require.NoError(t, err)
	new2 := testGenSource()
	newBundle2, err := new2.Certificate(context.Background(), nil)
	require.NoError(t, err)

	old1 := testGenSource()
	oldBundle1, err := old1.Certificate(context.Background(), nil)
	require.NoError(t, err)
	old2 := testGenSource()
	oldBundle2, err := old2.Certificate(context.Background(), nil)
	require.NoError(t, err)

	tests := map[string]struct {
		oldCAs   []byte
		expected []byte
	}{
		"no old CAs": {
			oldCAs:   nil,
			expected: newBundle1.CACert,
		},
		"one old CA": {
			oldCAs:   oldBundle1.CACert,
			expected: append(oldBundle1.CACert, newBundle1.CACert...),
		},
		"two old CAs": {
			oldCAs:   append(oldBundle1.CACert, oldBundle2.CACert...),
			expected: append(oldBundle2.CACert, newBundle1.CACert...),
		},
		"invalid old CAs": {
			oldCAs:   []byte("not a cert"),
			expected: newBundle1.CACert,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			result, err := prependLastCA(newBundle1.CACert, tc.oldCAs, hclog.Default())
			require.NoError(t, err)
			assert.Equal(t, tc.expected, result)

			// Run again with the output from previous
			result2, err := prependLastCA(newBundle2.CACert, result, hclog.Default())
			require.NoError(t, err)
			assert.Equal(t, append(newBundle1.CACert, newBundle2.CACert...), result2)
		})
	}
}

func TestGensource_getExistingCA(t *testing.T) {
	tests := map[string]struct {
		existingBundle []byte
		expectBundle   []byte
	}{
		"no existing CA": {
			existingBundle: nil,
			expectBundle:   nil,
		},
		"one existing CA": {
			existingBundle: []byte("exists"),
			expectBundle:   []byte("exists"),
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			s := testGenSource()
			s.WebhookName = "test"

			betaCfg := &adminv1beta.MutatingWebhookConfiguration{
				ObjectMeta: metav1.ObjectMeta{Name: s.WebhookName},
				Webhooks: []adminv1beta.MutatingWebhook{
					{
						ClientConfig: adminv1beta.WebhookClientConfig{
							CABundle: tc.existingBundle,
						},
					},
				},
			}
			v1Cfg := &adminv1.MutatingWebhookConfiguration{
				ObjectMeta: metav1.ObjectMeta{Name: s.WebhookName},
				Webhooks: []adminv1.MutatingWebhook{
					{
						ClientConfig: adminv1.WebhookClientConfig{
							CABundle: tc.existingBundle,
						},
					},
				},
			}
			t.Run("v1", func(t *testing.T) {
				s.AdminAPIVersion = adminv1.SchemeGroupVersion.Version
				s.K8sClient = fake.NewSimpleClientset(v1Cfg)
				result := s.getExistingCA(context.Background())
				assert.Equal(t, tc.expectBundle, result)
			})
			t.Run("v1beta1", func(t *testing.T) {
				s.AdminAPIVersion = adminv1beta.SchemeGroupVersion.Version
				s.K8sClient = fake.NewSimpleClientset(betaCfg)
				result := s.getExistingCA(context.Background())
				assert.Equal(t, tc.expectBundle, result)
			})
		})
	}

	t.Run("unknown admin API version", func(t *testing.T) {
		s := testGenSource()
		s.AdminAPIVersion = "invalid"
		s.K8sClient = fake.NewSimpleClientset()
		result := s.getExistingCA(context.Background())
		assert.Empty(t, result)
	})
	t.Run("no caBundle v1", func(t *testing.T) {
		s := testGenSource()
		s.WebhookName = "test"
		s.AdminAPIVersion = adminv1.SchemeGroupVersion.Version
		s.K8sClient = fake.NewSimpleClientset(&adminv1.MutatingWebhookConfiguration{
			ObjectMeta: metav1.ObjectMeta{Name: s.WebhookName},
		})
		result := s.getExistingCA(context.Background())
		assert.Empty(t, result)
	})
	t.Run("no caBundle v1beta1", func(t *testing.T) {
		s := testGenSource()
		s.WebhookName = "test"
		s.AdminAPIVersion = adminv1beta.SchemeGroupVersion.Version
		s.K8sClient = fake.NewSimpleClientset(&adminv1beta.MutatingWebhookConfiguration{
			ObjectMeta: metav1.ObjectMeta{Name: s.WebhookName},
		})
		result := s.getExistingCA(context.Background())
		assert.Empty(t, result)
	})

}
