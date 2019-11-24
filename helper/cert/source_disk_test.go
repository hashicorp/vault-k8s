package cert

import (
	"context"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// Test that an error is immediately returned with no files
func TestGenDisk_noExist(t *testing.T) {
	t.Parallel()
	require := require.New(t)

	td, err := ioutil.TempDir("", "consul")
	require.NoError(err)
	defer os.RemoveAll(td)

	source := &DiskSource{
		CertPath: filepath.Join(td, "nope.pem"),
		KeyPath:  filepath.Join(td, "nope.pem"),
		CAPath:   filepath.Join(td, "nope.pem"),
	}
	_, err = source.Certificate(context.Background(), nil)
	require.Error(err)
}

// Test that the initial bundles are returned
func TestGenDisk_initial(t *testing.T) {
	t.Parallel()
	require := require.New(t)

	td := testBundleDir(t, testBundle(t), "")
	defer os.RemoveAll(td)

	source := &DiskSource{
		CertPath: filepath.Join(td, "leaf.pem"),
		KeyPath:  filepath.Join(td, "leaf.key.pem"),
		CAPath:   filepath.Join(td, "ca.pem"),
	}
	bundle, err := source.Certificate(context.Background(), nil)
	require.NoError(err)
	testBundleVerify(t, &bundle)
}

// Test that cert will block until the contents change
func TestGenDisk_blockWrite(t *testing.T) {
	t.Parallel()
	require := require.New(t)

	td := testBundleDir(t, testBundle(t), "")
	defer os.RemoveAll(td)

	source := &DiskSource{
		CertPath:     filepath.Join(td, "leaf.pem"),
		KeyPath:      filepath.Join(td, "leaf.key.pem"),
		CAPath:       filepath.Join(td, "ca.pem"),
		pollInterval: 5 * time.Millisecond, // Fast for tests
	}
	bundle, err := source.Certificate(context.Background(), nil)
	require.NoError(err)
	testBundleVerify(t, &bundle)

	// Start waiting for the next bundle
	nextCh := make(chan *Bundle, 1)
	go func() {
		next, err := source.Certificate(context.Background(), &bundle)
		require.NoError(err)
		nextCh <- &next
	}()

	// It should not be received yet since no updates
	select {
	case <-nextCh:
		t.Fatal("should not have received next")
	case <-time.After(1000 * time.Millisecond):
	}

	// Update the file
	testBundleDir(t, testBundle(t), td)

	// It should not be received yet since no updates
	select {
	case <-time.After(500 * time.Millisecond):
		t.Fatal("should receive update")

	case next := <-nextCh:
		testBundleVerify(t, next)
	}
}
