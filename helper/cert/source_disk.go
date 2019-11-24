package cert

import (
	"context"
	"fmt"
	"io/ioutil"
	"time"

	"github.com/radovskyb/watcher"
)

// DiskSource sources certificates from files on disk. It sets up a
// file watcher that detects when the content changes and sends an update
// on the configured channel.
type DiskSource struct {
	CertPath string // CertPath is the path to the PEM-encoded cert
	KeyPath  string // KeyPath is the path to the PEM-encoded private key
	CAPath   string // CAPath is the path to the PEM-encoded CA root bundle (optional)

	pollInterval time.Duration
}

// Certificate implements Source
func (s *DiskSource) Certificate(ctx context.Context, last *Bundle) (Bundle, error) {
	// Setup the poll interval
	pollInterval := s.pollInterval
	if pollInterval == 0 {
		pollInterval = 250 * time.Millisecond
	}

	// Setup the file watcher. We do this first so taht there isn't a race
	// between reading the files below initially and detecting a change.
	w := watcher.New()
	defer w.Close()
	w.SetMaxEvents(1)
	if err := w.Add(s.CertPath); err != nil {
		return Bundle{}, err
	}
	if err := w.Add(s.KeyPath); err != nil {
		return Bundle{}, err
	}
	go w.Start(pollInterval)
	w.Wait()

	// At this point the file watcher is started and we can start reading
	// events. But we want to load the files as-is right now so we can
	// detect if there is change.
	for {
		// Always load the current. If they don't exist yet or something
		// just return the error since the higher level system will retry.
		bundle, err := s.loadCerts()
		if err != nil {
			return bundle, err
		}

		// If there was no prior certificate bundle or the bundle has
		// changed, then return it.
		if last == nil || !last.Equal(&bundle) {
			return bundle, nil
		}

		// No change in the bundle, let's wait for a change from the watcher
		select {
		case <-w.Event:
			// Fall through the loop so that we reload the certs from disk

		case err := <-w.Error:
			return bundle, err

		case <-w.Closed:
			return bundle, fmt.Errorf("filesystem watcher closed")

		case <-ctx.Done():
			return bundle, ctx.Err()
		}
	}
}

func (s *DiskSource) loadCerts() (Bundle, error) {
	certPEMBlock, err := ioutil.ReadFile(s.CertPath)
	if err != nil {
		return Bundle{}, err
	}

	keyPEMBlock, err := ioutil.ReadFile(s.KeyPath)
	if err != nil {
		return Bundle{}, err
	}

	var caPEMBlock []byte
	if s.CAPath != "" {
		caPEMBlock, err = ioutil.ReadFile(s.CAPath)
		if err != nil {
			return Bundle{}, err
		}
	}

	return Bundle{
		Cert:   certPEMBlock,
		Key:    keyPEMBlock,
		CACert: caPEMBlock,
	}, nil
}
