package cert

import (
	"context"
	"log"
	"sync"
	"time"
)

// Notify sends an update on a channel whenever a Source has an updated
// cert bundle. This struct maintains state, performs backoffs, etc.
type Notify struct {
	// Ch is where the notifications for new bundles are sent. If this
	// blocks then the notify loop will also be blocked, so downstream
	// users should process this channel in a timely manner.
	Ch chan<- Bundle

	// Source is the source of certificates.
	Source Source

	mu        sync.Mutex
	ctx       context.Context
	ctxCancel context.CancelFunc
	doneCh    <-chan struct{}
}

// Start starts the notifier. This blocks and should be started in a goroutine.
// To stop the notifier, the passed in context can be cancelled OR Stop can
// be called. In either case, Stop will block until the notifier is stopped.
func (n *Notify) Start(ctx context.Context) {
	ctx, cancelFunc := context.WithCancel(ctx)
	defer cancelFunc()

	doneCh := make(chan struct{})
	defer close(doneCh)

	n.mu.Lock()
	if n.doneCh != nil {
		// Already started
		return
	}
	n.ctx = ctx
	n.ctxCancel = cancelFunc
	n.doneCh = doneCh
	n.mu.Unlock()

	var last *Bundle
	for {
		next, err := n.Source.Certificate(ctx, last)
		if err != nil {
			log.Printf("[ERROR] helper/cert: error loading next cert: %s", err)

			// If the ctx ended, then we exit
			if ctx.Err() != nil {
				return
			}

			time.Sleep(5 * time.Second) // note: maybe should backoff
			continue
		}

		// If the returned bundles are equal, then ignore it.
		if last.Equal(&next) {
			continue
		}
		last = &next

		// Send the update, or quit if we were cancelled
		select {
		case n.Ch <- next:
		case <-ctx.Done():
			return
		}
	}
}

// Stops the notifier. Blocks until stopped. If the notifier isn't running
// this returns immediately.
func (n *Notify) Stop() {
	n.mu.Lock()
	doneCh := n.doneCh
	if n.ctxCancel != nil {
		n.ctxCancel()
		n.ctxCancel = nil
	}
	n.mu.Unlock()

	// Block on the done channel if it exists. If it doesn't exist, then
	// we never started.
	if doneCh != nil {
		<-doneCh
	}
}
