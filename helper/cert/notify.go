package cert

import (
	"context"
	"time"

	"github.com/hashicorp/go-hclog"
)

func NewNotify(ctx context.Context, newBundle chan<- Bundle, source Source, logger hclog.Logger) *Notify {
	return &Notify{
		ctx:    ctx,
		ch:     newBundle,
		source: source,
		logger: logger,
	}
}

// Notify sends an update on a channel whenever a source has an updated
// cert bundle. This struct maintains state, performs backoffs, etc.
type Notify struct {
	ctx    context.Context
	logger hclog.Logger

	// ch is where the notifications for new bundles are sent. If this
	// blocks then the notify loop will also be blocked, so downstream
	// users should process this channel in a timely manner.
	ch chan<- Bundle

	// source is the source of certificates.
	source Source
}

// Run starts the notifier. This blocks and should be started in a goroutine.
// To stop the notifier, the passed in context can be cancelled OR Stop can
// be called. In either case, Stop will block until the notifier is stopped.
func (n *Notify) Run() {
	var last *Bundle
	retryTicker := time.NewTicker(5 * time.Second)
	defer retryTicker.Stop()
	first := true
	for {
		if first {
			// On the first pass we want to check for the cert immediately.
			first = false
		} else {
			// On all other passes we want to wait for 5 seconds, interruptibly.
			select {
			case <-n.ctx.Done():
				return
			case <-retryTicker.C:
			}
		}

		next, err := n.source.Certificate(n.ctx, last)
		if err != nil {
			n.logger.Warn("error loading next cert", "error", err.Error())
			continue
		}

		// If the returned bundles are equal, then ignore it.
		if last.Equal(&next) {
			continue
		}
		last = &next
		// Send the certificate out, but in case it hangs, because
		// the certificates aren't being pulled off the channel quickly
		// enough, also listen for other stops.
		select {
		case n.ch <- next:
		case <-n.ctx.Done():
			return
		}
	}
}
