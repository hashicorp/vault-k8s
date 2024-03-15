// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package cert

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/hashicorp/go-hclog"
)

var CertificateValidErr = errors.New("cert still valid, continue to next round")

func NewNotify(ctx context.Context, newBundle chan<- Bundle, notifyOnce chan<- bool, source Source, logger hclog.Logger) *Notify {
	return &Notify{
		ctx:        ctx,
		ch:         newBundle,
		notifyOnce: notifyOnce,
		source:     source,
		logger:     logger,
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
	// used to notify the first time it is run
	notifyOnce chan<- bool

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
	once := sync.Once{}
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
			switch err {
			case CertificateValidErr:
				n.logger.Info("valid cert", "info", err.Error())
			default:
				n.logger.Warn("error loading next cert", "error", err.Error())
			}

			continue
		}

		once.Do(func() {
			go func() {
				n.notifyOnce <- true
			}()
		})

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
