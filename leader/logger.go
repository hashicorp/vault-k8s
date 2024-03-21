// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

// Borrowed from https://github.com/hashicorp/consul-api-gateway/blob/4ca5788fa357e389336049bd652f28309ee29d4a/internal/k8s/logger.go

package leader

import (
	"github.com/go-logr/logr"

	"github.com/hashicorp/go-hclog"
)

func fromHCLogger(log hclog.Logger) logr.Logger {
	return logr.New(&logger{log})
}

// logger is a LogSink that wraps hclog
type logger struct {
	hclog.Logger
}

// Verify that it actually implements the interface
var _ logr.LogSink = logger{}

func (l logger) Init(logr.RuntimeInfo) {
}

func (l logger) Enabled(_ int) bool {
	return true
}

// Info actually logs as debug here, since operator-lib's Info logs are pretty
// chatty, and seem to fit better as debug
func (l logger) Info(_ int, msg string, keysAndValues ...interface{}) {
	if l.Logger.GetLevel() <= hclog.Debug {
		l.Logger.Debug(msg, keysAndValues...)
	}
}

func (l logger) Error(err error, msg string, keysAndValues ...interface{}) {
	keysAndValues = append([]interface{}{"error", err}, keysAndValues...)
	l.Logger.Error(msg, keysAndValues...)
}

func (l logger) WithValues(keysAndValues ...interface{}) logr.LogSink {
	return &logger{l.With(keysAndValues...)}
}

func (l logger) WithName(name string) logr.LogSink {
	return &logger{l.Named(name)}
}
