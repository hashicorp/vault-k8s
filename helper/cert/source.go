package cert

import (
	"context"
	"reflect"
)

// Source should be implemented by systems that support loading TLS
// certificates. These are run for the lifetime of an application and are
// expected to provide continuous updates to certificates as needed (updates,
// rotation, etc.).
type Source interface {
	// Certificate returns the certificates to use for the TLS listener.
	// If `last` is given, this should block until new certificates are
	// available. If last is nil, then this is an initial certificate request
	// and new certificates should be loaded.
	//
	// If this is a blocking call, a done context should cancel the result
	// and return immediately with an error (usually ctx.Err()).
	//
	// If any errors occur then an error should be returned. Higher level
	// systems should deal with safely backing off to prevent calling this
	// method too frequently.
	Certificate(ctx context.Context, last *Bundle) (Bundle, error)
}

// Bundle is the set of certificates to serve and optionally the CA
// certificate (if available).
type Bundle struct {
	Cert   []byte
	Key    []byte
	CACert []byte // CA cert bundle, optional.
}

// Equal returns true if the two cert bundles contain equivalent certs.
func (b *Bundle) Equal(b2 *Bundle) bool {
	return reflect.DeepEqual(b, b2)
}
