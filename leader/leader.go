package leader

import (
	"context"
	"sync/atomic"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/hashicorp/go-hclog"
	operator_leader "github.com/operator-framework/operator-lib/leader"
	"k8s.io/client-go/kubernetes"
)

type Elector interface {
	// IsLeader returns whether this host is the leader
	IsLeader() (bool, error)
}

type LeaderForLife struct {
	isLeader atomic.Value
}

// New returns a Elector that uses the operator-sdk's leader for life elector
func New(ctx context.Context, logger hclog.Logger, clientset kubernetes.Interface, exitOnError chan error) *LeaderForLife {
	le := &LeaderForLife{}
	le.isLeader.Store(false)

	go func() {
		// The Become() function blocks until this replica becomes the "leader",
		// by creating a ConfigMap with an OwnerReference. Another replica can
		// become the leader when the current leader replica stops running, and
		// the Kubernetes garbage collector deletes the vault-k8s-leader
		// ConfigMap.

		// New exponential backoff with 10 retries
		expBo := backoff.NewExponentialBackOff()
		expBo.MaxInterval = time.Second * 30
		bo := backoff.WithMaxRetries(expBo, 10)

		err := backoff.Retry(func() error {
			if err := operator_leader.Become(ctx, "vault-k8s-leader"); err != nil {
				logger.Error("Trouble becoming leader", "error", err)
				return err
			}
			return nil
		}, bo)

		if err != nil {
			// Signal the caller to shutdown the injector server, since Become()
			// failed all the retries
			exitOnError <- err
			return
		}

		le.isLeader.Store(true)
	}()

	return le
}

// IsLeader returns whether this host is the leader
func (le *LeaderForLife) IsLeader() (bool, error) {
	leaderStatus := le.isLeader.Load().(bool)
	return leaderStatus, nil
}
