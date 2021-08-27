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
func New(ctx context.Context, logger hclog.Logger, clientset kubernetes.Interface) *LeaderForLife {
	le := &LeaderForLife{}
	le.isLeader.Store(false)

	go func() {
		// This function blocks until this replica becomes the "leader", which
		// means it creates a ConfigMap with an OwnerReference. Another replica can
		// become the leader when the current leader replica stops running, and
		// the Kubernetes garbage collector deletes the vault-k8s-leader
		// ConfigMap.

		// New exponential backoff with unlimited retries
		bo := backoff.NewExponentialBackOff()
		bo.MaxInterval = time.Second * 30
		bo.MaxElapsedTime = 0
		ticker := backoff.NewTicker(bo)
		defer ticker.Stop()

		for range ticker.C {
			if err := operator_leader.Become(ctx, "vault-k8s-leader"); err != nil {
				logger.Error("trouble becoming leader, will retry", "error", err)
				continue
			}
			break
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
