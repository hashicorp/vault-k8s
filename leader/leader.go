package leader

import (
	"context"
	"sync/atomic"

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
		// means it creates a ConfigMap with an ownerref. Another replica can
		// become the leader when the current leader replica stops running, and
		// the Kubernetes garbage collector deletes the vault-k8s-leader
		// ConfigMap.
		err := operator_leader.Become(ctx, "vault-k8s-leader")
		if err != nil {
			logger.Error("trouble becoming leader:", "error", err)
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
