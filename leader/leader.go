package leader

import (
	"context"
	"sync/atomic"

	"github.com/hashicorp/go-hclog"
	operator_leader "github.com/operator-framework/operator-lib/leader"
)

type Elector interface {
	IsLeader() (bool, error)
}

type LeaderForLife struct {
	isLeader atomic.Value
}

// New returns a Elector that uses the operator-sdk's leader for life elector
func New(ctx context.Context, logger hclog.Logger) *LeaderForLife {
	logger.Debug("starting leader.New()")
	le := &LeaderForLife{}
	le.isLeader.Store(false)
	go func() {
		err := operator_leader.Become(ctx, "vault-k8s-leader")
		if err != nil {
			logger.Error("trouble becoming leader:", "error", err)
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
