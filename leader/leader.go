package leader

import (
	"context"
	"fmt"
	"os"
	"sync/atomic"

	"github.com/hashicorp/go-hclog"
	operator_leader "github.com/operator-framework/operator-lib/leader"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
)

type Elector interface {
	IsLeader() (bool, error)
}

type LeaderForLife struct {
	isLeader atomic.Value
}

// New returns a Elector that uses the operator-sdk's leader for life elector
func New(ctx context.Context, logger hclog.Logger, clientset kubernetes.Interface) *LeaderForLife {
	logger.Debug("starting leader.New()")
	le := &LeaderForLife{}
	le.isLeader.Store(false)

	if err := setLeaderLabel(ctx, clientset, false); err != nil {
		logger.Warn("trouble setting leader=false", "err", err)
	}
	go func() {
		// This function blocks until this replica becomes the "leader", which
		// means it creates a ConfigMap with an ownerref. Another replica can
		// become the leader when the current leader replica stops running, and
		// the Kubernetes garbage collector deletes the vault-k8s-leader
		// ConfigMap.
		err := operator_leader.Become(ctx, "vault-k8s-leader")
		if err != nil {
			logger.Error("trouble becoming leader:", "error", err)
		}
		le.isLeader.Store(true)
		if err := setLeaderLabel(ctx, clientset, true); err != nil {
			logger.Warn("trouble setting leader=true label", "err", err)
		}
	}()

	return le
}

// IsLeader returns whether this host is the leader
func (le *LeaderForLife) IsLeader() (bool, error) {
	leaderStatus := le.isLeader.Load().(bool)
	return leaderStatus, nil
}

func setLeaderLabel(ctx context.Context, clientset kubernetes.Interface, label bool) error {
	namespace := os.Getenv("NAMESPACE")
	if namespace == "" {
		return fmt.Errorf("could not determine namespace of pod")
	}
	podName := os.Getenv("POD_NAME")
	if podName == "" {
		return fmt.Errorf("could not determine pod name")
	}
	patch := fmt.Sprintf(`[{
		"op": "replace",
		"path": "/metadata/labels/leader",
		"value": "%t"
	}]`, label)
	_, err := clientset.CoreV1().Pods(namespace).Patch(ctx, podName, types.JSONPatchType, []byte(patch), v1.PatchOptions{})
	if err != nil {
		return fmt.Errorf("failed to set leader=%t on pod %s, namespace %s: %w",
			label, podName, namespace, err)
	}
	return nil
}
