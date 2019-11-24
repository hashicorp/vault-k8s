package subcommand

import (
	"fmt"
	"path/filepath"

	"github.com/hashicorp/go-multierror"
	"github.com/mitchellh/go-homedir"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// K8SConfig returns a *restclient.Config for initializing a K8S client.
// This configuration first attempts to load a local kubeconfig if a
// path is given. If that doesn't work, then in-cluster auth is used.
func K8SConfig(path string) (*rest.Config, error) {
	// Get the configuration. This can come from multiple sources. We first
	// try kubeconfig it is set directly, then we fall back to in-cluster
	// auth. Finally, we try the default kubeconfig path.
	kubeconfig := path
	if kubeconfig == "" {
		// If kubeconfig is empty, let's first try the default directory.
		// This is must faster than trying in-cluster auth so we try this
		// first.
		dir, err := homedir.Dir()
		if err != nil {
			return nil, fmt.Errorf("error retrieving home directory: %s", err)
		}
		kubeconfig = filepath.Join(dir, ".kube", "config")
	}

	// First try to get the configuration from the kubeconfig value
	config, configErr := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if configErr != nil {
		configErr = fmt.Errorf("error loading kubeconfig: %s", configErr)

		// kubeconfig failed, fall back and try in-cluster config. We do
		// this as the fallback since this makes network connections and
		// is much slower to fail.
		var err error
		config, err = rest.InClusterConfig()
		if err != nil {
			return nil, multierror.Append(configErr, fmt.Errorf(
				"error loading in-cluster config: %s", err))
		}
	}

	return config, nil
}
