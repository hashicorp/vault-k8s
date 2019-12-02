package flags

import (
	"flag"

	"github.com/hashicorp/consul/command/flags"
)

type K8SFlags struct {
	kubeconfig flags.StringValue
}

func (f *K8SFlags) Flags() *flag.FlagSet {
	fs := flag.NewFlagSet("", flag.ContinueOnError)
	fs.Var(&f.kubeconfig, "kubeconfig",
		"The path to a kubeconfig file to use for authentication. If this is "+
			"blank, the default kubeconfig path (~/.kube/config) will be checked. "+
			"If no kubeconfig is found, in-cluster auth will be used.")
	return fs
}

func (f *K8SFlags) KubeConfig() string {
	return f.kubeconfig.String()
}
