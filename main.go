// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"log"
	"os"

	"github.com/hashicorp/vault-k8s/version"
	"github.com/mitchellh/cli"
)

func main() {
	c := cli.NewCLI("vault-k8s", version.Version)
	c.Args = os.Args[1:]
	c.Commands = Commands
	c.HelpFunc = cli.BasicHelpFunc("vault-k8s")

	exitStatus, err := c.Run()
	if err != nil {
		log.Println(err)
	}
	os.Exit(exitStatus)
}
