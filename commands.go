package main

import (
	"os"

	cmdInjector "github.com/hashicorp/vault-k8s/subcommand/injector"
	cmdVersion "github.com/hashicorp/vault-k8s/subcommand/version"
	"github.com/hashicorp/vault-k8s/version"
	"github.com/mitchellh/cli"
)

var Commands map[string]cli.CommandFactory

func init() {
	ui := &cli.BasicUi{Writer: os.Stdout, ErrorWriter: os.Stderr}

	Commands = map[string]cli.CommandFactory{
		"agent-inject": func() (cli.Command, error) {
			return &cmdInjector.Command{UI: ui}, nil
		},
		"version": func() (cli.Command, error) {
			return &cmdVersion.Command{UI: ui, Version: version.GetHumanVersion()}, nil
		},
	}
}
