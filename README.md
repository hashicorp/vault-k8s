# Vault + Kubernetes (vault-k8s)

> :warning: **Please note**: We take Vault's security and our users' trust very seriously. If 
you believe you have found a security issue in Vault K8s, _please responsibly disclose_ 
by contacting us at [security@hashicorp.com](mailto:security@hashicorp.com).

The `vault-k8s` binary includes first-class integrations between Vault and
Kubernetes.  Currently the only integration in this repository is the 
Vault Agent Sidecar Injector (`agent-inject`).  In the future more integrations 
will be found here.

The Kubernetes integrations with Vault are
[documented directly on the Vault website](https://www.vaultproject.io/docs/platform/k8s/index.html).
This README will present a basic overview of each use case, but for full
documentation please reference the Vault website.

This project is versioned separately from Vault. Supported Vault versions
for each feature will be noted below. By versioning this project separately,
we can iterate on Kubernetes integrations more quickly and release new versions
without forcing Vault users to do a full Vault upgrade.

## Features

  * [**Agent Inject**](https://www.vaultproject.io/docs/platform/k8s/injector/index.html):
    Agent Inject is a mutation webhook controller that injects Vault Agent containers 
    into pods meeting specific annotation criteria.
    _(Requires Vault 1.3.1+)_

## Installation

`vault-k8s` is distributed in multiple forms:

  * The recommended installation method is the official
    [Vault Helm chart](https://github.com/hashicorp/vault-helm). This will
    automatically configure the Vault and Kubernetes integration to run within
    an existing Kubernetes cluster.

  * A Docker image [`hashicorp/vault-k8s`](https://hub.docker.com/r/hashicorp/vault-k8s) is available. This can be used to manually run `vault-k8s` within a scheduled environment.

  * Raw binaries are available in the [HashiCorp releases directory](https://releases.hashicorp.com/vault-k8s/). These can be used to run vault-k8s directly or build custom packages.
