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

## Agent Binary

Injected init and sidecar containers use `vault` by default. For an agent image
that contains only `vault-client`, set these pod annotations alongside the usual
injection and authentication annotations:

```yaml
vault.hashicorp.com/agent-image: "your-registry/vault-client:your-tag"
vault.hashicorp.com/agent-binary: "vault-client"
```

The binary selection applies to agent startup (including ConfigMap-based
configuration) and token revocation when `vault.hashicorp.com/agent-revoke-on-shutdown`
is enabled. Supported binary names are `vault` and `vault-client`; paths and
additional arguments are not accepted. An empty pod annotation selects `vault`.
The image must provide the selected binary on `PATH` and, for token revocation,
at `/bin/<binary>`, as well as the shell and utilities used by injected commands.

Set the injector-wide default with `vault-k8s agent-inject -vault-binary=vault-client`
or the injector environment variable `AGENT_INJECT_VAULT_BINARY=vault-client`.
As with existing injector settings, the environment variable takes precedence
over the flag, and a pod annotation overrides the injector default. Configure a
matching agent image separately; selecting a binary does not change the image.
With Helm, the environment variable can be supplied through
`injector.extraEnvironmentVars.AGENT_INJECT_VAULT_BINARY`; a dedicated chart value
and external configuration-reference documentation remain follow-up work.

This setting does not affect Vault server startup, probes, or shutdown commands,
nor does it rewrite user-supplied template commands or container JSON patches.

## Installation

`vault-k8s` is distributed in multiple forms:

  * The recommended installation method is the official
    [Vault Helm chart](https://github.com/hashicorp/vault-helm). This will
    automatically configure the Vault and Kubernetes integration to run within
    an existing Kubernetes cluster.

  * A Docker image [`hashicorp/vault-k8s`](https://hub.docker.com/r/hashicorp/vault-k8s) is available. This can be used to manually run `vault-k8s` within a scheduled environment.

  * Raw binaries are available in the [HashiCorp releases directory](https://releases.hashicorp.com/vault-k8s/). These can be used to run vault-k8s directly or build custom packages.
