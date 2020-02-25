## Unreleased

Features:

* Added annotation to change log-format for the injector: [GH-50](https://github.com/hashicorp/vault-k8s/pull/50)
* Added annotation to run a command after template has been rendered: [GH-57](https://github.com/hashicorp/vault-k8s/pull/57)
* Added annotation to configure Vault namespace: [GH-82](https://github.com/hashicorp/vault-k8s/pull/82)
* Added annotation to configure Vault Agent log level: [GH-82](https://github.com/hashicorp/vault-k8s/pull/82)

Improvements:

* Added `GO111MODULE` flag to `Makefile`: [GH-61](https://github.com/hashicorp/vault-k8s/pull/61)
* Changed token location from `/home/vault/.token` to `/home/vault/.vault-token`: [GH-66](https://github.com/hashicorp/vault-k8s/pull/66)
* The annotation `"vault.hashicorp.com/agent-inject-token": "true"` results in a token file containing the lookup-self token: [GH-77](https://github.com/hashicorp/vault-k8s/pull/77)

Bugs:

## 0.2.0 (January 31st, 2020)

Features:

* Added configurable auth mount path annotation and environment variable [GH-23]
* Added kustomize [GH-43]

## 0.1.2 (January 8th, 2020)

Bugs:

* Fixed bug where tlsSkipVerify was true by default [GH-34]

## 0.1.1 (January 2nd, 2020)

Bugs:

* Fixed bug causing pods in kube-system to be rejected [GH-14]

## 0.1.0 (December 17th, 2019)

Initial release
