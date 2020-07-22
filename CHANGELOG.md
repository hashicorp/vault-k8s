## Unreleased

Features:
* Added annotations to configure agent caching/listener: [GH-132](https://github.com/hashicorp/vault-k8s/pull/132)

Improvements:
* Injected agents are now configured with `readOnlyRootFilesystem: true`: [GH-142](https://github.com/hashicorp/vault-k8s/pull/142)
* Added additional security contexts for better integration with restrictive PSPs: [GH-153](https://github.com/hashicorp/vault-k8s/pull/153)

## 0.4.0 (June 2, 2020)

Features:
* Added annotations/envs to change the UID and GID of the Vault Agent process: [GH-60](https://github.com/hashicorp/vault-k8s/pull/60)
* Added command-line options, annotations, and envs for `run-as-same-user` and `set-security-context`: [GH-131](https://github.com/hashicorp/vault-k8s/pull/131)

Improvements:

Bugs:

## 0.3.0 (March 5th, 2020)

Features:

* Added flag/env to change log-format for the injector: [GH-50](https://github.com/hashicorp/vault-k8s/pull/50)
* Added annotation to run a command after template has been rendered: [GH-57](https://github.com/hashicorp/vault-k8s/pull/57)
* Added annotation to configure Vault namespace: [GH-82](https://github.com/hashicorp/vault-k8s/pull/82)
* Added annotation to configure Vault Agent log level: [GH-82](https://github.com/hashicorp/vault-k8s/pull/82)
* Added annotation that shares the Vault Agent token in the shared volume: [GH-77](https://github.com/hashicorp/vault-k8s/pull/77)
* Added annotations to configure token revocation during shutdown: [GH-67](https://github.com/hashicorp/vault-k8s/pull/67)
* Added annotations to customize render path of secrets (per secret and global default): [GH-71](https://github.com/hashicorp/vault-k8s/pull/71)
* Added annotation to preserve case: [GH-71](https://github.com/hashicorp/vault-k8s/pull/71)
* Added annotation to configure if the init container runs first or last: [GH-91](https://github.com/hashicorp/vault-k8s/pull/91)

Improvements:

* Added `GO111MODULE` flag to `Makefile`: [GH-61](https://github.com/hashicorp/vault-k8s/pull/61)
* Changed token location from `/home/vault/.token` to `/home/vault/.vault-token`: [GH-66](https://github.com/hashicorp/vault-k8s/pull/66)

Bugs:
* Fixed bug where secret volumes were not shared with other init containers: [GH-91](https://github.com/hashicorp/vault-k8s/pull/91)

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
