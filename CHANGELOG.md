## Unreleased

## 0.14.1 (November 17, 2021)

Changes:
* Bump the default Vault image to v1.9.0

Improvements:
* Dependency update [GH-304](https://github.com/hashicorp/vault-k8s/pull/304)

## 0.14.0 (October 21, 2021)

Improvements:
* Added options for setting the TLS minimum version (default 1.2) and supported cipher suites: [GH-302](https://github.com/hashicorp/vault-k8s/pull/302)

## 0.13.1 (September 29, 2021)

Changes:
* Bump the default Vault image to v1.8.3

## 0.13.0 (September 15, 2021)

Improvements:
* Continuously retry updating the cert secret: [GH-280](https://github.com/hashicorp/vault-k8s/pull/280)
* Keep the last CA when creating a new one: [GH-287](https://github.com/hashicorp/vault-k8s/pull/287)
* Moved leader election inside vault-k8s: [GH-271](https://github.com/hashicorp/vault-k8s/pull/271)
* Add projected service account support [GH-288](https://github.com/hashicorp/vault-k8s/pull/288)

Bugs:
* Set GVK on AdmissionReview responses in webhook [GH-296](https://github.com/hashicorp/vault-k8s/pull/296)
* Fix a typo in deploy/injector-mutating-webhook.yaml manifest [GH-296](https://github.com/hashicorp/vault-k8s/pull/296)

## 0.12.0 (August 18, 2021)

Features:
* New annotation to allow the user to set the rendered file permission: [GH-277](https://github.com/hashicorp/vault-k8s/pull/277)
* Adds flag and annotation to configure template config `static_secret_render_interval`: [GH-276](https://github.com/hashicorp/vault-k8s/pull/276)

## 0.11.0 (July 28, 2021)

Features:
* Added exit_on_retry_failure flag and annotation: [GH-267](https://github.com/hashicorp/vault-k8s/pull/267)

Improvements:
* Switch the default vault image to come from the hashicorp docker hub org: [GH-270](https://github.com/hashicorp/vault-k8s/pull/270)
* Better support for setting the region when auth type is AWS: [GH-268](https://github.com/hashicorp/vault-k8s/pull/268)
* Added support for K8s v1 Admission API: [GH-273](https://github.com/hashicorp/vault-k8s/pull/273)

## 0.10.2 (June 16, 2021)

Improvements:
* Dependency update: [GH-265](https://github.com/hashicorp/vault-k8s/pull/265)

## 0.10.1 (May 25, 2021)

Bugs:
* Fix agent-inject-token when caching enabled: [GH-290](https://github.com/hashicorp/vault-k8s/pull/250)
* Remove new line from injected token: [GH-290](https://github.com/hashicorp/vault-k8s/pull/250)

## 0.10.0 (April 14, 2021)

Features:
* Added flags/envs to change default resources for all injected containers: [GH-235](https://github.com/hashicorp/vault-k8s/pull/235)
* Added an annotation to use template path on disk: [GH-222](https://github.com/hashicorp/vault-k8s/pull/222)
* Added an annotation and global flag to change default template from map to json: [GH-242](https://github.com/hashicorp/vault-k8s/pull/242)

Improvements:
* Better support for IRSA on AWS/EKS: [GH-169](https://github.com/hashicorp/vault-k8s/pull/169)

## 0.9.0 (March 18, 2021)

Features:
* Added annotation to specify HTTPS proxy on Vault Agent containers: [GH-211](https://github.com/hashicorp/vault-k8s/pull/211)
* Added support for all auto-auth methods: [GH-213](https://github.com/hashicorp/vault-k8s/pull/213)
* Added support for persistent agent caching: [GH-229](https://github.com/hashicorp/vault-k8s/pull/229)
* Arm binaries and images are now being published as part of a release: [GH-221](https://github.com/hashicorp/vault-k8s/pull/221)

Improvements:

Bugs:

## 0.8.0 (February 2, 2021)

Features:
* Added annotation to copy mounts from a specified container: [GH-212](https://github.com/hashicorp/vault-k8s/pull/212)
* Added annotation to change log format for the agent: [GH-200](https://github.com/hashicorp/vault-k8s/pull/200)

## 0.7.0 (January 5, 2021)

Features:
* Added UBI container image: [GH-183](https://github.com/hashicorp/vault-k8s/pull/183)
* Support for multiple replicas with auto-tls: [GH-198](https://github.com/hashicorp/vault-k8s/pull/198)

## 0.6.0 (October 20, 2020)

Features:
* Added `extra-secret` annotation for mounting kube-secrets: [GH-119](https://github.com/hashicorp/vault-k8s/pull/119)

Improvements:
* Resource limits and requests can be disabled via annotation: [GH-174](https://github.com/hashicorp/vault-k8s/pull/174)

## 0.5.0 (August 24, 2020)

Features:
* Added annotations to configure agent caching/listener: [GH-132](https://github.com/hashicorp/vault-k8s/pull/132)
* Added annotation for specifying filenames and paths within the secrets volume: [GH-158](https://github.com/hashicorp/vault-k8s/pull/158)
* Added prometheus telemetry support: [GH-145](https://github.com/hashicorp/vault-k8s/pull/145)

Improvements:
* Injected agents are now configured with `readOnlyRootFilesystem: true`: [GH-142](https://github.com/hashicorp/vault-k8s/pull/142)
* Added additional security contexts for better integration with restrictive PSPs: [GH-153](https://github.com/hashicorp/vault-k8s/pull/153)
* Added unique token volumes for init/sidecar: [GH-170](https://github.com/hashicorp/vault-k8s/pull/170)

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
