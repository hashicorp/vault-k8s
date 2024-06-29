## Unreleased

Changes:
* Dependency updates:
  * Docker image `alpine` 3.19.1 => 3.20.1
  * Docker image `ubi8/ubi-minimal` 8.9-1161 => 8.10-896.1717584414
  * `github.com/go-logr/logr` v1.4.1 => v1.4.2
  * `github.com/hashicorp/vault/sdk` v0.11.1 => v0.13.0
  * `github.com/operator-framework/operator-lib` v0.12.0 => v0.14.0
  * `github.com/prometheus/client_golang` v1.19.0 => v1.19.1
  * `k8s.io/api` v0.29.3 => v0.30.2
  * `k8s.io/apimachinery` v0.29.3 => v0.30.2
  * `k8s.io/client-go` v0.29.3 => v0.30.2
  * `k8s.io/utils` v0.0.0-20230726121419-3b25d923346b => v0.0.0-20240502163921-fe8a2dddb1d0
  * `sigs.k8s.io/controller-runtime` v0.17.2 => v0.18.4

## 1.4.1 (April 8, 2024)

Changes:
* Building with Go 1.22.2
* Default Vault version update to 1.16.1
* Dependency updates:
  * Docker UBI image `ubi8/ubi-minimal` 8.9-1137 => 8.9-1161
  * `github.com/cenkalti/backoff/v4` v4.2.1 => v4.3.0
  * `github.com/go-logr/logr` v1.3.0 => v1.4.1
  * `github.com/hashicorp/go-hclog` v1.6.2 => v1.6.3
  * `github.com/hashicorp/vault/sdk` v0.11.0 => v0.11.1
  * `golang.org/x/crypto` v0.18.0 => v0.22.0
  * `golang.org/x/net` v0.20.0 => v0.24.0
  * `golang.org/x/sys` v0.16.0 => v0.19.0
  * `golang.org/x/term` v0.16.0 => v0.19.0
  * `k8s.io/api` v0.29.2 => v0.29.3
  * `k8s.io/apimachinery` v0.29.2 => v0.29.3
  * `k8s.io/client-go` v0.29.2 => v0.29.3
  * `sigs.k8s.io/controller-runtime` v0.16.3 => v0.17.2

Bugs:
* Enable logging from operator-lib's leader election (used during auto-tls certificate generation) [GH-608](https://github.com/hashicorp/vault-k8s/pull/608)

## 1.4.0 (March 4, 2024)

Features:
* Add support for `max_connections_per_host` within Agent injector [GH-579](https://github.com/hashicorp/vault-k8s/pull/579)
* Add support for `error_on_missing_key` within Agent injector [GH-441](https://github.com/hashicorp/vault-k8s/pull/441)

Changes:
* Default Vault version updated to 1.15.6
* Building with Go 1.21.7
* Testing with K8s versions 1.25-1.29
* Dependency updates:
  * Docker UBI image `ubi8/ubi-minimal` 8.8-1072.1697626218 => 8.9-1137
  * Docker alpine version 3.18.4 => 3.19.1
  * `k8s.io/api` v0.28.3 => v0.29.2
  * `k8s.io/apimachinery` v0.28.3 => v0.29.2
  * `k8s.io/client-go` v0.28.3 => v0.29.2
  * `k8s.io/utils` v0.0.0-20230406110748-d93618cff8a2 => v0.0.0-20230726121419-3b25d923346b`
  * `github.com/hashicorp/go-hclog` v1.5.0 => v1.6.2
  * `github.com/hashicorp/go-secure-stdlib/tlsutil` v0.1.2 => v0.1.3
  * `github.com/hashicorp/vault/sdk` v0.10.2 => v0.11.0
  * `github.com/prometheus/client_golang` v1.17.0 => v1.19.0
  * `github.com/operator-framework/operator-lib` v0.11.0 => v0.12.0
  * `github.com/evanphx/json-patch` v5.7.0 => v5.9.0
  * `github.com/stretchr/testify` v1.8.4 => v1.9.0

## 1.3.1 (October 25, 2023)

Changes:
* Default Vault version updated to 1.15.1
* Building with Go 1.21.3
* Testing with K8s versions 1.24-1.28
* Dependency updates:
  * Docker UBI image `ubi8/ubi-minimal` 8.8-1037 -> 8.8-1072.1697626218
  * Docker alpine version 3.18.3 -> 3.18.4
  * `golang.org/x/crypto` v0.11.0 => v0.14.0
  * `golang.org/x/net` v0.13.0 => v0.17.0
  * `golang.org/x/sys` v0.10.0 => v0.13.0
  * `golang.org/x/term` v0.10.0 => v0.13.0
  * `golang.org/x/text` v0.11.0 => v0.13.0
  * `k8s.io/api` v0.27.4 => v0.28.3
  * `k8s.io/apimachinery` v0.27.4 => v0.28.3
  * `k8s.io/client-go` v0.27.4 => v0.28.3
  * `github.com/hashicorp/vault/sdk` v0.9.2 => v0.10.2
  * `github.com/prometheus/client_golang` v1.16.0 => v1.17.0
  * `github.com/evanphx/json-patch` v5.6.0 => v5.7.0

Improvements:
* Injector can set CA certificate for injected pods via `AGENT_INJECT_VAULT_CACERT_BYTES` env var or `-vault-cacert-bytes` flag [GH-507](https://github.com/hashicorp/vault-k8s/pull/507)
* Remove refs to deprecated io/ioutil [GH-516](https://github.com/hashicorp/vault-k8s/pull/516)

## 1.3.0 (August 16, 2023)

Improvements:
* Add `NAMESPACE`, `HOST_IP`, and `POD_IP` environment variables to Agent container using downward API [GH-486](https://github.com/hashicorp/vault-k8s/pull/486)

Changes:
* Templated secrets no longer require the -secret annotation [GH-505](https://github.com/hashicorp/vault-k8s/pull/505)
* Only inject Pods that are Pending [GH-501](https://github.com/hashicorp/vault-k8s/pull/501)
* Default to Vault 1.14.1
* Building with Go 1.20.7
* Testing with K8s versions 1.23-1.27
* Dependency updates:
  * `github.com/cenkalti/backoff/v4` v4.2.0 -> v4.2.1
  * `github.com/hashicorp/vault/sdk` v0.8.1 -> v0.9.2
  * `github.com/stretchr/testify` v1.8.2 -> v1.8.4
  * `github.com/prometheus/client_golang` v1.14.0 -> v1.16.0
  * `k8s.io/apimachinery` v0.26.3 -> v0.27.4
  * `k8s.io/api` v0.26.3 -> v0.27.4
  * `k8s.io/client-go` v0.26.3 -> v0.27.4
  * `golang.org/x/net` v0.7.0 -> v0.13.0
  * `golang.org/x/sys` v0.5.0 -> v0.10.0
  * `golang.org/x/term` v0.5.0 -> v0.10.0
  * `golang.org/x/text` v0.7.0 -> v0.11.0
  * Docker alpine version 3.17.3 -> 3.18.3
  * Docker UBI image `ubi8/ubi-minimal` 8.7-1107 -> 8.8-1037

Bugs:
* Prevent `auth-config-token-path` from being overridden when another serviceaccount volume is present [GH-457](https://github.com/hashicorp/vault-k8s/pull/457)

## 1.2.1 (April 6, 2023)

Changes:
* Default to Vault 1.13.1
* Building with Go 1.20.3
* Dependency updates:
  * `github.com/cenkalti/backoff/v4` v4.1.3 -> v4.2.0
  * `github.com/hashicorp/go-hclog` v1.3.1 -> v1.5.0
  * `github.com/hashicorp/vault/sdk` v0.6.1 -> v0.8.1
  * `golang.org/x/net` v0.4.0 -> v0.7.0
  * `golang.org/x/sys` v0.3.0 -> v0.5.0
  * `golang.org/x/term` v0.3.0 -> v0.5.0
  * `golang.org/x/text` v0.5.0 -> v0.7.0
  * `k8s.io/api` v0.25.4 -> v0.26.3
  * `k8s.io/apimachinery` v0.25.4 -> v0.26.3
  * `k8s.io/client-go` v0.25.4 -> v0.26.3
  * `k8s.io/utils` v0.0.0-20220728103510-ee6ede2d64ed -> v0.0.0-20230406110748-d93618cff8a2
  * Docker UBI image `ubi8/ubi-minimal` 8.7 -> 8.7-1107
  * Used fixed Docker alpine version: 3.17.3

Bugs:
* Don't override `shareProcessNamespace` if an annotation is not present [GH-445](https://github.com/hashicorp/vault-k8s/pull/445)

## 1.2.0 (February 6, 2023)

Changes:
* Building with Go 1.19.5
* Update golang.org/x/net to v0.4.0 [GH-409](https://github.com/hashicorp/vault-k8s/pull/409)
* Default to Vault v1.12.3

Features:
* Add support for enabling `sharedProcessNamespace` on the Pod `spec` [GH-408](https://github.com/hashicorp/vault-k8s/pull/408)
* Add `agent-telemetry` annotation [GH-413](https://github.com/hashicorp/vault-k8s/pull/413)

Improvements:
* Set Kubernetes user-agent to include vault-k8s version [GH-411](https://github.com/hashicorp/vault-k8s/pull/411)

Bugs:
* Preserve metadata when updating the cert secret [GH-401](https://github.com/hashicorp/vault-k8s/pull/401)

## 1.1.0 (November 17, 2022)

Changes:
* Building with go 1.19.3
* Default to Vault v1.12.1

Features:
* Allow modifying agent and agent-init containers with json-patch [GH-399](https://github.com/hashicorp/vault-k8s/pull/399)
* Support for setting [`exit_on_err`](https://github.com/hashicorp/vault/pull/17091) in the agent auto-auth method config [GH-400](https://github.com/hashicorp/vault-k8s/pull/400).

Improvements:
* Dependency updates:
  * github.com/cenkalti/backoff/v4 v4.1.1 => v4.1.3
  * github.com/hashicorp/go-hclog v1.0.0 => v1.3.1
  * github.com/hashicorp/go-secure-stdlib/tlsutil v0.1.1 => v0.1.2
  * github.com/hashicorp/vault/sdk v0.2.1 => v0.6.1
  * github.com/mitchellh/cli v1.1.4 => v1.1.5
  * github.com/operator-framework/operator-lib v0.8.0 => v0.11.0
  * github.com/prometheus/client_golang v1.11.1 => v1.12.1
  * github.com/stretchr/testify v1.8.0 => v1.8.1
  * k8s.io/api v0.22.2 => v0.25.4
  * k8s.io/apimachinery v0.22.2 => v0.25.4
  * k8s.io/client-go v0.22.2 => v0.25.4

## 1.0.1 (October 24, 2022)

Changes:
* Default to Vault v1.12.0

Bugs:
* Default ephemeral storage resources to unset for injected containers [GH-386](https://github.com/hashicorp/vault-k8s/pull/386)

Improvements:
* Upgrade dependency `golang.org/x/net` from `v0.0.0-20220708220712-1185a9018129` to `v0.0.0-20221004154528-8021a29435af`
* Upgrade dependency `golang.org/x/sys` from `v0.0.0-20220520151302-bc2c85ada10a` to `v0.0.0-20220728004956-3c1f35247d10`
* Upgrade dependency `golang.org/x/text` from v0.3.7 to v0.3.8

## 1.0.0 (September 6, 2022)

Changes:
* Upgrade Docker base image to alpine:3.16.2 [GH-382](https://github.com/hashicorp/vault-k8s/pull/382)
* Default to Vault v1.11.3

Features:
* Support for setting [`disable_keep_alives`](https://github.com/hashicorp/vault/pull/16479) in the agent config [GH-376](https://github.com/hashicorp/vault-k8s/pull/376)
* Added flags, envs and annotations to control ephemeral storage resources for injected containers [GH-360](https://github.com/hashicorp/vault-k8s/pull/360)

## 0.17.0 (July 28, 2022)

Features:
* Support for setting [`disable_idle_connections`](https://github.com/hashicorp/vault/pull/15986) in the agent config [GH-366](https://github.com/hashicorp/vault-k8s/pull/366)

Improvements:
* Added support to configure default vault namespace on the agent config [GH-345](https://github.com/hashicorp/vault-k8s/pull/345)

Bugs:
* Properly return admission errors [GH-363](https://github.com/hashicorp/vault-k8s/pull/363)

## 0.16.1 (May 25, 2022)

Improvements:
* ConfigMap with missing vault section should default to env vars [GH-353](https://github.com/hashicorp/vault-k8s/pull/353)
* Wait for certificate before starting HTTP listener [GH-354](https://github.com/hashicorp/vault-k8s/pull/354)
* Update example injector mutating webhook config to exclude agent pod [GH-351](https://github.com/hashicorp/vault-k8s/pull/351)

Bugs:
* Certificate watcher timer deadlock fix [GH-350](https://github.com/hashicorp/vault-k8s/pull/350)

## 0.16.0 (May 11, 2022)

Features:
* Add agent-enable-quit annotation [GH-330](https://github.com/hashicorp/vault-k8s/pull/330)
* Add go-max-procs annotation [GH-333](https://github.com/hashicorp/vault-k8s/pull/333)
* Add min and max auth backoff annotations and environment variables [GH-341](https://github.com/hashicorp/vault-k8s/pull/341)

Improvements:
* Add a name to the service port [GH-262](https://github.com/hashicorp/vault-k8s/pull/262)

Changes:
* Only update webhook CA bundles when needed [GH-336](https://github.com/hashicorp/vault-k8s/pull/336)

## 0.15.0 (March 21, 2022)

Features:
* Add agent-inject-containers annotation [GH-313](https://github.com/hashicorp/vault-k8s/pull/313)

Changes:
* Build with go 1.17.8
* Default to Vault v1.9.4

## 0.14.2 (January 19, 2022)

Changes:
* Build with go 1.17.6
* Default to Vault v1.9.2

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
* Fix agent-inject-token when caching enabled: [GH-250](https://github.com/hashicorp/vault-k8s/pull/250)
* Remove new line from injected token: [GH-250](https://github.com/hashicorp/vault-k8s/pull/250)

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
